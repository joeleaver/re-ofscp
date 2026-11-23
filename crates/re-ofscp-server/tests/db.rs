//! The data layer against a real rhypedb-server.

mod common;

use std::sync::Arc;

use axum::http::StatusCode;
use common::harness::*;
use common::rhypedb::RhypeServer;
use re_ofscp_server::db::{Db, DbConfig, DbError, Ql};
use re_ofscp_server::replay::ledger::RhypeLedger;
use re_ofscp_server::replay::{LedgerError, NonceLedger, SignerKind, StoredNonce};
use re_ofscp_server::{AppState, Config, router};
use serde::Deserialize;

fn db(server: &RhypeServer) -> Arc<Db> {
    Arc::new(Db::new(DbConfig::new(server.tcp_addr())))
}

fn nonce(nonce: &str, signer: &str, expires: i64) -> StoredNonce {
    StoredNonce {
        kind: SignerKind::Actor,
        signer: signer.into(),
        domain: "b.example".into(),
        key_id: "dk_1".into(),
        nonce: nonce.into(),
        signed_at: expires - 301,
        expires,
    }
}

#[derive(Deserialize, Debug)]
struct SignerOnly {
    signer: String,
}

/// Values containing query syntax, quotes, backslashes, newlines and
/// non-ASCII come back byte-for-byte, and match exactly in a filter.
#[tokio::test]
async fn hostile_strings_round_trip_and_never_become_syntax() {
    let server = RhypeServer::start();
    let db = db(&server);
    let ledger = RhypeLedger::new(db.clone());
    let hostile = [
        r#"a" }) ReplayNonce.delete() //"#,
        r#"\"#,
        r#"\\\""#,
        "line\nbreak\ttab\r",
        "\\n is not a newline",
        "ünïcødé 🦀 ''",
        "",
    ];
    for (i, h) in hostile.iter().enumerate() {
        ledger
            .persist(&nonce(&format!("n{i}"), h, 4_000_000_000))
            .await
            .unwrap();
    }
    for h in hostile {
        let q = Ql::new("ReplayNonce.filter(.signer == ").str(h).raw(")");
        let rows = db.fetch::<SignerOnly>(&q).await.unwrap();
        assert_eq!(rows.len(), 1, "{h:?}");
        assert_eq!(rows[0].data.signer, h);
    }
    // Nothing was deleted by the "injection".
    let all = db
        .fetch::<SignerOnly>(&Ql::new("ReplayNonce"))
        .await
        .unwrap();
    assert_eq!(all.len(), hostile.len());
}

#[tokio::test]
async fn unique_violation_is_a_conflict_and_a_ledger_duplicate() {
    let server = RhypeServer::start();
    let db = db(&server);
    let ledger = RhypeLedger::new(db.clone());
    let n = nonce("dup", "a@b.example", 4_000_000_000);
    ledger.persist(&n).await.unwrap();
    assert_eq!(ledger.persist(&n).await, Err(LedgerError::Duplicate));
    // The raw error is classified as a conflict.
    let q = Ql::new("ReplayNonce.create({ key: ")
        .str(&n.ledger_key())
        .raw(", kind: \"actor\", signer: \"x\", domain: \"x\", key_id: \"x\", nonce: \"x\", signed_at: 0, expires_at: 0 })");
    assert!(matches!(db.execute(&q).await, Err(DbError::Conflict(_))));
    // A syntax error is a query error, not a conflict.
    assert!(matches!(
        db.execute(&Ql::new("ReplayNonce.nope(")).await,
        Err(DbError::Query(_))
    ));
}

#[tokio::test]
async fn ledger_loads_live_nonces_in_pages_and_purges_expired_ones() {
    let server = RhypeServer::start();
    let ledger = RhypeLedger::with_page_size(db(&server), 3);
    let now = 2_000_000_000;
    for i in 0..7 {
        ledger
            .persist(&nonce(&format!("live{i}"), "a@b.example", now + 1 + i))
            .await
            .unwrap();
    }
    for i in 0..4 {
        ledger
            .persist(&nonce(&format!("dead{i}"), "a@b.example", now - i))
            .await
            .unwrap();
    }
    let mut live: Vec<String> = ledger
        .load(now)
        .await
        .unwrap()
        .into_iter()
        .map(|n| n.nonce)
        .collect();
    live.sort();
    assert_eq!(live, (0..7).map(|i| format!("live{i}")).collect::<Vec<_>>());
    let loaded = ledger.load(now).await.unwrap();
    assert!(loaded.iter().all(|n| n.signed_at == n.expires - 301));

    ledger.purge(now).await.unwrap();
    // Purged rows are gone (not merely filtered out by `load`).
    let everything = ledger.load(0).await.unwrap();
    assert_eq!(everything.len(), 7);
}

/// With idle connections pinged before reuse, a database restart costs no
/// query at all once the database is back.
#[tokio::test]
async fn pool_reconnects_after_the_server_restarts() {
    let mut server = RhypeServer::start();
    let mut cfg = DbConfig::new(server.tcp_addr());
    cfg.liveness_after = std::time::Duration::ZERO;
    let db = Db::new(cfg);
    // Warm every slot.
    for _ in 0..8 {
        db.execute(&Ql::new("ReplayNonce")).await.unwrap();
    }
    server.stop();
    assert!(!db.ping().await);
    assert!(matches!(
        db.execute(&Ql::new("ReplayNonce")).await,
        Err(DbError::Unavailable(_))
    ));
    server.restart();
    for i in 0..8 {
        if let Err(e) = db.execute(&Ql::new("ReplayNonce")).await {
            panic!("write {i} after restart: {e}\n{}", server.log());
        }
        assert!(db.ping().await, "ping {i}");
    }
}

/// Without the liveness ping (a connection used moments before the
/// restart), the stale connection costs at most one write; it then clears
/// the whole pool, and reads are retried, so they never fail.
#[tokio::test]
async fn a_restart_costs_at_most_one_unretried_write() {
    let mut server = RhypeServer::start();
    let mut cfg = DbConfig::new(server.tcp_addr());
    cfg.liveness_after = std::time::Duration::from_secs(3600);
    let db = Db::new(cfg);
    for _ in 0..8 {
        db.execute(&Ql::new("ReplayNonce")).await.unwrap();
    }
    server.restart();
    // A read on a stale connection is retried on a fresh one.
    assert!(
        db.fetch::<SignerOnly>(&Ql::new("ReplayNonce"))
            .await
            .is_ok()
    );
    // Every slot was cleared by that failure, so writes now succeed.
    for i in 0..8 {
        if let Err(e) = db.execute(&Ql::new("ReplayNonce")).await {
            panic!("write {i}: {e}");
        }
    }
}

fn config(server: &RhypeServer) -> Config {
    let addr = server.tcp_addr();
    Config::from_lookup(move |k| match k {
        "DOMAIN" => Some("providera.com".into()),
        "RHYPEDB_ADDR" => Some(addr.clone()),
        _ => None,
    })
    .unwrap()
}

/// The point of the ledger: a nonce accepted before a restart is still
/// refused after it, and the restarted provider serves at once, with no
/// warm-up.
#[tokio::test]
async fn nonces_survive_a_restart_and_the_warm_up_is_skipped() {
    let server = RhypeServer::start();
    let clock = SettableClock::at(SIGNED_AT - time::Duration::seconds(400));

    let before = AppState::builder(config(&server))
        .keys(Arc::new(alice_keys()))
        .clock(clock.clone())
        .build();
    clock.set(SIGNED_AT);
    let app = router(before);
    assert_eq!(send(&app, Req::health().build()).await.0, StatusCode::OK);

    // "Restart": a new process state over the same database, started now.
    let after = AppState::builder(config(&server))
        .keys(Arc::new(alice_keys()))
        .clock(clock.clone())
        .build();
    assert!(after.verifier.replay_store().warming_up());
    assert_eq!(after.restore_replay().await.unwrap(), 1);
    assert!(!after.verifier.replay_store().warming_up());
    let app = router(after);

    // The same request is a replay...
    let (status, json, _, _) = send(&app, Req::health().build()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{json}");
    assert_eq!(json["detail"], "nonce already used for this key");

    // ...and a fresh one is served immediately, not 503.
    let mut fresh = Req::health();
    fresh.nonce = "fresh-nonce-0123456789ab".into();
    assert_eq!(send(&app, fresh.build()).await.0, StatusCode::OK);
}

/// If the ledger cannot be written, the request fails closed with 503, and
/// its nonce stays burned in memory.
#[tokio::test]
async fn an_unwritable_ledger_fails_closed() {
    let mut server = RhypeServer::start();
    let clock = SettableClock::at(SIGNED_AT - time::Duration::seconds(400));
    let state = AppState::builder(config(&server))
        .keys(Arc::new(alice_keys()))
        .clock(clock.clone())
        .build();
    state.restore_replay().await.unwrap();
    clock.set(SIGNED_AT);
    server.stop();
    let app = router(state);
    let req = || Req::health().build();
    let (status, json, _, retry) = send(&app, req()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{json}");
    assert_eq!(retry.as_deref(), Some("2"));
    server.restart();
    // Re-sending the same signed request is still a replay.
    assert_eq!(send(&app, req()).await.0, StatusCode::UNAUTHORIZED);
}
