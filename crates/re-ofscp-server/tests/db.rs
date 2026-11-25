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
            .persist(&nonce(&format!("n{i}"), h, 4_000_000_000), 0)
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
    ledger.persist(&n, 0).await.unwrap();
    assert_eq!(ledger.persist(&n, 0).await, Err(LedgerError::Duplicate));
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
            .persist(&nonce(&format!("live{i}"), "a@b.example", now + 1 + i), 0)
            .await
            .unwrap();
    }
    for i in 0..4 {
        ledger
            .persist(&nonce(&format!("dead{i}"), "a@b.example", now - i), 0)
            .await
            .unwrap();
    }
    let mut live: Vec<String> = ledger
        .load(now)
        .await
        .unwrap()
        .nonces
        .into_iter()
        .map(|n| n.nonce)
        .collect();
    live.sort();
    assert_eq!(live, (0..7).map(|i| format!("live{i}")).collect::<Vec<_>>());
    let loaded = ledger.load(now).await.unwrap();
    assert!(loaded.nonces.iter().all(|n| n.signed_at == n.expires - 301));
    assert_eq!(loaded.clock, None);

    ledger.purge(now).await.unwrap();
    // The clock was persisted before anything was deleted...
    let after = ledger.load(0).await.unwrap();
    assert_eq!(after.clock, Some(now));
    // ...so `load(0)` uses it as the cutoff: still exactly the 7 live rows.
    assert_eq!(after.nonces.len(), 7);
    // And the purged rows are really gone, not merely filtered out.
    #[derive(Deserialize)]
    struct Nonce {
        #[allow(dead_code)]
        nonce: String,
    }
    let db = db(&server);
    let rows = db.fetch::<Nonce>(&Ql::new("ReplayNonce")).await.unwrap();
    assert_eq!(rows.len(), 7);
    // The clock never moves backwards.
    ledger.purge(now - 1000).await.unwrap();
    assert_eq!(ledger.load(0).await.unwrap().clock, Some(now));
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
        .build()
        .unwrap();
    clock.set(SIGNED_AT);
    let app = router(before);
    assert_eq!(send(&app, Req::health().build()).await.0, StatusCode::OK);

    // "Restart": a new process state over the same database, started now.
    let after = AppState::builder(config(&server))
        .keys(Arc::new(alice_keys()))
        .clock(clock.clone())
        .build()
        .unwrap();
    assert!(after.verifier.replay_store().warming_up());
    assert_eq!(after.restore_replay().await.unwrap(), 1);
    assert!(!after.verifier.replay_store().warming_up());
    // The restored nonce is in memory (the 401 below must not rely only on
    // the ledger's unique key).
    assert_eq!(
        after
            .verifier
            .replay_store()
            .len(SIGNED_AT.unix_timestamp()),
        1
    );
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
        .build()
        .unwrap();
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

/// A query future dropped mid-flight (a timeout, a disconnected client)
/// must not poison its connection for the next write.
#[tokio::test]
async fn a_cancelled_query_does_not_poison_the_next_write() {
    use std::future::Future;
    use std::task::{Context, Waker};
    let server = RhypeServer::start();
    let mut cfg = DbConfig::new(server.tcp_addr());
    cfg.pool_size = 1;
    let db = Db::new(cfg);
    db.execute(&Ql::new("ReplayNonce")).await.unwrap();
    {
        let q = Ql::new("ReplayNonce");
        let mut fut = Box::pin(db.execute(&q));
        let mut cx = Context::from_waker(Waker::noop());
        // Start it, then abandon it.
        for _ in 0..3 {
            if fut.as_mut().poll(&mut cx).is_ready() {
                break;
            }
        }
    }
    let q = Ql::new("ReplayClock.create({ name: \"x\", high_water: 0 })");
    db.execute(&q).await.unwrap();
}

/// Clock steps forward, the purge deletes a nonce it believes expired, the
/// clock is corrected, the process restarts. The persisted replay clock
/// keeps the purged nonce expired, so the replay is still refused.
#[tokio::test]
async fn forward_clock_step_purge_then_restart_still_refuses_the_replay() {
    let server = RhypeServer::start();
    let clock = SettableClock::at(SIGNED_AT - time::Duration::seconds(400));
    let first = AppState::builder(config(&server))
        .keys(Arc::new(alice_keys()))
        .clock(clock.clone())
        .build()
        .unwrap();
    first.restore_replay().await.unwrap();
    clock.set(SIGNED_AT);
    let app = router(first.clone());
    assert_eq!(send(&app, Req::health().build()).await.0, StatusCode::OK);

    // NTP steps the clock 600 s forward; the purge runs by the store clock.
    clock.set(SIGNED_AT + time::Duration::seconds(600));
    let store_clock = first.verifier.replay_store().clock(first.verifier.now());
    first.verifier.ledger().purge(store_clock).await.unwrap();

    // Corrected, then restarted, 30 s after signing.
    clock.set(SIGNED_AT + time::Duration::seconds(30));
    let second = AppState::builder(config(&server))
        .keys(Arc::new(alice_keys()))
        .clock(clock.clone())
        .build()
        .unwrap();
    assert_eq!(second.restore_replay().await.unwrap(), 0);
    let app = router(second);
    let (status, json, _, _) = send(&app, Req::health().build()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{json}");
}

/// A nonce reused after its window (allowed by §4.5) replaces the stale,
/// not-yet-purged row; a live row is still a duplicate.
#[tokio::test]
async fn an_expired_unpurged_row_is_replaced_not_a_replay() {
    let server = RhypeServer::start();
    let ledger = RhypeLedger::new(db(&server));
    let old = nonce("reuse", "a@b.example", 1_000);
    ledger.persist(&old, 500).await.unwrap();
    let again = nonce("reuse", "a@b.example", 2_000);
    // Still live at 900: a replay.
    assert_eq!(
        ledger.persist(&again, 900).await,
        Err(LedgerError::Duplicate)
    );
    #[derive(Deserialize)]
    struct Any {}
    let db = db(&server);
    let before = db.fetch::<Any>(&Ql::new("ReplayNonce")).await.unwrap();
    // Expired at 1_500: replaced.
    ledger.persist(&again, 1_500).await.unwrap();
    let live = ledger.load(1_500).await.unwrap().nonces;
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].expires, 2_000);
    // In place: the same object, so no moment existed without a covering row.
    let after = db.fetch::<Any>(&Ql::new("ReplayNonce")).await.unwrap();
    assert_eq!(before.len(), 1);
    assert_eq!(after.len(), 1);
    assert_eq!(before[0].id, after[0].id);
}

/// A purge racing re-persists of the same (expired) nonces must not delete
/// a row a re-persist just made live. The reviewer's reproduction lost 5 of
/// 900 before the purge gate.
#[tokio::test]
async fn purge_never_deletes_a_row_just_made_live() {
    let server = RhypeServer::start();
    let ledger = Arc::new(RhypeLedger::new(db(&server)));
    let count = 600;
    for i in 0..count {
        ledger
            .persist(&nonce(&format!("r{i}"), "a@b.example", 1_000), 0)
            .await
            .unwrap();
    }
    let purge = {
        let ledger = ledger.clone();
        tokio::spawn(async move { ledger.purge(1_500).await })
    };
    let mut tasks = Vec::new();
    for t in 0..8 {
        let ledger = ledger.clone();
        tasks.push(tokio::spawn(async move {
            let mut ok = Vec::new();
            for i in (t..count).step_by(8) {
                let n = nonce(&format!("r{i}"), "a@b.example", 2_000);
                if ledger.persist(&n, 1_500).await.is_ok() {
                    ok.push(format!("r{i}"));
                }
            }
            ok
        }));
    }
    let mut accepted = Vec::new();
    for t in tasks {
        accepted.extend(t.await.unwrap());
    }
    purge.await.unwrap().unwrap();
    let live: std::collections::HashSet<String> = ledger
        .load(1_500)
        .await
        .unwrap()
        .nonces
        .into_iter()
        .map(|n| n.nonce)
        .collect();
    let lost: Vec<_> = accepted.iter().filter(|n| !live.contains(*n)).collect();
    assert!(lost.is_empty(), "accepted but lost: {lost:?}");
}
