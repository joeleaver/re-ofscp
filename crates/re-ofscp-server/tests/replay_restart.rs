//! Startup of the replay store (spec §4.5 "Restarts", decision 0001).
//!
//! On jkbase the managed rhypedb starts beside the app and listens about a
//! second after it, so the first attempt to reload the nonce ledger is
//! refused. A single attempt left the warm-up (`503` on every signed
//! request) in force for the whole skew window after each restart. The
//! restore must retry until the ledger loads, and end the warm-up then;
//! a provider without a persistent ledger must still warm up.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::StatusCode;
use common::harness::*;
use common::rhypedb::RhypeServer;
use re_ofscp_server::replay::ledger::{LedgerFuture, Restored};
use re_ofscp_server::replay::{LedgerError, NoLedger, NonceLedger, StoredNonce};
use re_ofscp_server::{AppState, Config, router};

fn config(rhypedb_addr: String) -> Config {
    Config::from_lookup(move |k| match k {
        "DOMAIN" => Some("providera.com".into()),
        "PROVIDER_SIGNING_KEY" => Some(common::PROVIDER_SIGNING_KEY.into()),
        "RHYPEDB_ADDR" => Some(rhypedb_addr.clone()),
        _ => None,
    })
    .unwrap()
}

/// The production restart: the database is not listening when the provider
/// starts. The restore keeps trying, and once the database is up the
/// previous process's nonces are back and signed requests are served at
/// once, long before the skew window would have passed.
#[tokio::test]
async fn a_restart_before_the_database_listens_restores_once_it_does() {
    let mut server = RhypeServer::start();
    let clock = SettableClock::at(SIGNED_AT - time::Duration::seconds(400));

    // The previous process accepts one signed request (its nonce is now in
    // the ledger).
    let before = AppState::builder(config(server.tcp_addr()))
        .keys(Arc::new(alice_keys()))
        .clock(clock.clone())
        .build()
        .unwrap();
    before.restore_replay().await.unwrap();
    clock.set(SIGNED_AT);
    assert_eq!(
        send(&router(before), Req::health().build()).await.0,
        StatusCode::OK
    );

    // Restart: the new process starts while the database is down.
    server.stop();
    let after = AppState::builder(config(server.tcp_addr()))
        .keys(Arc::new(alice_keys()))
        .clock(clock.clone())
        .build()
        .unwrap();
    let restore = tokio::spawn(after.clone().restore_replay_until_loaded());
    let app = router(after.clone());
    let mut fresh = Req::health();
    fresh.nonce = "fresh-nonce-0123456789ab".into();

    // Several attempts fail meanwhile; the warm-up holds, and says how long
    // it could last (T0 + skew + 1 - now).
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!restore.is_finished(), "the restore must keep retrying");
    assert!(after.verifier.replay_store().warming_up());
    let (status, json, _, retry) = send(&app, fresh.build()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{json}");
    assert_eq!(retry.as_deref(), Some("301"));

    // A client whose clock runs ahead signs after T0 + skew, so the warm-up
    // lets it through to the store. The ledger is down, so it fails closed,
    // but its nonce stays burned in memory.
    clock.set(SIGNED_AT + time::Duration::seconds(5));
    let mut ahead = Req::health();
    ahead.nonce = "ahead-nonce-0123456789ab".into();
    ahead.timestamp = "2026-01-01T12:05:02Z".into(); // SIGNED_AT + 302
    let (status, json, _, retry) = send(&app, ahead.build()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{json}");
    assert_eq!(retry.as_deref(), Some("2"), "the ledger write failed");

    // The database comes up; the restore finishes within its retry cap.
    server.restart();
    let restored = tokio::time::timeout(Duration::from_secs(10), restore)
        .await
        .expect("the restore finishes once the database listens")
        .unwrap();
    assert_eq!(restored, Ok(1));
    assert!(!after.verifier.replay_store().warming_up());

    // Well inside the skew window: a fresh signed request is served...
    let mut again = Req::health();
    again.nonce = "fresh-nonce-again-456789ab".into();
    assert_eq!(send(&app, again.build()).await.0, StatusCode::OK);
    // ...the previous process's nonce is still refused...
    let (status, json, _, _) = send(&app, Req::health().build()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{json}");
    assert_eq!(json["detail"], "nonce already used for this key");
    // ...and so is the one burned during the warm-up, which never reached
    // the ledger: the restore kept the in-memory entry.
    let (status, json, _, _) = send(&app, ahead.build()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{json}");
    assert_eq!(json["detail"], "nonce already used for this key");
}

/// With the database up at startup the restore succeeds on its first
/// attempt, and signed requests are served at once.
#[tokio::test]
async fn a_restart_with_the_database_up_serves_at_once() {
    let server = RhypeServer::start();
    let clock = SettableClock::at(SIGNED_AT);
    let state = AppState::builder(config(server.tcp_addr()))
        .keys(Arc::new(alice_keys()))
        .clock(clock)
        .build()
        .unwrap();
    assert!(state.verifier.replay_store().warming_up());
    let restored = tokio::time::timeout(
        Duration::from_secs(5),
        state.clone().restore_replay_until_loaded(),
    )
    .await
    .expect("one attempt suffices");
    assert_eq!(restored, Ok(0));
    assert_eq!(
        send(&router(state), Req::health().build()).await.0,
        StatusCode::OK
    );
}

/// A provider whose store does not persist stops trying at once and keeps
/// the warm-up (§4.5): signed requests get `503` until T0 + skew.
#[tokio::test]
async fn a_restart_without_a_ledger_still_warms_up() {
    let clock = SettableClock::at(SIGNED_AT);
    let state = AppState::builder(config("127.0.0.1:9".into()))
        .keys(Arc::new(alice_keys()))
        .ledger(Arc::new(NoLedger))
        .clock(clock)
        .build()
        .unwrap();
    let restored = tokio::time::timeout(
        Duration::from_secs(5),
        state.clone().restore_replay_until_loaded(),
    )
    .await
    .expect("a ledger that persists nothing is not retried");
    assert_eq!(restored, Err(LedgerError::NotPersistent));
    assert!(state.verifier.replay_store().warming_up());
    let (status, json, _, retry) = send(&router(state), Req::health().build()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{json}");
    assert_eq!(json["errorCode"], "service_unavailable");
    assert_eq!(retry.as_deref(), Some("301"));
}

/// A ledger that is unavailable for its first `failures` loads, recording
/// the order of loads and purges.
struct FlakyLedger {
    failures: Mutex<usize>,
    events: Arc<Mutex<Vec<&'static str>>>,
}

impl NonceLedger for FlakyLedger {
    fn persist<'a>(&'a self, _n: &'a StoredNonce, _now: i64) -> LedgerFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
    fn load(&self, _now: i64) -> LedgerFuture<'_, Restored> {
        Box::pin(async {
            let mut failures = self.failures.lock().unwrap();
            if *failures > 0 {
                *failures -= 1;
                self.events.lock().unwrap().push("load failed");
                return Err(LedgerError::Unavailable("connection refused".into()));
            }
            self.events.lock().unwrap().push("loaded");
            Ok(Restored::default())
        })
    }
    fn purge(&self, _clock: i64) -> LedgerFuture<'_, ()> {
        Box::pin(async {
            self.events.lock().unwrap().push("purge");
            Ok(())
        })
    }
}

/// The ledger is read in pages by offset, so nothing may delete rows while
/// it loads: the purge starts only once the restore has succeeded, and the
/// outcome reaches startup before it.
#[tokio::test]
async fn the_purge_waits_for_the_restore() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let state = AppState::builder(config("127.0.0.1:9".into()))
        .keys(Arc::new(alice_keys()))
        .ledger(Arc::new(FlakyLedger {
            failures: Mutex::new(3),
            events: events.clone(),
        }))
        .clock(SettableClock::at(SIGNED_AT))
        .build()
        .unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(state.clone().maintain_replay(tx));
    let restored = tokio::time::timeout(Duration::from_secs(5), rx)
        .await
        .expect("the restore succeeds on the fourth attempt")
        .unwrap();
    assert_eq!(restored, Ok(0));
    assert!(!state.verifier.replay_store().warming_up());
    // The purge's first tick is immediate once it starts.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !events.lock().unwrap().contains(&"purge") {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the purge never ran"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    task.abort();
    let events = events.lock().unwrap();
    assert_eq!(
        events[..5],
        [
            "load failed",
            "load failed",
            "load failed",
            "loaded",
            "purge"
        ]
    );
}
