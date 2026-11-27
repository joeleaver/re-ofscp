//! Startup of the replay store (spec §4.5 "Restarts", decision 0001).
//!
//! On jkbase the managed rhypedb starts beside the app and listens about a
//! second after it, so the first attempt to reload the nonce ledger is
//! refused. A single attempt left the warm-up (`503` on every signed
//! request) in force for the whole skew window after each restart. The
//! restore must retry until the ledger loads, and end the warm-up then;
//! a provider without a persistent ledger must still warm up.

mod common;

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use common::harness::*;
use common::rhypedb::RhypeServer;
use re_ofscp_server::replay::{LedgerError, NoLedger};
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

    // The database comes up; the restore finishes within its retry cap.
    server.restart();
    let restored = tokio::time::timeout(Duration::from_secs(10), restore)
        .await
        .expect("the restore finishes once the database listens")
        .unwrap();
    assert_eq!(restored, Ok(1));
    assert!(!after.verifier.replay_store().warming_up());

    // The same clock second: a fresh signed request is served...
    let mut again = Req::health();
    again.nonce = "fresh-nonce-again-456789ab".into();
    assert_eq!(send(&app, again.build()).await.0, StatusCode::OK);
    // ...and the previous process's nonce is still refused.
    let (status, json, _, _) = send(&app, Req::health().build()).await;
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
