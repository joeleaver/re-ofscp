//! Replay protection over HTTP (§4.5): nonce reuse, expiry boundaries,
//! restart warm-up, pools and quotas, and the stale-clock race.

mod common;

use std::sync::Arc;

use axum::http::StatusCode;
use axum::routing::post;
use axum::{Router, middleware};
use common::harness::*;
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt;
use re_ofscp_server::replay::{NoLedger, ReplayLimits, ReplayStore};
use re_ofscp_server::signing::canonical::sign;
use re_ofscp_server::signing::{Authenticated, Clock, Verifier, authenticate};

#[tokio::test]
async fn replay_is_refused() {
    let h = harness();
    assert_eq!(send(&h.app, Req::vector().build()).await.0, StatusCode::OK);
    let (status, json, _, _) = send(&h.app, Req::vector().build()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["detail"], "nonce already used for this key");
    assert_eq!(json["errorCode"], "unauthorized");
}

#[tokio::test]
async fn forged_request_does_not_burn_the_nonce() {
    let h = harness();
    let mut forged = Req::vector();
    forged.signature = Some(sign(&SigningKey::from_bytes(&[7; 32]), "anything"));
    assert_eq!(
        send(&h.app, forged.build()).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert!(h.replay.is_empty(SIGNED_AT.unix_timestamp()));
    // The genuine request with the same nonce still goes through.
    assert_eq!(send(&h.app, Req::vector().build()).await.0, StatusCode::OK);
}

#[tokio::test]
async fn requests_during_restart_warm_up_get_503_with_retry_after() {
    // The store's warm-up covers timestamps up to SIGNED_AT - 1; such a
    // request may have been recorded by a previous process.
    let h = harness();
    let mut r = Req::vector();
    r.timestamp = "2026-01-01T11:59:59Z".into();
    let (status, json, _, retry) = send(&h.app, r.build()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json["errorCode"], "service_unavailable");
    assert_eq!(retry.as_deref(), Some("1"));
}

#[tokio::test]
async fn production_state_warms_up_for_one_skew_window() {
    let config = re_ofscp_server::Config::from_lookup(|k| match k {
        "DOMAIN" => Some("providera.com".into()),
        "RHYPEDB_ADDR" => Some("127.0.0.1:9".into()),
        _ => None,
    })
    .unwrap();
    // Started exactly when the vector was signed: inside the warm-up, which
    // covers timestamps up to start + 300 inclusive.
    let state = re_ofscp_server::AppState::builder(config)
        .keys(Arc::new(alice_keys()))
        .ledger(Arc::new(re_ofscp_server::replay::NoLedger))
        .clock(Arc::new(FixedClock(SIGNED_AT)))
        .build();
    let app = re_ofscp_server::router(state);
    let req = Req::health().build();
    let (status, json, _, retry) = send(&app, req).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(retry.as_deref(), Some("301"));
    assert_eq!(
        json["type"],
        "https://providera.com/problems/service_unavailable"
    );
}

#[tokio::test]
async fn full_replay_store_fails_closed_with_503() {
    let h = harness_with(Arc::new(alice_keys()), SIGNED_AT, limits(1));
    assert_eq!(send(&h.app, Req::vector().build()).await.0, StatusCode::OK);
    let mut r = Req::vector();
    r.nonce = "another-nonce-0123456789".into();
    let (status, json, _, retry) = send(&h.app, r.build()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json["errorCode"], "service_unavailable");
    // The vector's nonce expires at SIGNED_AT + 301.
    assert_eq!(retry.as_deref(), Some("301"));
}

#[tokio::test]
async fn one_signer_over_its_share_gets_429_not_everyone_503() {
    let h = harness_with(
        Arc::new(alice_keys()),
        SIGNED_AT,
        ReplayLimits {
            per_signer: 1,
            ..limits(1000)
        },
    );
    assert_eq!(send(&h.app, Req::vector().build()).await.0, StatusCode::OK);
    let mut r = Req::vector();
    r.nonce = "another-nonce-0123456789".into();
    let (status, json, _, retry) = send(&h.app, r.build()).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(json["errorCode"], "too_many_requests");
    assert_eq!(retry.as_deref(), Some("301"));
    // A provider signature is a different signer and still gets through.
    let mut p = Req::vector();
    p.identity = ("x-ofscp-provider", "providera.com".into());
    p.nonce = "provider-nonce-0123456789".into();
    assert_eq!(send(&h.app, p.build()).await.0, StatusCode::OK);
}

#[tokio::test]
async fn replay_refused_through_the_last_acceptable_second() {
    // Signed 300 s ahead of the clock: acceptable until SIGNED_AT + 600.
    let clock = SettableClock::at(SIGNED_AT);
    let replay = Arc::new(ReplayStore::new(
        limits(1000),
        300,
        SIGNED_AT.unix_timestamp() - 301,
        "providera.com",
    ));
    let verifier = Arc::new(Verifier::new(
        provider_a(),
        300,
        replay,
        Arc::new(NoLedger),
        Arc::new(alice_keys()),
        clock.clone(),
    ));
    let app = Router::new()
        .route(PATH, post(|_: Authenticated| async { "ok" }))
        .layer(middleware::from_fn_with_state(verifier, authenticate));
    let mut r = Req::vector();
    r.timestamp = "2026-01-01T12:05:00Z".into();
    assert_eq!(send(&app, r.build()).await.0, StatusCode::OK);
    for at in [599, 600] {
        clock.set(SIGNED_AT + time::Duration::seconds(at));
        assert_eq!(
            send(&app, r.build()).await.0,
            StatusCode::UNAUTHORIZED,
            "replayed at +{at}s"
        );
    }
    // At +601 the timestamp itself is too old.
    clock.set(SIGNED_AT + time::Duration::seconds(601));
    assert_eq!(send(&app, r.build()).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn provider_signed_request_uses_its_own_replay_namespace() {
    let h = harness();
    assert_eq!(send(&h.app, Req::vector().build()).await.0, StatusCode::OK);
    // Same key id and nonce, but signed as a provider: a different namespace.
    let mut r = Req::vector();
    r.identity = ("x-ofscp-provider", "providera.com".into());
    let (status, _, text, _) = send(&h.app, r.build()).await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(text, "provider providera.com dk_abc123xyz");
}

fn verifier_at(clock: Arc<SettableClock>) -> (Verifier, Arc<ReplayStore>) {
    let replay = Arc::new(ReplayStore::new(
        limits(1000),
        300,
        SIGNED_AT.unix_timestamp() - 301,
        "providera.com",
    ));
    let v = Verifier::new(
        provider_a(),
        300,
        replay.clone(),
        Arc::new(NoLedger),
        Arc::new(alice_keys()),
        clock,
    );
    (v, replay)
}

/// Two copies precheck together; one completes; long after, a sweep expires
/// its nonce; the slow copy then completes. It must not be accepted.
#[tokio::test]
async fn slow_copy_cannot_record_with_a_stale_clock() {
    use re_ofscp_server::signing::RequestParts;
    let clock = SettableClock::at(SIGNED_AT);
    let (v, replay) = verifier_at(clock.clone());
    let req = Req::vector().build();
    let (parts, body) = req.into_parts();
    let body = body.collect().await.unwrap().to_bytes();
    let rp = RequestParts {
        method: &parts.method,
        uri: &parts.uri,
        headers: &parts.headers,
    };
    let first = v.precheck(rp).unwrap();
    let second = v.precheck(rp).unwrap();
    v.complete(first, rp, &body).await.unwrap();
    clock.set(SIGNED_AT + time::Duration::seconds(301));
    assert!(replay.is_empty(clock.now().unix_timestamp()));
    let err = v.complete(second, rp, &body).await.unwrap_err();
    assert_eq!(
        err.to_string(),
        "X-OFSCP-Timestamp expired while the request was in flight"
    );
}
