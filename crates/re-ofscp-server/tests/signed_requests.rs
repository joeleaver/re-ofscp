//! End-to-end behaviour of the signature middleware (§4.5, §8.1): header,
//! host, timestamp, digest, key and signature checks.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::harness::*;
use ed25519_dalek::VerifyingKey;
use re_ofscp_server::signing::{KeyFuture, KeyResolver, Signer, StaticKeys};

#[tokio::test]
async fn spec_vector_request_authenticates_as_alice() {
    let h = harness();
    let (status, _, text, _) = send(&h.app, Req::vector().build()).await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(text, "actor alice@providera.com dk_abc123xyz");
}

#[tokio::test]
async fn unsigned_request_reaches_handler_as_anonymous_and_is_refused_there() {
    let h = harness();
    let req = Request::post(PATH)
        .header("host", "providera.com")
        .body(Body::empty())
        .unwrap();
    let (status, json, _, _) = send(&h.app, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["detail"], "this endpoint requires a signed request");
}

#[tokio::test]
async fn tampered_body_is_400() {
    let h = harness();
    let mut r = Req::vector();
    r.send_body = Some(r#"{"content":{"text":"bye","mime":"text/plain"}}"#.into());
    let (status, json, _, _) = send(&h.app, r.build()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["errorCode"], "bad_request");
}

#[tokio::test]
async fn request_for_another_host_is_401() {
    let h = harness();
    let mut r = Req::vector();
    r.host = "providerb.com";
    let (status, json, _, _) = send(&h.app, r.build()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        json["detail"],
        "request authority does not match this provider"
    );
}

#[tokio::test]
async fn host_spelling_is_canonicalised() {
    let h = harness();
    let mut r = Req::vector();
    r.host = "ProviderA.com:443";
    assert_eq!(send(&h.app, r.build()).await.0, StatusCode::OK);
}

#[tokio::test]
async fn every_signing_header_is_required() {
    for name in [
        "x-ofscp-actor",
        "x-ofscp-key-id",
        "x-ofscp-timestamp",
        "x-ofscp-nonce",
        "x-ofscp-content-digest",
        "x-ofscp-signature",
    ] {
        let h = harness();
        let mut r = Req::vector();
        r.drop_header = Some(name);
        let (status, _, text, _) = send(&h.app, r.build()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{name}: {text}");
    }
}

#[tokio::test]
async fn actor_and_provider_together_are_refused() {
    let h = harness();
    let mut r = Req::vector();
    r.extra_header = Some(("x-ofscp-provider", "providera.com".into()));
    assert_eq!(send(&h.app, r.build()).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn non_canonical_actor_header_is_refused() {
    let h = harness();
    let mut r = Req::vector();
    r.identity.1 = "alice@ProviderA.com".into();
    let (status, json, _, _) = send(&h.app, r.build()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["detail"], "X-OFSCP-Actor is not a canonical actor");
}

#[tokio::test]
async fn clock_skew_beyond_300s_is_refused() {
    let h = harness_with(
        Arc::new(alice_keys()),
        SIGNED_AT + time::Duration::seconds(301),
        limits(1000),
    );
    assert_eq!(
        send(&h.app, Req::vector().build()).await.0,
        StatusCode::UNAUTHORIZED
    );
    let h = harness_with(
        Arc::new(alice_keys()),
        SIGNED_AT + time::Duration::seconds(300),
        limits(1000),
    );
    assert_eq!(send(&h.app, Req::vector().build()).await.0, StatusCode::OK);
}

#[tokio::test]
async fn cheap_checks_run_before_the_body_is_read() {
    // A half-signed request with an oversized body is refused for its
    // headers (401), not for its size (413): the body was never buffered.
    let h = harness();
    let req = Request::post(PATH)
        .header("host", "providera.com")
        .header("x-ofscp-nonce", "abc")
        .body(Body::from(
            "x".repeat(re_ofscp_server::signing::MAX_SIGNED_BODY + 1),
        ))
        .unwrap();
    let (status, json, _, _) = send(&h.app, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["errorCode"], "unauthorized");
    assert_eq!(json["type"], "https://providera.com/problems/unauthorized");
}

#[tokio::test]
async fn unknown_key_is_401() {
    let h = harness_with(Arc::new(StaticKeys::default()), SIGNED_AT, limits(1000));
    let (status, json, _, _) = send(&h.app, Req::vector().build()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["detail"], "unknown or revoked key");
}

#[tokio::test]
async fn oversized_signed_body_is_413() {
    let h = harness();
    let mut r = Req::vector();
    r.body = "x".repeat(re_ofscp_server::signing::MAX_SIGNED_BODY + 1);
    assert_eq!(
        send(&h.app, r.build()).await.0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
}

/// Knows the key only on a fresh lookup, like a cache that predates rotation.
struct RotatedKeys {
    key: VerifyingKey,
    fresh_calls: AtomicUsize,
}

impl KeyResolver for RotatedKeys {
    fn resolve<'a>(&'a self, _signer: &'a Signer, _key_id: &'a str, fresh: bool) -> KeyFuture<'a> {
        if fresh {
            self.fresh_calls.fetch_add(1, Ordering::SeqCst);
        }
        let key = fresh.then_some(self.key);
        Box::pin(async move { Ok(key) })
    }
}

#[tokio::test]
async fn stale_cache_is_refreshed_once_before_rejecting() {
    let keys = Arc::new(RotatedKeys {
        key: key().verifying_key(),
        fresh_calls: AtomicUsize::new(0),
    });
    let h = harness_with(keys.clone(), SIGNED_AT, limits(1000));
    assert_eq!(send(&h.app, Req::vector().build()).await.0, StatusCode::OK);
    assert_eq!(keys.fresh_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn production_router_rejects_signed_requests_it_cannot_verify() {
    let config = re_ofscp_server::Config::from_lookup(|k| match k {
        "DOMAIN" => Some("providera.com".into()),
        "RHYPEDB_ADDR" => Some("127.0.0.1:9".into()),
        _ => None,
    })
    .unwrap();
    // Started well before signing, so the warm-up is over and step 6 is
    // reached.
    let clock = SettableClock::at(SIGNED_AT - time::Duration::seconds(301));
    let state = re_ofscp_server::AppState::with_clock(
        config,
        Arc::new(StaticKeys::default()),
        clock.clone(),
    );
    clock.set(SIGNED_AT);
    let app = re_ofscp_server::router(state);
    let mut req = Req::vector().build();
    *req.uri_mut() = "/api/health".parse().unwrap();
    assert_eq!(send(&app, req).await.0, StatusCode::UNAUTHORIZED);
}
