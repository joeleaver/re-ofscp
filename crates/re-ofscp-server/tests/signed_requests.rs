//! End-to-end behaviour of the signature middleware (§4.5, §8.1): header,
//! host, timestamp, digest, key and signature checks.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::harness::*;
use ed25519_dalek::VerifyingKey;
use re_ofscp_server::signing::{
    KeyError, KeyFuture, KeyResolver, Requester, Resolved, Signer, StaticKeys,
};

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

/// Answers non-fresh lookups with `stale` (from cache or not, per
/// `stale_from_cache`) and fresh ones with the current key, counting fresh
/// lookups.
struct RotatedKeys {
    stale: Option<VerifyingKey>,
    stale_from_cache: bool,
    current: VerifyingKey,
    fresh_calls: AtomicUsize,
}

impl RotatedKeys {
    fn new(stale: Option<VerifyingKey>, stale_from_cache: bool) -> Arc<Self> {
        Arc::new(Self {
            stale,
            stale_from_cache,
            current: key().verifying_key(),
            fresh_calls: AtomicUsize::new(0),
        })
    }
}

impl KeyResolver for RotatedKeys {
    fn resolve<'a>(
        &'a self,
        _signer: &'a Signer,
        _key_id: &'a str,
        fresh: bool,
        _requester: &'a Requester,
    ) -> KeyFuture<'a> {
        let answer = if fresh {
            self.fresh_calls.fetch_add(1, Ordering::SeqCst);
            Resolved::authoritative(Some(self.current))
        } else if self.stale_from_cache {
            Resolved::cached(self.stale)
        } else {
            Resolved::authoritative(self.stale)
        };
        Box::pin(async move { Ok(answer) })
    }
}

#[tokio::test]
async fn a_cached_miss_is_refreshed_once_before_rejecting() {
    let keys = RotatedKeys::new(None, true);
    let h = harness_with(keys.clone(), SIGNED_AT, limits(1000));
    assert_eq!(send(&h.app, Req::vector().build()).await.0, StatusCode::OK);
    assert_eq!(keys.fresh_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_cached_key_that_fails_is_refreshed_once_before_rejecting() {
    let keys = RotatedKeys::new(Some(new_key().verifying_key()), true);
    let h = harness_with(keys.clone(), SIGNED_AT, limits(1000));
    assert_eq!(send(&h.app, Req::vector().build()).await.0, StatusCode::OK);
    assert_eq!(keys.fresh_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn an_answer_fetched_for_this_request_is_final() {
    // No key, and a wrong key, both straight from the source: asking again
    // could not change them, so there is no second lookup (lost-conn/ofscp#19).
    for (stale, detail) in [
        (None, "unknown or revoked key"),
        (Some(new_key().verifying_key()), "signature does not verify"),
    ] {
        let keys = RotatedKeys::new(stale, false);
        let h = harness_with(keys.clone(), SIGNED_AT, limits(1000));
        let (status, json, _, _) = send(&h.app, Req::vector().build()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(json["detail"], detail);
        assert_eq!(keys.fresh_calls.load(Ordering::SeqCst), 0);
    }
}

/// Always fails with `error`.
struct FailingKeys(KeyError);

impl KeyResolver for FailingKeys {
    fn resolve<'a>(
        &'a self,
        _signer: &'a Signer,
        _key_id: &'a str,
        _fresh: bool,
        _requester: &'a Requester,
    ) -> KeyFuture<'a> {
        let e = self.0.clone();
        Box::pin(async move { Err(e) })
    }
}

#[tokio::test]
async fn key_errors_map_to_401_and_503_with_retry_after() {
    let h = harness_with(
        Arc::new(FailingKeys(KeyError::Unresolvable("refused".into()))),
        SIGNED_AT,
        limits(1000),
    );
    let (status, json, _, retry) = send(&h.app, Req::vector().build()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["detail"], "unknown or revoked key");
    assert_eq!(retry, None);

    let h = harness_with(
        Arc::new(FailingKeys(KeyError::Unavailable {
            reason: "remote down".into(),
            retry_after: 42,
        })),
        SIGNED_AT,
        limits(1000),
    );
    let (status, json, text, retry) = send(&h.app, Req::vector().build()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json["errorCode"], "service_unavailable");
    assert_eq!(retry.as_deref(), Some("42"));
    assert!(!text.contains("remote down"), "reasons stay in the logs");
}

#[tokio::test]
async fn production_router_rejects_signed_requests_it_cannot_verify() {
    let config = re_ofscp_server::Config::from_lookup(|k| match k {
        "DOMAIN" => Some("providera.com".into()),
        "PROVIDER_SIGNING_KEY" => Some(common::PROVIDER_SIGNING_KEY.into()),
        "RHYPEDB_ADDR" => Some("127.0.0.1:9".into()),
        _ => None,
    })
    .unwrap();
    // Started well before signing, so the warm-up is over and step 6 is
    // reached.
    let clock = SettableClock::at(SIGNED_AT - time::Duration::seconds(301));
    let state = re_ofscp_server::AppState::builder(config)
        .keys(Arc::new(StaticKeys::default()))
        .ledger(Arc::new(re_ofscp_server::replay::NoLedger))
        .clock(clock.clone())
        .build()
        .unwrap();
    clock.set(SIGNED_AT);
    let app = re_ofscp_server::router(state);
    let req = Req::health().build();
    let (status, json, _, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["detail"], "unknown or revoked key");
}

/// Records whom each lookup was made for, then answers like `StaticKeys`.
struct RecordingKeys {
    seen: std::sync::Mutex<Vec<String>>,
}

impl KeyResolver for RecordingKeys {
    fn resolve<'a>(
        &'a self,
        _signer: &'a Signer,
        _key_id: &'a str,
        _fresh: bool,
        requester: &'a Requester,
    ) -> KeyFuture<'a> {
        self.seen
            .lock()
            .unwrap()
            .push(requester.as_str().to_owned());
        Box::pin(async move { Ok(Resolved::authoritative(Some(key().verifying_key()))) })
    }
}

#[tokio::test]
async fn key_lookups_are_made_for_the_requesting_client() {
    // Remote key fetches are charged to the client that sent the request:
    // behind a trusted proxy, the last entry of its header.
    let keys = Arc::new(RecordingKeys {
        seen: std::sync::Mutex::new(Vec::new()),
    });
    let h = harness_full(
        keys.clone(),
        SIGNED_AT,
        limits(1000),
        Some("x-forwarded-for"),
    );
    let mut r = Req::vector();
    r.extra_header = Some(("x-forwarded-for", "192.0.2.1, 203.0.113.9".into()));
    assert_eq!(send(&h.app, r.build()).await.0, StatusCode::OK);
    // Without connect info or a proxy header the client is unknown.
    let h = harness_with(keys.clone(), SIGNED_AT, limits(1000));
    assert_eq!(send(&h.app, Req::vector().build()).await.0, StatusCode::OK);
    assert_eq!(*keys.seen.lock().unwrap(), ["203.0.113.9", "unknown"]);
}
