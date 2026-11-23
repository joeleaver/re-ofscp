//! End-to-end behaviour of the signature middleware (§4.5, §8.1).

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::post;
use axum::{Router, middleware};
use common::{spec_json, vector_key};
use ed25519_dalek::{SigningKey, VerifyingKey};
use http_body_util::BodyExt;
use re_ofscp_server::replay::ReplayStore;
use re_ofscp_server::signing::canonical::{CanonicalRequest, content_digest, sign};
use re_ofscp_server::signing::{
    Authenticated, Clock, KeyFuture, KeyResolver, Signer, StaticKeys, Verifier, authenticate,
};
use re_ofscp_types::{Actor, Authority};
use time::OffsetDateTime;
use time::macros::datetime;
use tower::ServiceExt;

const PATH: &str = "/api/groups/grp_1/channels/chn_general/messages";
const SIGNED_AT: OffsetDateTime = datetime!(2026-01-01 12:00:00 UTC);

struct FixedClock(OffsetDateTime);
impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

fn alice() -> Actor {
    Actor::parse_canonical("alice@providera.com").unwrap()
}

fn provider_a() -> Authority {
    Authority::parse_canonical("providera.com").unwrap()
}

fn key() -> SigningKey {
    vector_key(&spec_json("signing-vector.json"))
}

fn alice_keys() -> StaticKeys {
    StaticKeys::default()
        .with(
            Signer::Actor(alice()),
            "dk_abc123xyz",
            key().verifying_key(),
        )
        .with(
            Signer::Provider(provider_a()),
            "dk_abc123xyz",
            key().verifying_key(),
        )
}

struct Harness {
    app: Router,
    replay: Arc<ReplayStore>,
}

fn harness_with(keys: Arc<dyn KeyResolver>, now: OffsetDateTime, capacity: usize) -> Harness {
    // The store's warm-up ended exactly at SIGNED_AT.
    let replay = Arc::new(ReplayStore::new(
        capacity,
        600,
        SIGNED_AT.unix_timestamp() - 300,
        300,
    ));
    let verifier = Arc::new(Verifier::new(
        provider_a(),
        300,
        replay.clone(),
        keys,
        Arc::new(FixedClock(now)),
    ));
    let app = Router::new()
        .route(
            PATH,
            post(|auth: Authenticated| async move {
                match auth.0.signer {
                    Signer::Actor(a) => format!("actor {a} {}", auth.0.key_id),
                    Signer::Provider(p) => format!("provider {p} {}", auth.0.key_id),
                }
            }),
        )
        .layer(middleware::from_fn_with_state(verifier, authenticate));
    Harness { app, replay }
}

fn harness() -> Harness {
    harness_with(Arc::new(alice_keys()), SIGNED_AT, 1000)
}

/// A request signed like the spec vector, with knobs for breaking it.
#[derive(Clone)]
struct Req {
    host: &'static str,
    identity: (&'static str, String),
    nonce: String,
    body: String,
    send_body: Option<String>,
    timestamp: String,
    drop_header: Option<&'static str>,
    extra_header: Option<(&'static str, String)>,
    signature: Option<String>,
}

impl Req {
    fn vector() -> Self {
        Self {
            host: "providera.com",
            identity: ("x-ofscp-actor", "alice@providera.com".into()),
            nonce: "8wQk2mJ0r5sV1xZ3aB6cDg".into(),
            body: r#"{"content":{"text":"hi","mime":"text/plain"}}"#.into(),
            send_body: None,
            timestamp: "2026-01-01T12:00:00Z".into(),
            drop_header: None,
            extra_header: None,
            signature: None,
        }
    }

    fn build(&self) -> Request<Body> {
        let digest = content_digest(self.body.as_bytes());
        let canonical = CanonicalRequest {
            authority: "providera.com",
            method: "POST",
            path: PATH,
            query: Some("foo=1"),
            timestamp: &self.timestamp,
            nonce: &self.nonce,
            content_digest: &digest,
        }
        .render();
        let signature = self
            .signature
            .clone()
            .unwrap_or_else(|| sign(&key(), &canonical));
        let mut headers = vec![
            ("host", self.host.to_owned()),
            (self.identity.0, self.identity.1.clone()),
            ("x-ofscp-key-id", "dk_abc123xyz".into()),
            ("x-ofscp-timestamp", self.timestamp.clone()),
            ("x-ofscp-nonce", self.nonce.clone()),
            ("x-ofscp-content-digest", digest),
            ("x-ofscp-signature", signature),
        ];
        if let Some(drop) = self.drop_header {
            headers.retain(|(k, _)| *k != drop);
        }
        if let Some(extra) = &self.extra_header {
            headers.push((extra.0, extra.1.clone()));
        }
        let mut b = Request::post(format!("{PATH}?foo=1"));
        for (k, v) in headers {
            b = b.header(k, v);
        }
        b.body(Body::from(
            self.send_body.clone().unwrap_or_else(|| self.body.clone()),
        ))
        .unwrap()
    }
}

async fn send(
    app: &Router,
    req: Request<Body>,
) -> (StatusCode, serde_json::Value, String, Option<String>) {
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let retry = res
        .headers()
        .get("retry-after")
        .map(|v| v.to_str().unwrap().to_owned());
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json, text, retry)
}

#[tokio::test]
async fn spec_vector_request_authenticates_as_alice() {
    let h = harness();
    let (status, _, text, _) = send(&h.app, Req::vector().build()).await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(text, "actor alice@providera.com dk_abc123xyz");
}

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
        1000,
    );
    assert_eq!(
        send(&h.app, Req::vector().build()).await.0,
        StatusCode::UNAUTHORIZED
    );
    let h = harness_with(
        Arc::new(alice_keys()),
        SIGNED_AT + time::Duration::seconds(300),
        1000,
    );
    assert_eq!(send(&h.app, Req::vector().build()).await.0, StatusCode::OK);
}

#[tokio::test]
async fn requests_during_restart_warm_up_get_503_with_retry_after() {
    // The store's warm-up ends at SIGNED_AT; a request timestamped one second
    // earlier may have been recorded by a previous process.
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
    // Started exactly when the vector was signed: inside the warm-up.
    let state = re_ofscp_server::AppState::with_clock(
        config,
        Arc::new(alice_keys()),
        Arc::new(FixedClock(SIGNED_AT)),
    );
    let app = re_ofscp_server::router(state);
    let mut req = Req::vector().build();
    *req.uri_mut() = "/api/health".parse().unwrap();
    let (status, _, _, retry) = send(&app, req).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(retry.as_deref(), Some("300"));
}

#[tokio::test]
async fn full_replay_store_fails_closed_with_503() {
    let h = harness_with(Arc::new(alice_keys()), SIGNED_AT, 1);
    assert_eq!(send(&h.app, Req::vector().build()).await.0, StatusCode::OK);
    let mut r = Req::vector();
    r.nonce = "another-nonce-0123456789".into();
    let (status, json, _, retry) = send(&h.app, r.build()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json["errorCode"], "service_unavailable");
    assert_eq!(retry.as_deref(), Some("600"));
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

#[tokio::test]
async fn unknown_key_is_401() {
    let h = harness_with(Arc::new(StaticKeys::default()), SIGNED_AT, 1000);
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
    let h = harness_with(keys.clone(), SIGNED_AT, 1000);
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
    // Started 300 s before signing (the request is 300 s ahead, the most
    // skew allows), so the warm-up ends exactly at SIGNED_AT and step 6 is
    // reached.
    let state = re_ofscp_server::AppState::with_clock(
        config,
        Arc::new(StaticKeys::default()),
        Arc::new(FixedClock(SIGNED_AT - time::Duration::seconds(300))),
    );
    let app = re_ofscp_server::router(state);
    let mut req = Req::vector().build();
    *req.uri_mut() = "/api/health".parse().unwrap();
    assert_eq!(send(&app, req).await.0, StatusCode::UNAUTHORIZED);
}
