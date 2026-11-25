//! Shared harness for the signed-request integration tests: the spec
//! vector's key and request, a router with the signature and problem
//! layers, and controllable clocks.
#![allow(dead_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::post;
use axum::{Router, middleware};
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt;
use re_ofscp_server::problem::{self, ProblemBase};
use re_ofscp_server::replay::{NoLedger, ReplayLimits, ReplayStore};
use re_ofscp_server::signing::canonical::{CanonicalRequest, content_digest, sign};
use re_ofscp_server::signing::{
    Authenticated, Clock, KeyResolver, SignatureLayer, Signer, StaticKeys, Verifier, authenticate,
};
use re_ofscp_types::{Actor, Authority};
use time::OffsetDateTime;
use time::macros::datetime;
use tower::ServiceExt;

use super::{spec_json, vector_key};

pub const PATH: &str = "/api/groups/grp_1/channels/chn_general/messages";

pub const SIGNED_AT: OffsetDateTime = datetime!(2026-01-01 12:00:00 UTC);

pub struct FixedClock(pub OffsetDateTime);
impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

/// A clock tests can move.
pub struct SettableClock(AtomicI64);
impl SettableClock {
    pub fn at(t: OffsetDateTime) -> Arc<Self> {
        Arc::new(Self(AtomicI64::new(t.unix_timestamp())))
    }
    pub fn set(&self, t: OffsetDateTime) {
        self.0.store(t.unix_timestamp(), Ordering::SeqCst);
    }
}

impl Clock for SettableClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(self.0.load(Ordering::SeqCst)).unwrap()
    }
}

/// Only the pool bounds apply.
pub fn limits(capacity: usize) -> ReplayLimits {
    ReplayLimits {
        local_total: capacity,
        remote_total: capacity,
        per_signer: usize::MAX,
        per_remote_domain: usize::MAX,
    }
}

pub fn alice() -> Actor {
    Actor::parse_canonical("alice@providera.com").unwrap()
}

pub fn provider_a() -> Authority {
    Authority::parse_canonical("providera.com").unwrap()
}

pub fn key() -> SigningKey {
    vector_key(&spec_json("signing-vector.json"))
}

pub fn alice_keys() -> StaticKeys {
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

pub struct Harness {
    pub app: Router,
    pub replay: Arc<ReplayStore>,
}

pub fn harness_with(
    keys: Arc<dyn KeyResolver>,
    now: OffsetDateTime,
    limits: ReplayLimits,
) -> Harness {
    harness_full(keys, now, limits, None)
}

/// A harness behind a trusted proxy that names the client in
/// `client_ip_header` (`CLIENT_IP_HEADER`).
pub fn harness_full(
    keys: Arc<dyn KeyResolver>,
    now: OffsetDateTime,
    limits: ReplayLimits,
    client_ip_header: Option<&str>,
) -> Harness {
    // The store began 301 s before SIGNED_AT, so its warm-up covers
    // timestamps up to SIGNED_AT - 1.
    let replay = Arc::new(ReplayStore::new(
        limits,
        300,
        SIGNED_AT.unix_timestamp() - 301,
        "providera.com",
    ));
    let verifier = Arc::new(Verifier::new(
        provider_a(),
        300,
        replay.clone(),
        Arc::new(NoLedger),
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
        .layer(middleware::from_fn_with_state(
            SignatureLayer::new(verifier, client_ip_header.map(str::to_owned)),
            authenticate,
        ))
        .layer(middleware::map_response_with_state(
            ProblemBase::new(&provider_a()),
            problem::render,
        ));
    Harness { app, replay }
}

pub fn harness() -> Harness {
    harness_with(Arc::new(alice_keys()), SIGNED_AT, limits(1000))
}

/// A request signed like the spec vector, with knobs for breaking it.
#[derive(Clone)]
pub struct Req {
    pub method: &'static str,
    pub path: &'static str,
    pub query: Option<&'static str>,
    pub host: &'static str,
    pub identity: (&'static str, String),
    pub nonce: String,
    pub body: String,
    pub send_body: Option<String>,
    pub timestamp: String,
    pub drop_header: Option<&'static str>,
    pub extra_header: Option<(&'static str, String)>,
    pub signature: Option<String>,
}

impl Req {
    /// The spec's signing vector, exactly.
    pub fn vector() -> Self {
        Self {
            method: "POST",
            path: PATH,
            query: Some("foo=1"),
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

    /// A signed, bodiless `GET /api/health` with the vector's key, timestamp
    /// and nonce (for tests against the production router).
    pub fn health() -> Self {
        Self {
            method: "GET",
            path: "/api/health",
            query: None,
            body: String::new(),
            ..Self::vector()
        }
    }

    pub fn build(&self) -> Request<Body> {
        let digest = content_digest(self.body.as_bytes());
        let canonical = CanonicalRequest {
            authority: "providera.com",
            method: self.method,
            path: self.path,
            query: self.query,
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
        let uri = match self.query {
            Some(q) => format!("{}?{q}", self.path),
            None => self.path.to_owned(),
        };
        let mut b = Request::builder().method(self.method).uri(uri);
        for (k, v) in headers {
            b = b.header(k, v);
        }
        b.body(Body::from(
            self.send_body.clone().unwrap_or_else(|| self.body.clone()),
        ))
        .unwrap()
    }
}

pub async fn send(
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

/// A signed request from any key and actor (for flows where keys are
/// registered at run time). `timestamp` is RFC 3339; the nonce is random.
pub fn signed(
    key: &SigningKey,
    actor: &str,
    key_id: &str,
    method: &str,
    path: &str,
    body: &str,
    timestamp: &str,
) -> Request<Body> {
    signed_as(
        key,
        ("x-ofscp-actor", actor),
        key_id,
        method,
        path,
        body,
        timestamp,
    )
}

/// [`signed`], naming the signer with `identity`: (`x-ofscp-actor`, an
/// actor) or (`x-ofscp-provider`, an authority).
pub fn signed_as(
    key: &SigningKey,
    identity: (&str, &str),
    key_id: &str,
    method: &str,
    path: &str,
    body: &str,
    timestamp: &str,
) -> Request<Body> {
    let digest = content_digest(body.as_bytes());
    let mut raw = [0u8; 18];
    for (i, b) in raw.iter_mut().enumerate() {
        *b = (rand_u64() >> (i % 8 * 8)) as u8;
    }
    let nonce: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    let canonical = CanonicalRequest {
        authority: "providera.com",
        method,
        path,
        query: None,
        timestamp,
        nonce: &nonce,
        content_digest: &digest,
    }
    .render();
    Request::builder()
        .method(method)
        .uri(path)
        .header("host", "providera.com")
        .header("content-type", "application/json")
        .header(identity.0, identity.1)
        .header("x-ofscp-key-id", key_id)
        .header("x-ofscp-timestamp", timestamp)
        .header("x-ofscp-nonce", nonce)
        .header("x-ofscp-content-digest", digest)
        .header("x-ofscp-signature", sign(key, &canonical))
        .body(Body::from(body.to_owned()))
        .unwrap()
}

/// A process-unique pseudo-random number (test nonces only).
pub fn rand_u64() -> u64 {
    use std::sync::atomic::AtomicU64;
    static COUNTER: AtomicU64 = AtomicU64::new(0x9e37_79b9_7f4a_7c15);
    let n = COUNTER.fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64);
    (n ^ t).wrapping_mul(0xbf58_476d_1ce4_e5b9)
}

/// A fresh Ed25519 key.
pub fn new_key() -> SigningKey {
    let mut seed = [0u8; 32];
    for chunk in seed.chunks_mut(8) {
        chunk.copy_from_slice(&rand_u64().to_le_bytes());
    }
    SigningKey::from_bytes(&seed)
}
