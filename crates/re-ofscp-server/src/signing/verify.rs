//! Signed-request verification (spec §4.5, §8.1).
//!
//! The seven checks run in the order §4.5 lists them, each failing with the
//! status the spec names. The replay store is only read at step 4 and written
//! after step 7 succeeds.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::http::{HeaderMap, Method, Uri, header};
use ed25519_dalek::VerifyingKey;
use re_ofscp_types::{Actor, Authority};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::canonical::{self, CanonicalRequest};
use crate::problem::Problem;
use crate::replay::{ReplayError, ReplayStore, SignerKind, Surface};

/// Header names (§4.4.1, §8.1). Lowercase, as `http` stores them.
pub mod headers {
    /// User-signed requests: the signing actor.
    pub const ACTOR: &str = "x-ofscp-actor";
    /// Provider-signed requests: the signing provider's authority.
    pub const PROVIDER: &str = "x-ofscp-provider";
    /// The signing key's id.
    pub const KEY_ID: &str = "x-ofscp-key-id";
    /// RFC 3339 moment of signing.
    pub const TIMESTAMP: &str = "x-ofscp-timestamp";
    /// Per-request nonce.
    pub const NONCE: &str = "x-ofscp-nonce";
    /// `base64(SHA-256(body))`.
    pub const CONTENT_DIGEST: &str = "x-ofscp-content-digest";
    /// `base64(Ed25519 signature)`.
    pub const SIGNATURE: &str = "x-ofscp-signature";

    /// Every header that marks a request as an attempt to sign.
    pub const ALL: [&str; 7] = [
        ACTOR,
        PROVIDER,
        KEY_ID,
        TIMESTAMP,
        NONCE,
        CONTENT_DIGEST,
        SIGNATURE,
    ];
}

/// Upper bound on key-id and nonce length, so one request cannot pin
/// unbounded memory in the replay store.
pub const MAX_TOKEN_LEN: usize = 256;

/// Who signed a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signer {
    /// A user, via one of their device keys (§4.4).
    Actor(Actor),
    /// A provider, via its signing key (§8.1).
    Provider(Authority),
}

impl Signer {
    /// The replay-store namespace for this signer.
    pub fn kind(&self) -> SignerKind {
        match self {
            Self::Actor(_) => SignerKind::Actor,
            Self::Provider(_) => SignerKind::Provider,
        }
    }
}

/// A successfully verified request. Inserted into request extensions by the
/// signature middleware.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// Who signed.
    pub signer: Signer,
    /// The key that signed.
    pub key_id: String,
}

/// A failure to resolve keys (network error, malformed key document, denied
/// by federation policy, …). §4.5 step 6 answers all of them with `401`.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{0}")]
pub struct KeyError(pub String);

/// Boxed future returned by [`KeyResolver::resolve`].
pub type KeyFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Option<VerifyingKey>, KeyError>> + Send + 'a>>;

/// Finds the active (non-revoked) public key a signer uses under a key id.
///
/// `fresh = false` may answer from cache. The verifier calls again with
/// `fresh = true` when the key is unknown or the signature fails, so rotated
/// keys are picked up (§4.6, §8.1); implementations that fetch remotely must
/// rate-limit fresh lookups (§8 "Outbound requests").
pub trait KeyResolver: Send + Sync {
    /// Resolve `key_id` for `signer`. `Ok(None)` means "no such active key".
    fn resolve<'a>(&'a self, signer: &'a Signer, key_id: &'a str, fresh: bool) -> KeyFuture<'a>;
}

/// Source of the current time (injectable for tests).
pub trait Clock: Send + Sync {
    /// Now.
    fn now(&self) -> OffsetDateTime;
}

/// The wall clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// Why verification failed, by §4.5 step.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    /// Step 1: a header is missing, duplicated, malformed, or the signer
    /// identity is ambiguous or not canonical.
    #[error("{0}")]
    Headers(&'static str),
    /// Step 2: the request was not addressed to this provider.
    #[error("request authority does not match this provider")]
    Authority,
    /// Step 3: timestamp unparsable or outside the skew window.
    #[error("{0}")]
    Timestamp(&'static str),
    /// Step 4 / record: nonce reuse.
    #[error("nonce already used for this key")]
    Replayed,
    /// Record: replay store at capacity.
    #[error("replay store is full")]
    StoreFull {
        /// Seconds to wait.
        retry_after: u64,
    },
    /// Step 4: the replay store is warming up after a restart and cannot yet
    /// vouch for this timestamp (lost-conn/ofscp#17).
    #[error("provider is warming up after a restart; retry shortly")]
    WarmingUp {
        /// Seconds to wait.
        retry_after: u64,
    },
    /// Step 5: body digest mismatch.
    #[error("X-OFSCP-Content-Digest does not match the body")]
    Digest,
    /// Step 6: no active key with that id (or lookup failed).
    #[error("unknown or revoked key")]
    UnknownKey,
    /// Step 7: bad signature.
    #[error("signature does not verify")]
    Signature,
}

impl From<VerifyError> for Problem {
    fn from(e: VerifyError) -> Self {
        let p = match e {
            VerifyError::Digest => Problem::bad_request(),
            VerifyError::StoreFull { retry_after } | VerifyError::WarmingUp { retry_after } => {
                Problem::service_unavailable(retry_after)
            }
            _ => Problem::unauthorized(),
        };
        p.with_detail(e.to_string())
    }
}

/// Verifies signed requests for one provider.
#[derive(Clone)]
pub struct Verifier {
    authority: Authority,
    skew_secs: i64,
    replay: Arc<ReplayStore>,
    keys: Arc<dyn KeyResolver>,
    clock: Arc<dyn Clock>,
}

/// The parts of an HTTP request the verifier reads.
#[derive(Debug, Clone, Copy)]
pub struct RequestParts<'a> {
    /// Method.
    pub method: &'a Method,
    /// Request-target as received (path and raw query, not decoded).
    pub uri: &'a Uri,
    /// Headers.
    pub headers: &'a HeaderMap,
}

struct SigHeaders<'a> {
    signer: Signer,
    key_id: &'a str,
    timestamp: &'a str,
    nonce: &'a str,
    digest: &'a str,
    signature: &'a str,
}

impl Verifier {
    /// Create a verifier for `authority` (this provider's canonical host).
    pub fn new(
        authority: Authority,
        skew_secs: i64,
        replay: Arc<ReplayStore>,
        keys: Arc<dyn KeyResolver>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            authority,
            skew_secs,
            replay,
            keys,
            clock,
        }
    }

    /// The shared replay store (the WebSocket handshake records into it too).
    pub fn replay_store(&self) -> &Arc<ReplayStore> {
        &self.replay
    }

    /// Run §4.5 steps 1–7 and record the nonce.
    pub async fn verify(
        &self,
        req: RequestParts<'_>,
        body: &[u8],
    ) -> Result<Verified, VerifyError> {
        // Step 1: header presence (and well-formedness of the signer identity).
        let h = parse_headers(req.headers)?;

        // Step 2: the request was addressed to us. The canonical string uses
        // our configured authority, so a request for another host cannot
        // verify; checking the Host explicitly gives a clear error first.
        let host = request_host(req)
            .and_then(|h| Authority::canonicalize(h).ok())
            .ok_or(VerifyError::Authority)?;
        if host != self.authority {
            return Err(VerifyError::Authority);
        }

        // Step 3: timestamp within ±skew.
        let signed_at = OffsetDateTime::parse(h.timestamp, &Rfc3339)
            .map_err(|_| VerifyError::Timestamp("X-OFSCP-Timestamp is not RFC 3339"))?
            .unix_timestamp();
        let now = self.clock.now().unix_timestamp();
        if (now - signed_at).abs() > self.skew_secs {
            return Err(VerifyError::Timestamp(
                "X-OFSCP-Timestamp is outside the allowed clock skew",
            ));
        }

        // Step 4: replay check only. Recording happens after step 7.
        let kind = h.signer.kind();
        self.replay
            .check(
                Surface::SignedRequest,
                kind,
                h.key_id,
                h.nonce,
                signed_at,
                now,
            )
            .map_err(replay_error)?;

        // Step 5: body digest.
        if canonical::content_digest(body) != h.digest {
            return Err(VerifyError::Digest);
        }

        // Steps 6 and 7: resolve the key and verify; on failure re-fetch once
        // so a freshly rotated key is honoured (§4.6, §8.1).
        let canonical = CanonicalRequest {
            authority: self.authority.as_str(),
            method: req.method.as_str(),
            path: req.uri.path(),
            query: req.uri.query(),
            timestamp: h.timestamp,
            nonce: h.nonce,
            content_digest: h.digest,
        }
        .render();
        let mut outcome = self.try_key(&h, &canonical, false).await;
        if outcome.is_err() {
            outcome = self.try_key(&h, &canonical, true).await;
        }
        outcome?;

        // Re-check and record atomically.
        self.replay
            .record(
                Surface::SignedRequest,
                kind,
                h.key_id,
                h.nonce,
                signed_at,
                now,
            )
            .map_err(replay_error)?;

        Ok(Verified {
            signer: h.signer,
            key_id: h.key_id.to_owned(),
        })
    }

    async fn try_key(
        &self,
        h: &SigHeaders<'_>,
        canonical: &str,
        fresh: bool,
    ) -> Result<(), VerifyError> {
        let key = match self.keys.resolve(&h.signer, h.key_id, fresh).await {
            Ok(Some(key)) => key,
            Ok(None) => return Err(VerifyError::UnknownKey),
            Err(e) => {
                tracing::debug!(error = %e, key_id = h.key_id, "key resolution failed");
                return Err(VerifyError::UnknownKey);
            }
        };
        if canonical::verify(&key, canonical, h.signature) {
            Ok(())
        } else {
            Err(VerifyError::Signature)
        }
    }
}

fn replay_error(e: ReplayError) -> VerifyError {
    match e {
        ReplayError::Replayed => VerifyError::Replayed,
        ReplayError::Full { retry_after } => VerifyError::StoreFull { retry_after },
        ReplayError::WarmingUp { retry_after } => VerifyError::WarmingUp { retry_after },
    }
}

/// The host the client addressed: the `Host` header, or the URI authority
/// (HTTP/2 `:authority`). Forwarding headers are never trusted.
fn request_host<'a>(req: RequestParts<'a>) -> Option<&'a str> {
    let mut hosts = req.headers.get_all(header::HOST).iter();
    match (hosts.next(), hosts.next()) {
        (Some(h), None) => h.to_str().ok(),
        (None, None) => req.uri.authority().map(|a| a.as_str()),
        _ => None,
    }
}

/// Exactly one value of `name`, as visible ASCII.
fn single<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, VerifyError> {
    let mut values = headers.get_all(name).iter();
    match (values.next(), values.next()) {
        (None, _) => Ok(None),
        (Some(v), None) => v
            .to_str()
            .map(Some)
            .map_err(|_| VerifyError::Headers("signing header is not visible ASCII")),
        (Some(_), Some(_)) => Err(VerifyError::Headers("signing header repeated")),
    }
}

fn required<'a>(headers: &'a HeaderMap, name: &'static str) -> Result<&'a str, VerifyError> {
    single(headers, name)?.ok_or(VerifyError::Headers("missing X-OFSCP-* signing header"))
}

fn parse_headers(headers: &HeaderMap) -> Result<SigHeaders<'_>, VerifyError> {
    let actor = single(headers, headers::ACTOR)?;
    let provider = single(headers, headers::PROVIDER)?;
    let key_id = required(headers, headers::KEY_ID)?;
    let timestamp = required(headers, headers::TIMESTAMP)?;
    let nonce = required(headers, headers::NONCE)?;
    let digest = required(headers, headers::CONTENT_DIGEST)?;
    let signature = required(headers, headers::SIGNATURE)?;

    let signer =
        match (actor, provider) {
            (Some(a), None) => Signer::Actor(
                Actor::parse_canonical(a)
                    .map_err(|_| VerifyError::Headers("X-OFSCP-Actor is not a canonical actor"))?,
            ),
            (None, Some(p)) => Signer::Provider(Authority::parse_canonical(p).map_err(|_| {
                VerifyError::Headers("X-OFSCP-Provider is not a canonical authority")
            })?),
            (Some(_), Some(_)) => {
                return Err(VerifyError::Headers(
                    "send exactly one of X-OFSCP-Actor and X-OFSCP-Provider",
                ));
            }
            (None, None) => {
                return Err(VerifyError::Headers(
                    "missing X-OFSCP-Actor or X-OFSCP-Provider",
                ));
            }
        };
    for v in [key_id, nonce] {
        if v.is_empty() || v.len() > MAX_TOKEN_LEN {
            return Err(VerifyError::Headers(
                "key id or nonce has an invalid length",
            ));
        }
    }
    Ok(SigHeaders {
        signer,
        key_id,
        timestamp,
        nonce,
        digest,
        signature,
    })
}

/// A fixed set of keys, for tests and for statically configured peers.
#[derive(Debug, Default, Clone)]
pub struct StaticKeys {
    keys: Vec<(Signer, String, VerifyingKey)>,
}

impl StaticKeys {
    /// Add a key.
    #[must_use]
    pub fn with(mut self, signer: Signer, key_id: &str, key: VerifyingKey) -> Self {
        self.keys.push((signer, key_id.to_owned(), key));
        self
    }
}

impl KeyResolver for StaticKeys {
    fn resolve<'a>(&'a self, signer: &'a Signer, key_id: &'a str, _fresh: bool) -> KeyFuture<'a> {
        let found = self
            .keys
            .iter()
            .find(|(s, k, _)| s == signer && k == key_id)
            .map(|(_, _, key)| *key);
        Box::pin(async move { Ok(found) })
    }
}
