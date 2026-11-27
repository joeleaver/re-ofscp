//! Signed-request verification (spec §4.5, §8.1).
//!
//! The seven checks run in the order §4.5 lists them, each failing with the
//! status the spec names. The replay store is only read at step 4 and written
//! after step 7 succeeds. Step 6 begins with the federation policy (§4.6 "No
//! fetch is allowed", docs/decisions/0008): a remote signer whose provider
//! is denied gets `403` before any key is resolved, cached or not, and its
//! nonce is never recorded.
//!
//! No route of this provider accepts provider signatures (§8 *Authorization*,
//! §8.1; lost-conn/ofscp#42, merged at spec 8ffa97b; docs/decisions/0021).
//! The only provider-signed requests the spec defines are §10 notification
//! deliveries, sent to an endpoint's `target`, and this provider receives
//! none. A provider-signed request passes or fails steps 1–5, then the
//! federation policy (`403` for a denied provider), and is otherwise
//! answered `401`, without a discovery fetch, a signature check or a
//! recorded nonce. Only actors are ever verified.

use std::sync::Arc;

use axum::http::{HeaderMap, Method, Uri, header};
use re_ofscp_types::{Actor, Authority};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::canonical::{self, CanonicalRequest};
use super::keys::{KeyError, KeyResolver, Requester, Resolved};
use crate::federation::{Decision, FederationPolicy, UNKNOWN_RETRY_SECS};
use crate::problem::Problem;
use crate::replay::{
    LedgerError, NonceLedger, NonceUse, ReplayError, ReplayStore, SignerKind, StoredNonce, Surface,
};

/// Header names (§4.4.1, §8.1), defined by the protocol core.
pub use ofscp_core::signing::headers;

/// Upper bound on key-id and nonce length, so one request cannot pin
/// unbounded memory in the replay store.
pub const MAX_TOKEN_LEN: usize = 256;

/// Who a request's signing headers claim signed it (§4.5 step 1). Only an
/// actor can go on to be verified (lost-conn/ofscp#42).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signer {
    /// A user, via one of their device keys (§4.4).
    Actor(Actor),
    /// A provider (`X-OFSCP-Provider`, §8.1). Never verified here: answered
    /// `403` or `401` after steps 1–5 (§8 *Authorization*).
    Provider(Authority),
}

/// A successfully verified request: always an actor's, since no route
/// accepts provider signatures (lost-conn/ofscp#42). Inserted into request
/// extensions by the signature middleware.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// The user who signed, by `(handle, domain)`.
    pub actor: Actor,
    /// The key that signed.
    pub key_id: String,
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
    /// vouch for this timestamp (§4.5 "Restarts").
    #[error("provider is warming up after a restart; re-sign and retry shortly")]
    WarmingUp {
        /// Seconds to wait.
        retry_after: u64,
    },
    /// Step 4 / record: this signer or its provider has too many nonces in
    /// flight.
    #[error("too many signed requests from this signer; slow down")]
    RateLimited {
        /// Seconds to wait.
        retry_after: u64,
    },
    /// Record: the persistent replay ledger could not be written, so the
    /// nonce cannot be vouched for across a restart.
    #[error("replay ledger unavailable; re-sign and retry shortly")]
    LedgerUnavailable,
    /// Step 5: body digest mismatch.
    #[error("X-OFSCP-Content-Digest does not match the body")]
    Digest,
    /// Step 6 (§8.1 step 2 for provider signers): the federation policy
    /// denies the signer's provider (§4.6, §8 *Authorization*,
    /// lost-conn/ofscp#25): `403` `forbidden`.
    #[error("federation with the signer's provider is not permitted")]
    Forbidden,
    /// Step 6: the federation policy has not loaded yet, so no remote
    /// signer can be judged: `503`.
    #[error("federation policy is loading; retry shortly")]
    PolicyUnknown,
    /// A permitted provider signed (`X-OFSCP-Provider`), but no route of
    /// this provider accepts provider signatures (§8 *Authorization*, §8.1,
    /// lost-conn/ofscp#42): `401` `unauthorized`, decided without fetching
    /// the signer's discovery document or checking the signature.
    #[error("this route does not accept provider signatures")]
    ProviderSignature,
    /// Step 6: no active key with that id, or no key for this signer can
    /// ever be checked (its provider is refused by our outbound rules).
    #[error("unknown or revoked key")]
    UnknownKey,
    /// Step 6: the signer's keys could not be obtained right now (their
    /// provider failed to answer, a re-fetch was rate-limited, or our own
    /// key store is down). §4.6: `503`, never `401`, because the signature
    /// was never checked.
    #[error("signing keys could not be obtained; retry shortly")]
    KeysUnavailable {
        /// Seconds to wait.
        retry_after: u64,
    },
    /// Step 7: bad signature.
    #[error("signature does not verify")]
    Signature,
}

impl From<VerifyError> for Problem {
    fn from(e: VerifyError) -> Self {
        let p = match e {
            VerifyError::Digest => Problem::bad_request(),
            VerifyError::StoreFull { retry_after }
            | VerifyError::WarmingUp { retry_after }
            | VerifyError::KeysUnavailable { retry_after } => {
                Problem::service_unavailable(retry_after)
            }
            VerifyError::LedgerUnavailable => Problem::service_unavailable(LEDGER_RETRY_SECS),
            VerifyError::RateLimited { retry_after } => Problem::too_many_requests(retry_after),
            VerifyError::Forbidden => Problem::forbidden(),
            VerifyError::PolicyUnknown => Problem::service_unavailable(UNKNOWN_RETRY_SECS),
            _ => Problem::unauthorized(),
        };
        p.with_detail(e.to_string())
    }
}

/// `Retry-After` when the replay ledger cannot be written.
const LEDGER_RETRY_SECS: u64 = 2;

/// Verifies signed requests for one provider.
#[derive(Clone)]
pub struct Verifier {
    pub(super) authority: Authority,
    pub(super) skew_secs: i64,
    pub(super) replay: Arc<ReplayStore>,
    ledger: Arc<dyn NonceLedger>,
    pub(super) keys: Arc<dyn KeyResolver>,
    pub(super) policy: Arc<FederationPolicy>,
    pub(super) clock: Arc<dyn Clock>,
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

/// The signing headers of a request that passed §4.5 steps 1–4.
///
/// Produced by [`Verifier::precheck`] *before* the body is read, so cheap
/// rejections (missing headers, wrong host, stale timestamp, replay) cost no
/// body buffering. Finish with [`Verifier::complete`].
#[derive(Debug, Clone)]
pub struct Precheck {
    signer: Signer,
    key_id: String,
    timestamp: String,
    nonce: String,
    digest: String,
    signature: String,
    signed_at: i64,
}

/// An actor's use of a nonce, as the replay store keys it. Actors are the
/// only signers whose nonces are checked or recorded (lost-conn/ofscp#42).
struct ActorNonce<'a> {
    /// Canonical actor identity and home domain, for replay quotas.
    actor: String,
    domain: String,
    key_id: &'a str,
    nonce: &'a str,
    signed_at: i64,
}

impl<'a> ActorNonce<'a> {
    fn new(actor: &Actor, key_id: &'a str, nonce: &'a str, signed_at: i64) -> Self {
        Self {
            actor: actor.to_string(),
            domain: actor.domain().to_string(),
            key_id,
            nonce,
            signed_at,
        }
    }

    fn nonce_use(&self) -> NonceUse<'_> {
        NonceUse {
            kind: SignerKind::Actor,
            signer: &self.actor,
            domain: &self.domain,
            key_id: self.key_id,
            nonce: self.nonce,
            signed_at: self.signed_at,
        }
    }
}

impl Verifier {
    /// Create a verifier for `authority` (this provider's canonical host).
    /// Every recorded nonce is also written to `ledger` before a request is
    /// accepted. Remote signers are judged by `policy` first.
    pub fn new(
        authority: Authority,
        skew_secs: i64,
        replay: Arc<ReplayStore>,
        ledger: Arc<dyn NonceLedger>,
        keys: Arc<dyn KeyResolver>,
        policy: Arc<FederationPolicy>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            authority,
            skew_secs,
            replay,
            ledger,
            keys,
            policy,
            clock,
        }
    }

    /// Step 6 begins with the federation policy, decided from the claimed
    /// provider (the actor's domain, or `X-OFSCP-Provider`) before any key
    /// is resolved (§4.5 step 6, §4.6 "No fetch is allowed", §7.3
    /// `forbidden`, §8 *Authorization*): a cached key that would verify
    /// must not rescue a denied signer. Signed HTTP and the WebSocket
    /// handshake both start step 6 here. This provider's own authority is
    /// never subject to its policy.
    pub(super) fn check_policy(&self, provider: &Authority) -> Result<(), VerifyError> {
        if *provider == self.authority {
            return Ok(());
        }
        match self.policy.decide(provider) {
            Decision::Permitted => Ok(()),
            Decision::Denied => Err(VerifyError::Forbidden),
            Decision::Unknown => Err(VerifyError::PolicyUnknown),
        }
    }

    /// The federation policy remote signers are judged by.
    pub fn policy(&self) -> &Arc<FederationPolicy> {
        &self.policy
    }

    /// The shared replay store (the WebSocket handshake records into it too).
    pub fn replay_store(&self) -> &Arc<ReplayStore> {
        &self.replay
    }

    /// The persistent replay ledger.
    pub fn ledger(&self) -> &Arc<dyn NonceLedger> {
        &self.ledger
    }

    /// Now, on this verifier's clock (unix seconds).
    pub fn now(&self) -> i64 {
        self.clock.now().unix_timestamp()
    }

    /// Run §4.5 steps 1–7 and record the nonce. Remote key fetches are
    /// charged to `requester`.
    pub async fn verify(
        &self,
        req: RequestParts<'_>,
        body: &[u8],
        requester: &Requester,
    ) -> Result<Verified, VerifyError> {
        let pre = self.precheck(req)?;
        self.complete(pre, req, body, requester).await
    }

    /// §4.5 steps 1–4, which need no body.
    pub fn precheck(&self, req: RequestParts<'_>) -> Result<Precheck, VerifyError> {
        // Step 1: header presence (and well-formedness of the signer identity).
        let h = parse_headers(req.headers)?;

        // Step 2: the request was addressed to us. The canonical string uses
        // our configured authority, so a request for another host could not
        // verify anyway; checking the Host explicitly fails fast and clearly.
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
        //
        // Only an actor's nonce is checked. A provider signature is never
        // verified, so its nonce is never recorded and the check could find
        // nothing; nor does the restart warm-up apply to it: its `403` or
        // `401` is answered during the warm-up too (§4.5 *Restarts*,
        // lost-conn/ofscp#42).
        if let Signer::Actor(actor) = &h.signer {
            let entry = ActorNonce::new(actor, h.key_id, h.nonce, signed_at);
            self.replay
                .check(Surface::SignedRequest, &entry.nonce_use(), now)
                .map_err(replay_error)?;
        }
        Ok(Precheck {
            signer: h.signer,
            key_id: h.key_id.to_owned(),
            timestamp: h.timestamp.to_owned(),
            nonce: h.nonce.to_owned(),
            digest: h.digest.to_owned(),
            signature: h.signature.to_owned(),
            signed_at,
        })
    }

    /// §4.5 steps 5–7, then record the nonce. `req` must be the request
    /// `pre` came from; remote key fetches are charged to `requester`, the
    /// client that sent it. A provider signer stops after step 5 and the
    /// federation policy: `403` if its provider is denied, otherwise `401`
    /// (§8 *Authorization*, lost-conn/ofscp#42).
    pub async fn complete(
        &self,
        pre: Precheck,
        req: RequestParts<'_>,
        body: &[u8],
        requester: &Requester,
    ) -> Result<Verified, VerifyError> {
        // Step 5: body digest.
        if canonical::content_digest(body) != pre.digest {
            return Err(VerifyError::Digest);
        }

        let actor = match pre.signer {
            Signer::Actor(actor) => {
                self.check_policy(actor.domain())?;
                actor
            }
            // The policy check sits where §8.1 step 2 would begin, and §8.1
            // step 2 is never performed: no route here accepts provider
            // signatures, so nothing is fetched, verified or recorded
            // (§8 *Authorization*, lost-conn/ofscp#42).
            Signer::Provider(provider) => {
                self.check_policy(&provider)?;
                return Err(VerifyError::ProviderSignature);
            }
        };

        // Steps 6 and 7: resolve the key and verify, re-fetching once after
        // a cached miss (see `resolve_and_check`).
        let canonical = CanonicalRequest {
            authority: self.authority.as_str(),
            method: req.method.as_str(),
            path: req.uri.path(),
            query: req.uri.query(),
            timestamp: &pre.timestamp,
            nonce: &pre.nonce,
            content_digest: &pre.digest,
        }
        .render()
        .map_err(|_| VerifyError::Headers("a signed component contains a line break"))?;
        self.resolve_and_check(&actor, &pre.key_id, &pre.signature, &canonical, requester)
            .await?;

        // Re-check and record atomically, on a fresh clock reading (reading
        // the body and resolving keys take time). The store re-checks
        // freshness under its lock on a clock that never runs backwards, so
        // a slow or stale copy cannot record a nonce a sibling already used.
        let now = self.clock.now().unix_timestamp();
        let entry = ActorNonce::new(&actor, &pre.key_id, &pre.nonce, pre.signed_at);
        let recorded = self
            .replay
            .record(Surface::SignedRequest, &entry.nonce_use(), now)
            .map_err(replay_error)?;

        // Make it durable before accepting. The in-memory entry stays even if
        // this fails, so the nonce remains burned either way.
        match self
            .ledger
            .persist(
                &StoredNonce::from_use(&entry.nonce_use(), recorded.expires),
                recorded.clock,
            )
            .await
        {
            Ok(()) => {}
            Err(LedgerError::Duplicate) => return Err(VerifyError::Replayed),
            Err(e) => {
                tracing::error!(error = %e, "replay ledger write failed");
                return Err(VerifyError::LedgerUnavailable);
            }
        }

        Ok(Verified {
            actor,
            key_id: pre.key_id,
        })
    }

    /// §4.5 steps 6 and 7: resolve `actor`'s key `key_id` and check
    /// `signature` over `canonical`. If a *cached* answer has no such key
    /// or its key does not verify, ask again with `fresh` so a newly
    /// registered or rotated key is honoured (§4.6, lost-conn/ofscp#19). An
    /// answer fetched for this lookup is final:
    /// fetching it twice could not change it. Resolvers that fetch remotely
    /// rate-limit fresh lookups (see `KeyResolver`). Returns the answer
    /// whose key verified.
    pub(super) async fn resolve_and_check(
        &self,
        actor: &Actor,
        key_id: &str,
        signature: &str,
        canonical: &str,
        requester: &Requester,
    ) -> Result<Resolved, VerifyError> {
        let attempt = |fresh| self.try_key(actor, key_id, signature, canonical, fresh, requester);
        match attempt(false).await {
            Ok(resolved) => Ok(resolved),
            Err(failure) if failure.retry => attempt(true).await.map_err(|f| f.error),
            Err(failure) => Err(failure.error),
        }
    }

    /// Resolve the key (step 6) and check the signature (step 7), once.
    async fn try_key(
        &self,
        actor: &Actor,
        key_id: &str,
        signature: &str,
        canonical: &str,
        fresh: bool,
        requester: &Requester,
    ) -> Result<Resolved, KeyFailure> {
        let resolved = match self.keys.resolve(actor, key_id, fresh, requester).await {
            Ok(resolved) => resolved,
            // The policy changed while the key was being resolved.
            Err(KeyError::Denied(_)) => return Err(KeyFailure::terminal(VerifyError::Forbidden)),
            Err(KeyError::Unresolvable(e)) => {
                tracing::info!(error = %e, key_id, "signer's keys are unresolvable");
                return Err(KeyFailure::terminal(VerifyError::UnknownKey));
            }
            Err(KeyError::Unavailable {
                reason,
                retry_after,
            }) => {
                tracing::warn!(error = %reason, key_id, "signing keys unavailable");
                return Err(KeyFailure::terminal(VerifyError::KeysUnavailable {
                    retry_after,
                }));
            }
        };
        let error = match resolved.key {
            Some(key) if canonical::verify(&key, canonical, signature) => return Ok(resolved),
            Some(_) => VerifyError::Signature,
            None => VerifyError::UnknownKey,
        };
        Err(KeyFailure {
            error,
            retry: resolved.from_cache,
        })
    }
}

/// Why steps 6–7 failed, and whether asking again with `fresh` could help.
struct KeyFailure {
    error: VerifyError,
    /// The answer came from a cache: a fresh lookup may know better.
    retry: bool,
}

impl KeyFailure {
    fn terminal(error: VerifyError) -> Self {
        Self {
            error,
            retry: false,
        }
    }
}

/// Borrowed signing headers, straight from the request.
struct SigHeaders<'a> {
    signer: Signer,
    key_id: &'a str,
    timestamp: &'a str,
    nonce: &'a str,
    digest: &'a str,
    signature: &'a str,
}

pub(super) fn replay_error(e: ReplayError) -> VerifyError {
    match e {
        ReplayError::Replayed => VerifyError::Replayed,
        ReplayError::Expired => {
            VerifyError::Timestamp("X-OFSCP-Timestamp expired while the request was in flight")
        }
        ReplayError::Full { retry_after } => VerifyError::StoreFull { retry_after },
        ReplayError::WarmingUp { retry_after } => VerifyError::WarmingUp { retry_after },
        ReplayError::RateLimited { retry_after } => VerifyError::RateLimited { retry_after },
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
