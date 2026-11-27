//! Key resolution for the verifier (spec §4.5 step 6, §4.6). Only actors'
//! keys are ever resolved: no route accepts provider signatures
//! (lost-conn/ofscp#42, docs/decisions/0021).
//!
//! A [`KeyResolver`] finds the active public key an actor uses under a key
//! id, and says whether its answer came from a cache. The verifier needs
//! that to apply the §4.6 re-fetch rule (lost-conn/ofscp#19): when a cached
//! answer has no matching key, or the key does not verify the signature, it
//! asks again with `fresh = true`; an answer that was fetched for this
//! request is final.

use std::future::Future;
use std::pin::Pin;

use ed25519_dalek::VerifyingKey;

use re_ofscp_types::Actor;

/// How long an answer may be relied on. Single requests ignore it; a
/// long-lived connection authenticated with the key keeps it, and must
/// re-confirm the key before it runs out (§7.1, lost-conn/ofscp#20).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifetime {
    /// No expiry: the key stays valid until it is revoked, and revocation
    /// is announced in this process (local accounts, static keys).
    Unbounded,
    /// Until this unix second: the `cache_until` of the cache entry the
    /// answer came from, or that the fetch made for it created.
    Until(i64),
    /// The answer came from a completed fetch that may not be cached: it
    /// held when fetched, and nothing vouches for it afterwards.
    Uncached,
}

/// What a resolver found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resolved {
    /// The active key with that id, or `None` for "no such active key".
    pub key: Option<VerifyingKey>,
    /// Whether the answer came from a cache rather than from the
    /// authoritative source read for this lookup. A cached answer that
    /// fails verification is worth re-checking with `fresh = true`.
    pub from_cache: bool,
    /// How long the answer may be relied on.
    pub lifetime: Lifetime,
}

impl Resolved {
    /// An answer read from a cache, with no expiry.
    pub fn cached(key: Option<VerifyingKey>) -> Self {
        Self {
            key,
            from_cache: true,
            lifetime: Lifetime::Unbounded,
        }
    }

    /// An answer read from the authoritative source for this lookup, with
    /// no expiry.
    pub fn authoritative(key: Option<VerifyingKey>) -> Self {
        Self {
            key,
            from_cache: false,
            lifetime: Lifetime::Unbounded,
        }
    }

    /// The same answer, relied on for `lifetime`.
    #[must_use]
    pub fn lasting(self, lifetime: Lifetime) -> Self {
        Self { lifetime, ..self }
    }
}

/// What re-confirming a connection's key found (§7.1 "For a connection
/// from a remote actor", lost-conn/ofscp#20).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reconfirmed {
    /// A completed fetch (or the authoritative store) still publishes the
    /// very key, now relied on for this lifetime.
    Present(Lifetime),
    /// A completed fetch shows the key is no longer published (a valid
    /// keys response without it, a `404`, or the id now names another
    /// key): close with `4003`.
    Gone,
    /// Nothing completed: the fetch failed, was refused by our outbound
    /// rules, or was suppressed by a limit. Not evidence of revocation:
    /// the connection lives on what it already holds, and closes with
    /// `4001` once that runs out.
    Unconfirmed(String),
}

/// Boxed future returned by [`KeyResolver::reconfirm`].
pub type ReconfirmFuture<'a> = Pin<Box<dyn Future<Output = Reconfirmed> + Send + 'a>>;

/// A failure to resolve keys.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    /// The federation policy denies the signer's provider: no fetch, and no
    /// cached key either (§4.6 "No fetch is allowed", §8 *Authorization*).
    /// §4.5 step 6: `403` `forbidden`.
    #[error("federation with {0} is denied by policy")]
    Denied(String),
    /// No key for this signer can ever be checked: our outbound-request
    /// rules refuse to contact its provider (§4.6 "No fetch is allowed",
    /// §8 "Outbound requests"). §4.5 step 6: `401`.
    #[error("keys unresolvable: {0}")]
    Unresolvable(String),
    /// The keys could not be obtained right now: the signer's provider did
    /// not answer usefully, a re-fetch was rate-limited, or this provider's
    /// own key store is down. Not the client's fault: `503` with
    /// `Retry-After`, so it retries rather than concluding its credentials
    /// are bad.
    #[error("keys unavailable: {reason}")]
    Unavailable {
        /// What went wrong (logged, never sent to the client).
        reason: String,
        /// Seconds until a retry can succeed.
        retry_after: u64,
    },
}

/// Whom a lookup is made for: the rate-limit key of the client whose
/// request is being verified (`client::client_key`: its address, or its
/// IPv6 /64) and, for an IPv6 client, the /48 it sits in. A resolver that
/// fetches remotely charges the fetches it makes to this client (and its
/// network), so one client cannot spend every peer's fetch budget
/// (docs/decisions/0006). Resolvers that never fetch ignore it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Requester {
    key: String,
    network: Option<String>,
}

impl Requester {
    /// The client with rate-limit key `key`, in no wider network.
    pub fn new(key: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            network: None,
        }
    }

    /// The client with rate-limit key `key`, within the network `network`
    /// (`client::ClientKeys::network`), if any.
    pub fn within(key: impl Into<String>, network: Option<String>) -> Self {
        Self {
            key: key.into(),
            network,
        }
    }

    /// The rate-limit key.
    pub fn as_str(&self) -> &str {
        &self.key
    }

    /// The rate-limit key of the client's network (its IPv6 /48), if any.
    pub fn network(&self) -> Option<&str> {
        self.network.as_deref()
    }
}

/// Boxed future returned by [`KeyResolver::resolve`].
pub type KeyFuture<'a> = Pin<Box<dyn Future<Output = Result<Resolved, KeyError>> + Send + 'a>>;

/// Finds the active (non-revoked) public key an actor uses under a key id.
///
/// `fresh = false` may answer from cache. The verifier calls again with
/// `fresh = true` only when a *cached* answer had no such key or its key
/// did not verify the signature, so rotated keys are picked up (§4.6).
/// That happens on failed signatures, forgeries included, so an
/// implementation that fetches remotely **must** rate-limit fresh lookups
/// (§8 "Outbound requests"); otherwise a stream of forged requests becomes
/// a stream of outbound fetches. It also charges fetches to `requester`.
pub trait KeyResolver: Send + Sync {
    /// Resolve `key_id` for `actor`, on behalf of `requester`.
    fn resolve<'a>(
        &'a self,
        actor: &'a Actor,
        key_id: &'a str,
        fresh: bool,
        requester: &'a Requester,
    ) -> KeyFuture<'a>;

    /// Re-confirm that `actor` still publishes `key` under `key_id`, for a
    /// live connection that has relied on it for `held` (§7.1). A resolver
    /// that fetches remotely should fetch unless a fetch completed since
    /// `held` began would answer, and charge it like an expiry re-fetch,
    /// not like a key miss.
    ///
    /// The default asks again with `fresh = true` and trusts only an
    /// answer read from the authoritative source.
    fn reconfirm<'a>(
        &'a self,
        actor: &'a Actor,
        key_id: &'a str,
        key: &'a VerifyingKey,
        _held: Lifetime,
        requester: &'a Requester,
    ) -> ReconfirmFuture<'a> {
        Box::pin(async move {
            match self.resolve(actor, key_id, true, requester).await {
                Ok(r) if r.from_cache => {
                    Reconfirmed::Unconfirmed("only a cached answer was available".to_owned())
                }
                Ok(r) => classify(r.key.as_ref(), key, r.lifetime),
                Err(e) => Reconfirmed::Unconfirmed(e.to_string()),
            }
        })
    }
}

/// A completed answer `found` for a connection holding `held_key`: the
/// very key is still published, or it is gone (absent, or the id now
/// names another key).
pub fn classify(
    found: Option<&VerifyingKey>,
    held_key: &VerifyingKey,
    lifetime: Lifetime,
) -> Reconfirmed {
    match found {
        Some(k) if k == held_key => Reconfirmed::Present(lifetime),
        _ => Reconfirmed::Gone,
    }
}

/// A fixed set of keys, for tests and for statically configured peers. Its
/// answers are authoritative: there is nothing to re-fetch.
#[derive(Debug, Default, Clone)]
pub struct StaticKeys {
    keys: Vec<(Actor, String, VerifyingKey)>,
}

impl StaticKeys {
    /// Add a key.
    #[must_use]
    pub fn with(mut self, actor: Actor, key_id: &str, key: VerifyingKey) -> Self {
        self.keys.push((actor, key_id.to_owned(), key));
        self
    }
}

impl KeyResolver for StaticKeys {
    fn resolve<'a>(
        &'a self,
        actor: &'a Actor,
        key_id: &'a str,
        _fresh: bool,
        _requester: &'a Requester,
    ) -> KeyFuture<'a> {
        let found = self
            .keys
            .iter()
            .find(|(a, k, _)| a == actor && k == key_id)
            .map(|(_, _, key)| *key);
        Box::pin(async move { Ok(Resolved::authoritative(found)) })
    }
}
