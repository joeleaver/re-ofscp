//! Key resolution for the verifier (spec §4.5 step 6, §4.6, §8.1).
//!
//! A [`KeyResolver`] finds the active public key a signer uses under a key
//! id, and says whether its answer came from a cache. The verifier needs
//! that to apply the §4.6 re-fetch rule (lost-conn/ofscp#19): when a cached
//! answer has no matching key, or the key does not verify the signature, it
//! asks again with `fresh = true`; an answer that was fetched for this
//! request is final.

use std::future::Future;
use std::pin::Pin;

use ed25519_dalek::VerifyingKey;

use super::verify::Signer;

/// What a resolver found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resolved {
    /// The active key with that id, or `None` for "no such active key".
    pub key: Option<VerifyingKey>,
    /// Whether the answer came from a cache rather than from the
    /// authoritative source read for this lookup. A cached answer that
    /// fails verification is worth re-checking with `fresh = true`.
    pub from_cache: bool,
}

impl Resolved {
    /// An answer read from a cache.
    pub fn cached(key: Option<VerifyingKey>) -> Self {
        Self {
            key,
            from_cache: true,
        }
    }

    /// An answer read from the authoritative source for this lookup.
    pub fn authoritative(key: Option<VerifyingKey>) -> Self {
        Self {
            key,
            from_cache: false,
        }
    }
}

/// A failure to resolve keys.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
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

/// Finds the active (non-revoked) public key a signer uses under a key id.
///
/// `fresh = false` may answer from cache. The verifier calls again with
/// `fresh = true` only when a *cached* answer had no such key or its key
/// did not verify the signature, so rotated keys are picked up (§4.6,
/// §8.1). That happens on failed signatures, forgeries included, so an
/// implementation that fetches remotely **must** rate-limit fresh lookups
/// (§8 "Outbound requests"); otherwise a stream of forged requests becomes
/// a stream of outbound fetches. It also charges fetches to `requester`.
pub trait KeyResolver: Send + Sync {
    /// Resolve `key_id` for `signer`, on behalf of `requester`.
    fn resolve<'a>(
        &'a self,
        signer: &'a Signer,
        key_id: &'a str,
        fresh: bool,
        requester: &'a Requester,
    ) -> KeyFuture<'a>;
}

/// A fixed set of keys, for tests and for statically configured peers. Its
/// answers are authoritative: there is nothing to re-fetch.
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
    fn resolve<'a>(
        &'a self,
        signer: &'a Signer,
        key_id: &'a str,
        _fresh: bool,
        _requester: &'a Requester,
    ) -> KeyFuture<'a> {
        let found = self
            .keys
            .iter()
            .find(|(s, k, _)| s == signer && k == key_id)
            .map(|(_, _, key)| *key);
        Box::pin(async move { Ok(Resolved::authoritative(found)) })
    }
}
