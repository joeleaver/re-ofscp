//! Resolving signing keys (spec §4.5 step 6, §4.6).
//!
//! [`ProviderKeys`] answers for actors of this provider from the account
//! store, and hands remote actors and remote providers to a remote resolver
//! (`crate::remote_keys`, docs/decisions/0006). A provider signature naming
//! this provider itself is never fetched (that would only fetch our own
//! discovery document): it is checked against the provider signing keys
//! this provider publishes (§8.1, docs/decisions/0007), held in memory.
//!
//! Local keys are cached briefly (positive results only). Revoking a key or
//! disabling an account invalidates the cache at once, in this process; a
//! `fresh` lookup (the verifier's retry after a failure) always reads the
//! store.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use ed25519_dalek::VerifyingKey;
use re_ofscp_types::Authority;

use super::store::AccountStore;
use crate::signing::canonical::decode_public_key;
use crate::signing::{
    KeyError, KeyFuture, KeyResolver, Lifetime, ReconfirmFuture, Reconfirmed, Requester, Resolved,
    Signer, classify,
};

/// How long a resolved local key is cached.
const CACHE_TTL: Duration = Duration::from_secs(60);
/// Most cached keys; past this the cache is cleared and refilled on demand.
const CACHE_MAX: usize = 10_000;
/// `Retry-After` when the account store cannot be read.
const STORE_RETRY_SECS: u64 = 2;

/// The account store could not be read: `503`, retry shortly.
fn store_unavailable(reason: String) -> KeyError {
    KeyError::Unavailable {
        reason,
        retry_after: STORE_RETRY_SECS,
    }
}

type CacheKey = (String, String);

/// The key cache and its invalidation epoch, under one lock.
///
/// A lookup notes the epoch before reading the store and inserts its result
/// only if the epoch is unchanged. Every invalidation bumps the epoch, so a
/// lookup that read a key just before it was revoked can never put it back
/// into the cache after the invalidation cleared it.
#[derive(Default)]
struct Cache {
    entries: HashMap<CacheKey, (VerifyingKey, Instant)>,
    epoch: u64,
}

/// Local keys from the account store; everything else from `remote`.
pub struct ProviderKeys {
    local: Authority,
    /// This provider's own published signing keys, by key id (§8.1).
    own: Vec<(String, VerifyingKey)>,
    store: AccountStore,
    remote: Arc<dyn KeyResolver>,
    cache: Mutex<Cache>,
}

impl std::fmt::Debug for ProviderKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderKeys")
            .field("local", &self.local)
            .finish_non_exhaustive()
    }
}

impl ProviderKeys {
    /// Resolve `local`'s actors from `store`, `local` itself from `own`
    /// (its published provider keys, by id), others via `remote`.
    pub fn new(
        local: Authority,
        own: Vec<(String, VerifyingKey)>,
        store: AccountStore,
        remote: Arc<dyn KeyResolver>,
    ) -> Self {
        Self {
            local,
            own,
            store,
            remote,
            cache: Mutex::new(Cache::default()),
        }
    }

    fn cache(&self) -> std::sync::MutexGuard<'_, Cache> {
        self.cache.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Forget cached keys of `handle` (a key revoked, the account disabled),
    /// and stop any lookup already in flight from caching what it read.
    pub fn invalidate(&self, handle: &str) {
        let mut cache = self.cache();
        cache.epoch = cache.epoch.wrapping_add(1);
        cache.entries.retain(|(h, _), _| h != handle);
    }

    async fn resolve_local(
        &self,
        handle: &str,
        key_id: &str,
        fresh: bool,
    ) -> Result<Resolved, KeyError> {
        let cache_key = (handle.to_owned(), key_id.to_owned());
        let epoch = {
            let cache = self.cache();
            if !fresh
                && let Some((key, at)) = cache.entries.get(&cache_key)
                && at.elapsed() < CACHE_TTL
            {
                return Ok(Resolved::cached(Some(*key)));
            }
            cache.epoch
        };
        let user = self
            .store
            .find_user(handle)
            .await
            .map_err(|e| store_unavailable(e.to_string()))?;
        if !user.is_some_and(|u| u.is_active()) {
            return Ok(Resolved::authoritative(None));
        }
        let Some(stored) = self
            .store
            .active_key(handle, key_id)
            .await
            .map_err(|e| store_unavailable(e.to_string()))?
        else {
            return Ok(Resolved::authoritative(None));
        };
        let key = decode_public_key(&stored.public_key)
            .map_err(|e| store_unavailable(format!("stored key {key_id} is unusable: {e}")))?;
        let mut cache = self.cache();
        // Invalidated since we read the store: return what we read for this
        // one request (it was valid when read), but never cache it.
        if cache.epoch == epoch {
            if cache.entries.len() >= CACHE_MAX {
                cache.entries.clear();
            }
            cache.entries.insert(cache_key, (key, Instant::now()));
        }
        Ok(Resolved::authoritative(Some(key)))
    }
}

impl KeyResolver for ProviderKeys {
    fn resolve<'a>(
        &'a self,
        signer: &'a Signer,
        key_id: &'a str,
        fresh: bool,
        requester: &'a Requester,
    ) -> KeyFuture<'a> {
        Box::pin(async move {
            match signer {
                Signer::Actor(actor) if actor.is_local_to(&self.local) => {
                    self.resolve_local(actor.handle(), key_id, fresh).await
                }
                Signer::Provider(authority) if *authority == self.local => {
                    Ok(Resolved::authoritative(
                        self.own
                            .iter()
                            .find(|(id, _)| id == key_id)
                            .map(|(_, key)| *key),
                    ))
                }
                _ => self.remote.resolve(signer, key_id, fresh, requester).await,
            }
        })
    }

    fn reconfirm<'a>(
        &'a self,
        signer: &'a Signer,
        key_id: &'a str,
        key: &'a VerifyingKey,
        held: Lifetime,
        requester: &'a Requester,
    ) -> ReconfirmFuture<'a> {
        Box::pin(async move {
            let ours = match signer {
                Signer::Actor(actor) => actor.is_local_to(&self.local),
                Signer::Provider(authority) => *authority == self.local,
            };
            if ours {
                match self.resolve(signer, key_id, true, requester).await {
                    Ok(r) => classify(r.key.as_ref(), key, r.lifetime),
                    Err(e) => Reconfirmed::Unconfirmed(e.to_string()),
                }
            } else {
                self.remote
                    .reconfirm(signer, key_id, key, held, requester)
                    .await
            }
        })
    }
}
