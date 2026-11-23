//! Resolving signing keys (spec §4.5 step 6, §4.6).
//!
//! [`ProviderKeys`] answers for actors of this provider from the account
//! store, and hands everything else (remote actors, provider signatures) to
//! a remote resolver. Remote fetching, with the outbound-request rules of
//! §8, is a separate component; until it lands, [`NoRemoteKeys`] refuses
//! every remote signer.
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
use crate::signing::{KeyError, KeyFuture, KeyResolver, Signer};

/// How long a resolved local key is cached.
const CACHE_TTL: Duration = Duration::from_secs(60);
/// Most cached keys; past this the cache is cleared and refilled on demand.
const CACHE_MAX: usize = 10_000;

/// Refuses every signer: no remote resolution is configured yet.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoRemoteKeys;

impl KeyResolver for NoRemoteKeys {
    fn resolve<'a>(&'a self, _signer: &'a Signer, _key_id: &'a str, _fresh: bool) -> KeyFuture<'a> {
        Box::pin(async { Ok(None) })
    }
}

type CacheKey = (String, String);

/// Local keys from the account store; everything else from `remote`.
pub struct ProviderKeys {
    local: Authority,
    store: AccountStore,
    remote: Arc<dyn KeyResolver>,
    cache: Mutex<HashMap<CacheKey, (VerifyingKey, Instant)>>,
}

impl std::fmt::Debug for ProviderKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderKeys")
            .field("local", &self.local)
            .finish_non_exhaustive()
    }
}

impl ProviderKeys {
    /// Resolve `local`'s actors from `store`, others via `remote`.
    pub fn new(local: Authority, store: AccountStore, remote: Arc<dyn KeyResolver>) -> Self {
        Self {
            local,
            store,
            remote,
            cache: Mutex::new(HashMap::new()),
        }
    }

    fn cache(&self) -> std::sync::MutexGuard<'_, HashMap<CacheKey, (VerifyingKey, Instant)>> {
        self.cache.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Forget cached keys of `handle` (a key revoked, the account disabled).
    pub fn invalidate(&self, handle: &str) {
        self.cache().retain(|(h, _), _| h != handle);
    }

    async fn resolve_local(
        &self,
        handle: &str,
        key_id: &str,
        fresh: bool,
    ) -> Result<Option<VerifyingKey>, KeyError> {
        let cache_key = (handle.to_owned(), key_id.to_owned());
        if !fresh
            && let Some((key, at)) = self.cache().get(&cache_key)
            && at.elapsed() < CACHE_TTL
        {
            return Ok(Some(*key));
        }
        let user = self
            .store
            .find_user(handle)
            .await
            .map_err(|e| KeyError(e.to_string()))?;
        if !user.is_some_and(|u| u.is_active()) {
            return Ok(None);
        }
        let Some(stored) = self
            .store
            .active_key(handle, key_id)
            .await
            .map_err(|e| KeyError(e.to_string()))?
        else {
            return Ok(None);
        };
        let Some(key) = decode_public_key(&stored.public_key) else {
            return Err(KeyError(format!(
                "stored key {key_id} is not a valid Ed25519 key"
            )));
        };
        let mut cache = self.cache();
        if cache.len() >= CACHE_MAX {
            cache.clear();
        }
        cache.insert(cache_key, (key, Instant::now()));
        Ok(Some(key))
    }
}

impl KeyResolver for ProviderKeys {
    fn resolve<'a>(&'a self, signer: &'a Signer, key_id: &'a str, fresh: bool) -> KeyFuture<'a> {
        Box::pin(async move {
            match signer {
                Signer::Actor(actor) if actor.is_local_to(&self.local) => {
                    self.resolve_local(actor.handle(), key_id, fresh).await
                }
                _ => self.remote.resolve(signer, key_id, fresh).await,
            }
        })
    }
}
