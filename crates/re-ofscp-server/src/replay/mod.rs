//! The provider-wide replay store (spec §4.5 "Replay store", §8, §7.1).
//!
//! One instance guards every surface that accepts a signature: signed REST
//! routes, provider-signed federation requests and the WebSocket
//! `authenticate` handshake. Entries are keyed by *(signer kind, key id,
//! nonce)* so actor and provider key-id spaces cannot collide.
//!
//! Protocol (§4.5):
//! 1. [`ReplayStore::check`] at step 4 only *reads*.
//! 2. [`ReplayStore::record`] runs after the signature verified; it re-checks
//!    and inserts under one lock, so of two concurrent copies exactly one wins.
//! 3. Each nonce is kept until its timestamp plus the skew window has passed,
//!    i.e. for as long as the timestamp could still be accepted.
//! 4. The store is bounded. When full it refuses (`503` + `Retry-After`)
//!    instead of evicting an unexpired entry.
//!
//! **Quotas.** A global bound alone would let one signer (or one hostile
//! remote provider minting actors) fill the store and lock everyone out. So
//! each signer, and each *remote* signer domain, may hold only a share of it;
//! past that share its own requests get `429` while everyone else carries on.
//! Local accounts are not grouped by domain (they all share ours); their
//! exposure is bounded by the per-signer cap.
//!
//! **Restarts (warm-up).** The store is in memory, so a restart forgets
//! every nonce. A request recorded just before the restart can carry a
//! timestamp up to one skew window *after* it, so the store refuses every
//! signed request timestamped at or before `T0 + skew` (`T0` = the second the
//! store began; "at" because the previous process may have run in that same
//! second), answering `503` with `Retry-After` (spec §4.5 "Restarts"). The
//! WebSocket `authenticate` handshake is exempt: its nonce is server-issued
//! for one connection and dies with it. See
//! `docs/decisions/0001-replay-store.md`.

mod quota;

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use quota::Counter;

/// Who produced a signature. Part of the replay key (§4.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SignerKind {
    /// A user's device key (§4.4).
    Actor,
    /// A provider signing key (§8.1).
    Provider,
}

/// Which kind of signature is being checked. Decides whether the restart
/// warm-up applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Surface {
    /// A signed HTTP request, user- or provider-signed (§4.4, §8.1). Its
    /// nonce is client-chosen, so the warm-up applies.
    SignedRequest,
    /// The WebSocket `authenticate` handshake (§7.1). Its nonce is a
    /// server-issued per-connection challenge that cannot outlive a restart,
    /// so the warm-up does not apply.
    WsHandshake,
}

/// One nonce use, as presented to the store.
#[derive(Debug, Clone, Copy)]
pub struct NonceUse<'a> {
    /// Actor or provider.
    pub kind: SignerKind,
    /// The signer's identity: the canonical actor or provider authority.
    pub signer: &'a str,
    /// The signer's home authority (the actor's domain, or the provider).
    pub domain: &'a str,
    /// `X-OFSCP-Key-ID`.
    pub key_id: &'a str,
    /// `X-OFSCP-Nonce`.
    pub nonce: &'a str,
    /// `X-OFSCP-Timestamp`, unix seconds.
    pub signed_at: i64,
}

/// Size limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayLimits {
    /// Live entries in total. Past this: `503`.
    pub capacity: usize,
    /// Live entries per signer. Past this: `429` for that signer.
    pub per_signer: usize,
    /// Live entries per remote signer domain. Past this: `429` for that domain.
    pub per_remote_domain: usize,
}

/// Why a nonce was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayError {
    /// The *(kind, key id, nonce)* triple was already used.
    Replayed,
    /// Still warming up after a restart (`503`).
    WarmingUp {
        /// Seconds until the warm-up ends.
        retry_after: u64,
    },
    /// The whole store is at capacity (`503`).
    Full {
        /// Seconds until the earliest entry expires.
        retry_after: u64,
    },
    /// This signer, or its remote domain, has used up its share (`429`).
    RateLimited {
        /// Seconds until one of its entries expires.
        retry_after: u64,
    },
}

/// A stored entry. Equality and hashing use only *(kind, key id, nonce)*;
/// the signer and domain are carried for quota bookkeeping.
#[derive(Debug)]
struct Entry {
    kind: SignerKind,
    key_id: Box<str>,
    nonce: Box<str>,
    signer: Arc<str>,
    /// `None` for local signers (not grouped by domain).
    remote_domain: Option<Arc<str>>,
}

impl PartialEq for Entry {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind && self.key_id == other.key_id && self.nonce == other.nonce
    }
}
impl Eq for Entry {}
impl Hash for Entry {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.kind.hash(state);
        self.key_id.hash(state);
        self.nonce.hash(state);
    }
}

#[derive(Debug, Default)]
struct Inner {
    /// Entry → expiry (unix seconds; the entry is gone once `now >= expiry`).
    entries: HashMap<Arc<Entry>, i64>,
    /// Min-heap of expiries, for sweeping.
    expiry: BinaryHeap<Reverse<(i64, ArcByAddr)>>,
    signers: HashMap<(SignerKind, Arc<str>), Counter>,
    domains: HashMap<Arc<str>, Counter>,
}

/// Heap payload: ordered by address only, so the heap never compares
/// strings (expiry ties are broken arbitrarily, which is fine).
#[derive(Debug, Clone)]
struct ArcByAddr(Arc<Entry>);
impl PartialEq for ArcByAddr {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for ArcByAddr {}
impl PartialOrd for ArcByAddr {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for ArcByAddr {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        Arc::as_ptr(&self.0).cmp(&Arc::as_ptr(&other.0))
    }
}

impl Inner {
    fn sweep(&mut self, now: i64) {
        while let Some(Reverse((expires, _))) = self.expiry.peek() {
            if *expires > now {
                break;
            }
            let Some(Reverse((expires, ArcByAddr(entry)))) = self.expiry.pop() else {
                break;
            };
            self.entries.remove(&entry);
            let signer_key = (entry.kind, entry.signer.clone());
            if self
                .signers
                .get_mut(&signer_key)
                .is_some_and(|c| c.remove(expires))
            {
                self.signers.remove(&signer_key);
            }
            if let Some(domain) = &entry.remote_domain
                && self
                    .domains
                    .get_mut(domain)
                    .is_some_and(|c| c.remove(expires))
            {
                self.domains.remove(domain);
            }
        }
    }

    fn contains(&self, u: &NonceUse<'_>) -> bool {
        self.entries.contains_key(&probe(u))
    }
}

/// A lookup key for `u` (signer/domain are irrelevant to equality).
fn probe(u: &NonceUse<'_>) -> Entry {
    Entry {
        kind: u.kind,
        key_id: u.key_id.into(),
        nonce: u.nonce.into(),
        signer: Arc::from(""),
        remote_domain: None,
    }
}

fn secs_until(at: i64, now: i64) -> u64 {
    u64::try_from(at - now).unwrap_or(1).max(1)
}

/// A bounded, fail-closed nonce store.
#[derive(Debug)]
pub struct ReplayStore {
    inner: Mutex<Inner>,
    limits: ReplayLimits,
    skew_secs: i64,
    /// `T0 + skew`: signed requests timestamped at or before it are refused.
    warm_until: i64,
    local_domain: Box<str>,
}

impl ReplayStore {
    /// Create a store for a verifier accepting timestamps within `skew_secs`
    /// of now, which began at `started_at` (unix seconds), on the provider
    /// whose canonical authority is `local_domain`.
    pub fn new(limits: ReplayLimits, skew_secs: i64, started_at: i64, local_domain: &str) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            limits,
            skew_secs,
            warm_until: started_at + skew_secs,
            local_domain: local_domain.into(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // A panic while holding the lock cannot leave a half-applied insert
        // visible to callers in a way that weakens replay protection: an
        // entry is inserted into `entries` before any bookkeeping. Recover.
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn warm_up(&self, surface: Surface, u: &NonceUse<'_>, now: i64) -> Result<(), ReplayError> {
        if surface == Surface::SignedRequest && u.signed_at <= self.warm_until {
            return Err(ReplayError::WarmingUp {
                retry_after: secs_until(self.warm_until + 1, now),
            });
        }
        Ok(())
    }

    fn is_remote(&self, u: &NonceUse<'_>) -> bool {
        *u.domain != *self.local_domain
    }

    /// The quota error, if `u`'s signer or remote domain is at its share.
    fn quota(&self, inner: &Inner, u: &NonceUse<'_>, now: i64) -> Result<(), ReplayError> {
        let signer = inner.signers.get(&(u.kind, Arc::from(u.signer)));
        if let Some(c) = signer
            && c.total() >= self.limits.per_signer
        {
            return Err(ReplayError::RateLimited {
                retry_after: secs_until(c.earliest().unwrap_or(now + 1), now),
            });
        }
        if self.is_remote(u)
            && let Some(c) = inner.domains.get(u.domain)
            && c.total() >= self.limits.per_remote_domain
        {
            return Err(ReplayError::RateLimited {
                retry_after: secs_until(c.earliest().unwrap_or(now + 1), now),
            });
        }
        Ok(())
    }

    /// Step 4: would this use be accepted? Records nothing.
    pub fn check(&self, surface: Surface, u: &NonceUse<'_>, now: i64) -> Result<(), ReplayError> {
        self.warm_up(surface, u, now)?;
        let mut inner = self.lock();
        inner.sweep(now);
        if inner.contains(u) {
            return Err(ReplayError::Replayed);
        }
        self.quota(&inner, u, now)
    }

    /// After the signature verified: atomically re-check and record.
    pub fn record(&self, surface: Surface, u: &NonceUse<'_>, now: i64) -> Result<(), ReplayError> {
        self.warm_up(surface, u, now)?;
        let mut inner = self.lock();
        inner.sweep(now);
        if inner.contains(u) {
            return Err(ReplayError::Replayed);
        }
        self.quota(&inner, u, now)?;
        if inner.entries.len() >= self.limits.capacity {
            let earliest = inner.expiry.peek().map_or(now + 1, |Reverse((e, _))| *e);
            return Err(ReplayError::Full {
                retry_after: secs_until(earliest, now),
            });
        }
        // Accepted while `now <= signed_at + skew`, so gone at the second after.
        // Never earlier than one second from now (a timestamp in the past).
        let expires = (u.signed_at + self.skew_secs + 1).max(now + 1);
        let signer: Arc<str> = Arc::from(u.signer);
        let remote_domain = self.is_remote(u).then(|| Arc::<str>::from(u.domain));
        let entry = Arc::new(Entry {
            kind: u.kind,
            key_id: u.key_id.into(),
            nonce: u.nonce.into(),
            signer: signer.clone(),
            remote_domain: remote_domain.clone(),
        });
        inner.entries.insert(entry.clone(), expires);
        inner.expiry.push(Reverse((expires, ArcByAddr(entry))));
        inner
            .signers
            .entry((u.kind, signer))
            .or_default()
            .add(expires);
        if let Some(domain) = remote_domain {
            inner.domains.entry(domain).or_default().add(expires);
        }
        Ok(())
    }

    /// Number of live entries (for metrics and tests).
    pub fn len(&self, now: i64) -> usize {
        let mut inner = self.lock();
        inner.sweep(now);
        inner.entries.len()
    }

    /// Whether the store holds no live entries.
    pub fn is_empty(&self, now: i64) -> bool {
        self.len(now) == 0
    }
}

#[cfg(test)]
mod tests;
