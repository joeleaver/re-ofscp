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
//! **Pools and quotas.** A single global bound would let one signer, or one
//! hostile provider, fill the store and lock everyone out. So:
//! * local signers (actors of this provider) and remote signers fill two
//!   separate pools, each bounded; a full pool gets `503` for that side only,
//!   so remote traffic can never lock out local users or vice versa;
//! * each signer may hold at most `per_signer` live nonces (`429` past it);
//! * remote signers are also grouped by *registrable domain* (Public Suffix
//!   List, port ignored), each group holding at most `per_remote_domain`
//!   (`429` past it), so `a.evil.example`, `b.evil.example:8443`, … share one
//!   quota. Filling the remote pool takes many separately registered domains.
//!
//! Local-pool exhaustion needs many local accounts; account creation is rate
//! limited where accounts are created.
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

pub mod ledger;
mod quota;

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

pub use ledger::{LedgerError, NoLedger, NonceLedger, StoredNonce};
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

/// What [`ReplayStore::record`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Recorded {
    /// When the entry expires (unix seconds).
    pub expires: i64,
    /// The store clock the use was judged by (never behind any earlier
    /// decision). The ledger compares expiries against this, not a raw
    /// wall-clock reading.
    pub clock: i64,
}

/// Size limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayLimits {
    /// Live entries from local signers. Past this: `503` for local signers.
    pub local_total: usize,
    /// Live entries from remote signers. Past this: `503` for remote signers.
    pub remote_total: usize,
    /// Live entries per signer. Past this: `429` for that signer.
    pub per_signer: usize,
    /// Live entries per remote registrable domain. Past this: `429` for it.
    pub per_remote_domain: usize,
}

/// Why a nonce was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayError {
    /// The *(kind, key id, nonce)* triple was already used.
    Replayed,
    /// The timestamp is no longer acceptable on the store's clock (it expired
    /// while the request was in flight, or another thread has already seen a
    /// later second).
    Expired,
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
    /// The registrable-domain group of a remote signer; `None` if local.
    remote_group: Option<Arc<str>>,
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
    groups: HashMap<Arc<str>, Counter>,
    local: Counter,
    remote: Counter,
    /// The latest "now" the store has been given. Every decision uses
    /// `max(now, high_water)`, so the store's clock never runs backwards:
    /// a caller holding an older reading (it read the clock, then waited for
    /// the lock) or a wall clock stepped back by NTP cannot sweep less than a
    /// previous caller already swept and so miss an entry that is gone
    /// (§4.5 "Restarts": expiry is measured on one clock).
    high_water: i64,
    /// Whether a clock regression is currently being reported (so the
    /// warning is logged once per episode, not once per request).
    regressed: bool,
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
    /// Move the store's clock to `max(now, high_water)`, sweep, and return it.
    fn advance(&mut self, now: i64) -> i64 {
        // A reading well behind the high-water mark means the wall clock was
        // stepped back (or had jumped forward and was corrected). Until real
        // time catches up, timestamps valid on the corrected clock are
        // refused as expired, which fails closed but needs an operator's eye.
        let lag = self.high_water - now;
        if lag > CLOCK_REGRESSION_ALERT_SECS && !self.regressed {
            self.regressed = true;
            tracing::warn!(
                lag_secs = lag,
                "server clock is behind the replay store's clock; signed requests \
                 timestamped before the store's clock minus the skew are refused \
                 until real time catches up"
            );
        } else if lag <= 0 && self.regressed {
            self.regressed = false;
            tracing::info!("server clock has caught up with the replay store's clock");
        }
        self.high_water = self.high_water.max(now);
        let now = self.high_water;
        self.sweep(now);
        now
    }

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
            match &entry.remote_group {
                Some(group) => {
                    self.remote.remove(expires);
                    if self
                        .groups
                        .get_mut(group)
                        .is_some_and(|c| c.remove(expires))
                    {
                        self.groups.remove(group);
                    }
                }
                None => {
                    self.local.remove(expires);
                }
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
        remote_group: None,
    }
}

/// The quota group of a remote authority: its registrable domain (eTLD+1 by
/// the Public Suffix List), port ignored. IP literals, and hosts without a
/// registrable domain (`localhost`, a bare public suffix), group by host.
pub fn registrable_group(authority: &str) -> String {
    let host = authority
        .rsplit_once(':')
        .map_or(authority, |(host, _port)| host);
    // The PSL would read `10.0.0.1` as a name under the suffix `1`.
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        return host.to_owned();
    }
    psl::domain_str(host).unwrap_or(host).to_owned()
}

/// How far behind the replay store's clock a reading may fall before it is
/// reported as a clock regression.
const CLOCK_REGRESSION_ALERT_SECS: i64 = 5;

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
    /// `i64::MIN` once the warm-up has ended (nonces restored from the
    /// persistent ledger, see [`ReplayStore::end_warm_up`]).
    warm_until: AtomicI64,
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
            warm_until: AtomicI64::new(started_at + skew_secs),
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
        let warm_until = self.warm_until.load(Ordering::SeqCst);
        if surface == Surface::SignedRequest && u.signed_at <= warm_until {
            return Err(ReplayError::WarmingUp {
                retry_after: secs_until(warm_until.saturating_add(1), now),
            });
        }
        Ok(())
    }

    /// End the restart warm-up. Call only once every nonce the previous
    /// process could have accepted is back in the store (restored from the
    /// persistent ledger), so nothing can be replayed across the restart.
    pub fn end_warm_up(&self) {
        self.warm_until.store(i64::MIN, Ordering::SeqCst);
    }

    /// Advance the store's clock to at least `now` and return it: the
    /// never-decreasing "now" every decision uses (see `Inner::high_water`).
    /// The ledger purges by this clock, and persists it.
    pub fn clock(&self, now: i64) -> i64 {
        self.lock().advance(now)
    }

    /// Raise the store's clock to at least `t` (the clock a previous process
    /// persisted), so a nonce it already purged as expired stays expired here
    /// even if this process's wall clock reads earlier.
    pub fn raise_clock(&self, t: i64) {
        self.lock().advance(t);
    }

    /// Whether the restart warm-up is still in force.
    pub fn warming_up(&self) -> bool {
        self.warm_until.load(Ordering::SeqCst) != i64::MIN
    }

    /// Load nonces recorded before a restart. Entries already expired at
    /// `now`, or already present, are skipped; limits are not applied (each
    /// was admitted when first recorded). Returns how many were restored.
    pub fn restore(&self, nonces: impl IntoIterator<Item = StoredNonce>, now: i64) -> usize {
        let mut inner = self.lock();
        let now = inner.advance(now);
        let mut restored = 0;
        for n in nonces {
            let u = n.as_use();
            if n.expires <= now || inner.contains(&u) {
                continue;
            }
            self.insert(&mut inner, &u, n.expires);
            restored += 1;
        }
        restored
    }

    fn is_remote(&self, u: &NonceUse<'_>) -> bool {
        *u.domain != *self.local_domain
    }

    /// Refuse if `u`'s signer or remote group is over its share (`429`) or
    /// its pool is full (`503`). `Retry-After` is the latest of the earliest
    /// expiries among everything that refused, so retrying then can succeed.
    fn admit(&self, inner: &Inner, u: &NonceUse<'_>, now: i64) -> Result<(), ReplayError> {
        let mut quota_retry: Option<i64> = None;
        let mut over = |c: &Counter| {
            let at = c.earliest().unwrap_or(now + 1);
            quota_retry = Some(quota_retry.map_or(at, |r| r.max(at)));
        };
        if let Some(c) = inner.signers.get(&(u.kind, Arc::from(u.signer)))
            && c.total() >= self.limits.per_signer
        {
            over(c);
        }
        let remote = self.is_remote(u);
        if remote
            && let Some(c) = inner.groups.get(registrable_group(u.domain).as_str())
            && c.total() >= self.limits.per_remote_domain
        {
            over(c);
        }
        if let Some(at) = quota_retry {
            return Err(ReplayError::RateLimited {
                retry_after: secs_until(at, now),
            });
        }
        let (pool, cap) = if remote {
            (&inner.remote, self.limits.remote_total)
        } else {
            (&inner.local, self.limits.local_total)
        };
        if pool.total() >= cap {
            return Err(ReplayError::Full {
                retry_after: secs_until(pool.earliest().unwrap_or(now + 1), now),
            });
        }
        Ok(())
    }

    /// Whether `u`'s timestamp is still acceptable at the store's `now`.
    fn fresh(&self, u: &NonceUse<'_>, now: i64) -> Result<(), ReplayError> {
        if u.signed_at + self.skew_secs < now {
            Err(ReplayError::Expired)
        } else {
            Ok(())
        }
    }

    /// Step 4: would this use be accepted? Records nothing.
    pub fn check(&self, surface: Surface, u: &NonceUse<'_>, now: i64) -> Result<(), ReplayError> {
        self.warm_up(surface, u, now)?;
        let mut inner = self.lock();
        let now = inner.advance(now);
        self.fresh(u, now)?;
        if inner.contains(u) {
            return Err(ReplayError::Replayed);
        }
        self.admit(&inner, u, now)
    }

    /// After the signature verified: atomically re-check freshness and
    /// replay, and record. Pass a fresh clock reading; the store also never
    /// lets its clock run backwards (see `Inner::high_water`). Returns the
    /// entry's expiry and the store clock it was judged by, for the ledger.
    pub fn record(
        &self,
        surface: Surface,
        u: &NonceUse<'_>,
        now: i64,
    ) -> Result<Recorded, ReplayError> {
        self.warm_up(surface, u, now)?;
        let mut inner = self.lock();
        let now = inner.advance(now);
        self.fresh(u, now)?;
        if inner.contains(u) {
            return Err(ReplayError::Replayed);
        }
        self.admit(&inner, u, now)?;
        // Accepted while `now <= signed_at + skew` (checked just above), so
        // gone at the second after; that is always later than `now`.
        let expires = u.signed_at + self.skew_secs + 1;
        self.insert(&mut inner, u, expires);
        Ok(Recorded {
            expires,
            clock: now,
        })
    }

    /// Insert `u` expiring at `expires`, with all bookkeeping.
    fn insert(&self, inner: &mut Inner, u: &NonceUse<'_>, expires: i64) {
        let signer: Arc<str> = Arc::from(u.signer);
        let remote_group = self
            .is_remote(u)
            .then(|| Arc::<str>::from(registrable_group(u.domain)));
        let entry = Arc::new(Entry {
            kind: u.kind,
            key_id: u.key_id.into(),
            nonce: u.nonce.into(),
            signer: signer.clone(),
            remote_group: remote_group.clone(),
        });
        inner.entries.insert(entry.clone(), expires);
        inner.expiry.push(Reverse((expires, ArcByAddr(entry))));
        inner
            .signers
            .entry((u.kind, signer))
            .or_default()
            .add(expires);
        match remote_group {
            Some(group) => {
                inner.remote.add(expires);
                inner.groups.entry(group).or_default().add(expires);
            }
            None => inner.local.add(expires),
        }
    }

    /// Number of live entries (for metrics and tests).
    pub fn len(&self, now: i64) -> usize {
        let mut inner = self.lock();
        inner.advance(now);
        inner.entries.len()
    }

    /// Whether the store holds no live entries.
    pub fn is_empty(&self, now: i64) -> bool {
        self.len(now) == 0
    }
}

#[cfg(test)]
mod tests;
