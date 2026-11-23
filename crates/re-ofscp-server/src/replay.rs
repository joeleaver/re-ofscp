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
//! 3. The store is bounded. When full it refuses (the caller answers `503`
//!    with `Retry-After`) instead of evicting an unexpired entry.
//!
//! **Restarts.** The store is in memory, so a restart forgets every nonce.
//! To stop a request captured before the restart from being replayed after
//! it, the store has a *floor*: a signature whose timestamp is earlier than
//! the moment the store was created is refused. See
//! `docs/decisions/0001-replay-store.md`.

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, PoisonError};

/// Who produced a signature. Part of the replay key (§4.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignerKind {
    /// A user's device key (§4.4).
    Actor,
    /// A provider signing key (§8.1).
    Provider,
}

/// Why a nonce was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayError {
    /// The *(kind, key id, nonce)* triple was already used, or the signature
    /// predates the store's floor.
    Replayed,
    /// The store is at capacity; retry after this many seconds.
    Full {
        /// Seconds until the oldest entry expires.
        retry_after: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Key {
    kind: SignerKind,
    key_id: Box<str>,
    nonce: Box<str>,
}

#[derive(Debug, Default)]
struct Inner {
    /// Entry → expiry (unix seconds).
    entries: HashMap<Key, i64>,
    /// Insertion order, for expiry sweeps.
    order: VecDeque<(i64, Key)>,
}

impl Inner {
    fn sweep(&mut self, now: i64) {
        while let Some((expires, _)) = self.order.front() {
            if *expires > now {
                break;
            }
            if let Some((expires, key)) = self.order.pop_front()
                && self.entries.get(&key) == Some(&expires)
            {
                self.entries.remove(&key);
            }
        }
    }
}

/// A bounded, fail-closed nonce store.
#[derive(Debug)]
pub struct ReplayStore {
    inner: Mutex<Inner>,
    capacity: usize,
    retention_secs: i64,
    floor: i64,
}

impl ReplayStore {
    /// Create a store holding at most `capacity` nonces for `retention_secs`
    /// each, refusing signatures timestamped before `floor` (unix seconds).
    ///
    /// `retention_secs` must be at least twice the clock-skew window so a
    /// nonce outlives every moment its timestamp is acceptable.
    pub fn new(capacity: usize, retention_secs: i64, floor: i64) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            capacity,
            retention_secs,
            floor,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A panic while holding the lock leaves the maps consistent (every
        // mutation is a single insert/remove), so poisoning is ignorable.
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn key(kind: SignerKind, key_id: &str, nonce: &str) -> Key {
        Key {
            kind,
            key_id: key_id.into(),
            nonce: nonce.into(),
        }
    }

    /// Step 4: has this triple been used? Does not record anything.
    pub fn check(
        &self,
        kind: SignerKind,
        key_id: &str,
        nonce: &str,
        signed_at: i64,
        now: i64,
    ) -> Result<(), ReplayError> {
        if signed_at < self.floor {
            return Err(ReplayError::Replayed);
        }
        let mut inner = self.lock();
        inner.sweep(now);
        if inner.entries.contains_key(&Self::key(kind, key_id, nonce)) {
            Err(ReplayError::Replayed)
        } else {
            Ok(())
        }
    }

    /// After the signature verified: atomically re-check and record.
    pub fn record(
        &self,
        kind: SignerKind,
        key_id: &str,
        nonce: &str,
        signed_at: i64,
        now: i64,
    ) -> Result<(), ReplayError> {
        if signed_at < self.floor {
            return Err(ReplayError::Replayed);
        }
        let key = Self::key(kind, key_id, nonce);
        let mut inner = self.lock();
        inner.sweep(now);
        if inner.entries.contains_key(&key) {
            return Err(ReplayError::Replayed);
        }
        if inner.entries.len() >= self.capacity {
            let oldest = inner.order.front().map_or(now + 1, |(e, _)| *e);
            return Err(ReplayError::Full {
                retry_after: u64::try_from(oldest - now).unwrap_or(1).max(1),
            });
        }
        let expires = now + self.retention_secs;
        inner.entries.insert(key.clone(), expires);
        inner.order.push_back((expires, key));
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
mod tests {
    use super::*;
    use SignerKind::{Actor, Provider};

    const T: i64 = 1_000_000;

    #[test]
    fn check_does_not_record() {
        let s = ReplayStore::new(10, 600, 0);
        assert_eq!(s.check(Actor, "k", "n", T, T), Ok(()));
        assert_eq!(s.check(Actor, "k", "n", T, T), Ok(()));
        assert!(s.is_empty(T));
    }

    #[test]
    fn record_then_replay_is_refused() {
        let s = ReplayStore::new(10, 600, 0);
        assert_eq!(s.record(Actor, "k", "n", T, T), Ok(()));
        assert_eq!(s.check(Actor, "k", "n", T, T), Err(ReplayError::Replayed));
        assert_eq!(s.record(Actor, "k", "n", T, T), Err(ReplayError::Replayed));
    }

    #[test]
    fn signer_kinds_do_not_collide() {
        let s = ReplayStore::new(10, 600, 0);
        assert_eq!(s.record(Actor, "k", "n", T, T), Ok(()));
        assert_eq!(s.record(Provider, "k", "n", T, T), Ok(()));
        assert_eq!(s.record(Actor, "k2", "n", T, T), Ok(()));
    }

    #[test]
    fn entries_expire_after_retention() {
        let s = ReplayStore::new(10, 600, 0);
        s.record(Actor, "k", "n", T, T).unwrap();
        assert_eq!(
            s.check(Actor, "k", "n", T, T + 599),
            Err(ReplayError::Replayed)
        );
        assert_eq!(s.check(Actor, "k", "n", T, T + 600), Ok(()));
        assert!(s.is_empty(T + 600));
    }

    #[test]
    fn full_store_fails_closed_without_evicting() {
        let s = ReplayStore::new(2, 600, 0);
        s.record(Actor, "k", "a", T, T).unwrap();
        s.record(Actor, "k", "b", T + 10, T + 10).unwrap();
        assert_eq!(
            s.record(Actor, "k", "c", T + 100, T + 100),
            Err(ReplayError::Full { retry_after: 500 })
        );
        // Nothing was evicted: both old nonces are still refused.
        assert_eq!(
            s.check(Actor, "k", "a", T, T + 100),
            Err(ReplayError::Replayed)
        );
        assert_eq!(
            s.check(Actor, "k", "b", T, T + 100),
            Err(ReplayError::Replayed)
        );
        // Once the oldest expires there is room again.
        assert_eq!(s.record(Actor, "k", "c", T + 600, T + 600), Ok(()));
    }

    #[test]
    fn floor_refuses_signatures_from_before_the_store_existed() {
        let s = ReplayStore::new(10, 600, T);
        assert_eq!(
            s.check(Actor, "k", "n", T - 1, T),
            Err(ReplayError::Replayed)
        );
        assert_eq!(
            s.record(Actor, "k", "n", T - 1, T),
            Err(ReplayError::Replayed)
        );
        assert_eq!(s.record(Actor, "k", "n", T, T), Ok(()));
    }

    #[test]
    fn concurrent_records_have_exactly_one_winner() {
        let s = std::sync::Arc::new(ReplayStore::new(100, 600, 0));
        let wins: usize = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..16)
                .map(|_| {
                    let s = s.clone();
                    scope.spawn(move || usize::from(s.record(Actor, "k", "n", T, T).is_ok()))
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).sum()
        });
        assert_eq!(wins, 1);
    }
}
