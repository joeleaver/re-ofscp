//! The resolver's bounded tables: cached documents, fetches in flight,
//! when each source was last re-fetched on a miss, and which sources are
//! known (their last completed fetch found keys).
//!
//! The cached documents and the known sources are bounded per target group
//! as well as overall ([`Grouped`]), so that a provider serving keys for
//! any handle cannot push other domains' entries out (docs/decisions/0006).

use std::collections::HashMap;
use std::sync::Arc;

use ed25519_dalek::VerifyingKey;
use tokio::sync::watch;

use super::document::KeySet;
use super::fetch::{Fetched, Source};
use super::grouped::Grouped;
use super::known::{KnownSources, MAX_KNOWN_PER_GROUP};

/// Most entries in each table.
pub const MAX_ENTRIES: usize = 10_000;
/// Most cached documents of one target group: as many as it may have known
/// sources.
pub const MAX_CACHED_PER_GROUP: usize = MAX_KNOWN_PER_GROUP;
/// Most cached documents in all.
pub const MAX_CACHED: usize = MAX_ENTRIES;
/// At most one failure-driven re-fetch per source this often (§4.6 allows
/// "one per minute").
pub const REFETCH_INTERVAL_SECS: i64 = 60;

/// A fetch in flight.
#[derive(Debug, Clone)]
pub struct Flight {
    /// Its answer, once it completes.
    pub answer: watch::Receiver<Option<Fetched>>,
    /// Whether it is a `fresh` re-fetch, which started the source's
    /// re-fetch interval.
    pub refetch: bool,
}

/// The tables, kept under one lock.
pub struct Tables {
    /// Cached documents, each usable while `now < expires` (unix seconds),
    /// bounded per target group and overall.
    cache: Grouped<Arc<KeySet>>,
    /// Fetches in flight, so concurrent lookups share one.
    pub flights: HashMap<Source, Flight>,
    /// When each source was last re-fetched for a `fresh` lookup.
    refetched: HashMap<Source, i64>,
    /// Known sources: those whose last completed fetch returned a
    /// non-empty key list. Their expiry re-fetches are charged to the
    /// targets' known budgets (docs/decisions/0006).
    known: KnownSources,
}

impl Default for Tables {
    fn default() -> Self {
        Self::with_cache_caps(MAX_CACHED_PER_GROUP, MAX_CACHED)
    }
}

impl Tables {
    /// Tables whose cache holds at most `per_group` documents of one target
    /// group and `total` in all.
    pub fn with_cache_caps(per_group: usize, total: usize) -> Self {
        Self {
            cache: Grouped::with_caps(per_group, total),
            flights: HashMap::new(),
            refetched: HashMap::new(),
            known: KnownSources::default(),
        }
    }

    /// `source`'s keys, if its cache entry has not expired at `now`.
    pub fn live(&self, source: &Source, now: i64) -> Option<&Arc<KeySet>> {
        match self.cache.get(source) {
            Some((keys, Some(expires))) if now < expires => Some(keys),
            _ => None,
        }
    }

    /// The key `key_id` of `source` from an entry still unexpired at `now`.
    /// Only such a key may stand in for a fetch that failed, was refused or
    /// was rate-limited: an expired entry never counts (lost-conn/ofscp#20),
    /// so a revoked key cannot outlive its cache because fetches keep
    /// failing.
    pub fn cached_key(&self, source: &Source, key_id: &str, now: i64) -> Option<VerifyingKey> {
        self.live(source, now)
            .and_then(|keys| keys.get(key_id).copied())
    }

    /// Record a completed fetch. Cacheable until `expires`, or (for
    /// `None`) not at all, which also drops what was cached before: it is
    /// superseded. Making room drops an expired entry or the oldest of a
    /// group at or over its share ([`Grouped`]); it never touches a fetch
    /// in flight, which lookups keep joining whatever the cache holds.
    pub fn store(&mut self, source: &Source, keys: Arc<KeySet>, expires: Option<i64>, now: i64) {
        let Some(expires) = expires.filter(|&t| t > now) else {
            self.cache.remove(source);
            return;
        };
        self.cache.insert(source, keys, Some(expires), now);
    }

    /// Seconds until `source` may be re-fetched for a `fresh` lookup, or
    /// `None` if it may be now.
    pub fn refetch_wait(&self, source: &Source, now: i64) -> Option<u64> {
        let last = *self.refetched.get(source)?;
        let wait = last + REFETCH_INTERVAL_SECS - now;
        (wait > 0).then(|| wait.unsigned_abs())
    }

    /// Whether `source` is known: its last completed fetch found keys.
    pub fn is_known(&self, source: &Source) -> bool {
        self.known.contains(source)
    }

    /// Record the outcome of a completed fetch of `source` at `now`: it
    /// found keys (`found`), so `source` is known, or an empty list or
    /// `404`, so it is not (any more). Failures and refusals say nothing
    /// about the source and are not recorded. The table is bounded per
    /// target group and overall ([`KnownSources`]); a source it forgets is
    /// charged as a first-time lookup until a fetch finds its keys again.
    pub fn note_found(&mut self, source: &Source, found: bool, now: i64) {
        if found {
            self.known.confirm(source, now);
        } else {
            self.known.forget(source);
        }
    }

    /// Note a `fresh` re-fetch of `source` at `now`.
    pub fn note_refetch(&mut self, source: &Source, now: i64) {
        make_room(
            &mut self.refetched,
            source,
            |&at| at + REFETCH_INTERVAL_SECS <= now,
            |&at| at,
        );
        self.refetched.insert(source.clone(), now);
    }
}

/// Make room for `key` in `map`: past [`MAX_ENTRIES`], drop expired
/// entries, then the oldest.
fn make_room<V>(
    map: &mut HashMap<Source, V>,
    key: &Source,
    expired: impl Fn(&V) -> bool,
    age: impl Fn(&V) -> i64,
) {
    if map.contains_key(key) || map.len() < MAX_ENTRIES {
        return;
    }
    map.retain(|_, v| !expired(v));
    if map.len() >= MAX_ENTRIES
        && let Some(oldest) = map
            .iter()
            .min_by_key(|(_, v)| age(v))
            .map(|(k, _)| k.clone())
    {
        map.remove(&oldest);
    }
}

#[cfg(test)]
mod tests {
    use re_ofscp_types::Authority;

    use super::*;

    fn source(i: usize) -> Source {
        Source::Provider(Authority::parse_canonical(&format!("p{i}.example")).unwrap())
    }

    #[test]
    fn entries_expire_and_uncacheable_results_drop_the_old_entry() {
        let mut t = Tables::default();
        let s = source(0);
        t.store(&s, Arc::new(KeySet::new()), Some(110), 100);
        assert!(t.live(&s, 109).is_some());
        assert!(t.live(&s, 110).is_none(), "expired at its expiry");
        t.store(&s, Arc::new(KeySet::new()), None, 105);
        assert!(
            t.live(&s, 106).is_none(),
            "superseded by an uncacheable answer"
        );
        t.store(&s, Arc::new(KeySet::new()), Some(105), 105);
        assert!(t.live(&s, 105).is_none(), "already expired: not stored");
    }

    #[test]
    fn refetch_waits_a_minute() {
        let mut t = Tables::default();
        let s = source(0);
        assert_eq!(t.refetch_wait(&s, 100), None);
        t.note_refetch(&s, 100);
        assert_eq!(t.refetch_wait(&s, 100), Some(60));
        assert_eq!(t.refetch_wait(&s, 159), Some(1));
        assert_eq!(t.refetch_wait(&s, 160), None);
    }

    #[test]
    fn sources_are_known_while_their_last_fetch_found_keys() {
        let mut t = Tables::default();
        let s = source(0);
        assert!(!t.is_known(&s));
        t.note_found(&s, true, 100);
        assert!(t.is_known(&s));
        t.note_found(&s, false, 200);
        assert!(!t.is_known(&s), "an empty list or 404 forgets it");
    }

    #[test]
    fn the_cache_is_bounded_dropping_expired_then_the_largest_groups_oldest() {
        let mut t = Tables::with_cache_caps(3, 4);
        let keys = || Arc::new(KeySet::new());
        let sub = Source::Provider(Authority::parse_canonical("a.p1.example").unwrap());
        // p0 expires at 50; p1.example holds two entries. The table is full.
        t.store(&source(0), keys(), Some(50), 0);
        t.store(&source(1), keys(), Some(1000), 1);
        t.store(&sub, keys(), Some(1000), 2);
        t.store(&source(2), keys(), Some(1000), 3);
        // An expired entry goes first, whatever its group.
        t.store(&source(3), keys(), Some(1000), 60);
        assert!(t.cache.get(&source(0)).is_none(), "expired entry dropped");
        assert!(t.live(&source(1), 60).is_some());
        // Then the oldest entry of the largest group.
        t.store(&source(4), keys(), Some(1000), 61);
        assert!(t.cache.get(&source(1)).is_none(), "p1.example was cut back");
        for s in [&sub, &source(2), &source(3), &source(4)] {
            assert!(t.live(s, 62).is_some(), "{s:?}");
        }
        t.cache.assert_consistent();
    }

    #[test]
    fn the_refetch_table_is_bounded_dropping_expired_then_oldest() {
        let mut t = Tables::default();
        // Re-fetch times: entry 0 is the oldest, none has lapsed yet.
        for i in 0..MAX_ENTRIES {
            t.note_refetch(&source(i), if i == 0 { 990 } else { 1000 });
        }
        t.note_refetch(&source(MAX_ENTRIES), 1000);
        assert_eq!(t.refetched.len(), MAX_ENTRIES);
        assert!(!t.refetched.contains_key(&source(0)), "oldest dropped");
        // Once they lapse, they all go to make room.
        t.note_refetch(&source(MAX_ENTRIES + 1), 1060);
        assert_eq!(t.refetched.len(), 1);
    }
}
