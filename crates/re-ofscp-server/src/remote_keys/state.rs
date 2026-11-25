//! The resolver's bounded tables: cached documents, fetches in flight,
//! when each source was last re-fetched on a miss, and which sources are
//! known (their last completed fetch found keys).

use std::collections::HashMap;
use std::sync::Arc;

use ed25519_dalek::VerifyingKey;
use tokio::sync::watch;

use super::document::KeySet;
use super::fetch::{Fetched, Source};

/// Most entries in each table.
pub const MAX_ENTRIES: usize = 10_000;
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

/// A cached document.
struct Entry {
    keys: Arc<KeySet>,
    /// Usable while `now < expires` (unix seconds).
    expires: i64,
    stored: i64,
}

/// The tables, kept under one lock.
#[derive(Default)]
pub struct Tables {
    cache: HashMap<Source, Entry>,
    /// Fetches in flight, so concurrent lookups share one.
    pub flights: HashMap<Source, Flight>,
    /// When each source was last re-fetched for a `fresh` lookup.
    refetched: HashMap<Source, i64>,
    /// Known sources: those whose last completed fetch returned a
    /// non-empty key list, with when that fetch completed. Their fetches
    /// are charged to the targets' known budgets (docs/decisions/0006).
    known: HashMap<Source, i64>,
}

impl Tables {
    /// `source`'s keys, if its cache entry has not expired at `now`.
    pub fn live(&self, source: &Source, now: i64) -> Option<&Arc<KeySet>> {
        self.cache
            .get(source)
            .filter(|e| now < e.expires)
            .map(|e| &e.keys)
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
    /// superseded.
    pub fn store(&mut self, source: &Source, keys: Arc<KeySet>, expires: Option<i64>, now: i64) {
        let Some(expires) = expires.filter(|&t| t > now) else {
            self.cache.remove(source);
            return;
        };
        make_room(&mut self.cache, source, |e| e.expires <= now, |e| e.stored);
        self.cache.insert(
            source.clone(),
            Entry {
                keys,
                expires,
                stored: now,
            },
        );
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
        self.known.contains_key(source)
    }

    /// Record the outcome of a completed fetch of `source` at `now`: it
    /// found keys (`found`), so `source` is known, or an empty list or
    /// `404`, so it is not (any more). Failures and refusals say nothing
    /// about the source and are not recorded. Past [`MAX_ENTRIES`] the
    /// source confirmed longest ago is forgotten; it is then charged as a
    /// first-time lookup until a fetch finds its keys again.
    pub fn note_found(&mut self, source: &Source, found: bool, now: i64) {
        if !found {
            self.known.remove(source);
            return;
        }
        make_room(&mut self.known, source, |_| false, |&at| at);
        self.known.insert(source.clone(), now);
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
    fn known_sources_are_bounded_dropping_the_longest_unconfirmed() {
        let mut t = Tables::default();
        for i in 0..MAX_ENTRIES {
            t.note_found(&source(i), true, if i == 0 { 5 } else { 10 });
        }
        // Re-confirming an entry does not grow the table.
        t.note_found(&source(1), true, 20);
        assert_eq!(t.known.len(), MAX_ENTRIES);
        t.note_found(&source(MAX_ENTRIES), true, 30);
        assert_eq!(t.known.len(), MAX_ENTRIES);
        assert!(!t.is_known(&source(0)), "confirmed longest ago");
        assert!(t.is_known(&source(1)));
        assert!(t.is_known(&source(MAX_ENTRIES)));
    }

    #[test]
    fn tables_are_bounded_dropping_expired_then_oldest() {
        let mut t = Tables::default();
        for i in 0..MAX_ENTRIES {
            // Entry 0 expires first; entry 1 is the oldest of the rest.
            let (stored, expires) = if i == 0 { (5, 50) } else { (i as i64, 100_000) };
            t.store(&source(i), Arc::new(KeySet::new()), Some(expires), stored);
        }
        t.store(
            &source(MAX_ENTRIES),
            Arc::new(KeySet::new()),
            Some(100_000),
            60,
        );
        assert_eq!(t.cache.len(), MAX_ENTRIES);
        assert!(!t.cache.contains_key(&source(0)), "expired entry dropped");
        assert!(t.cache.contains_key(&source(1)));
        t.store(
            &source(MAX_ENTRIES + 1),
            Arc::new(KeySet::new()),
            Some(100_000),
            60,
        );
        assert!(!t.cache.contains_key(&source(1)), "then the oldest");
        assert_eq!(t.cache.len(), MAX_ENTRIES);

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
