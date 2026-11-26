//! The resolver's bounded tables: cached documents, cached negatives,
//! fetches in flight, when each source was last re-fetched on a miss, and
//! which sources are known (their last completed fetch found keys).
//!
//! Every table but the flights is a [`Grouped`] one, grouped by target group
//! (registrable domain), so that a provider serving keys for any handle
//! cannot push other domains' entries out (docs/decisions/0006). Cached
//! negatives (empty key lists and user-keys `404`s) live apart from cached
//! documents with keys, in a smaller table capped per group as well, so
//! that a flood of handles that do not exist can never displace a real
//! user's document.

use std::collections::HashMap;
use std::sync::Arc;

use ed25519_dalek::VerifyingKey;
use tokio::sync::watch;

use super::document::KeySet;
use super::fetch::{Fetched, Source};
use super::grouped::Grouped;
use super::known::KnownSources;

/// Most entries in each table.
pub const MAX_ENTRIES: usize = 10_000;
/// Most cached documents with keys, in all. One target group may hold any
/// number of them while there is room.
pub const MAX_CACHED: usize = MAX_ENTRIES;
/// Most cached negatives of one target group.
pub const MAX_NEGATIVE_PER_GROUP: usize = 100;
/// Most cached negatives in all.
pub const MAX_NEGATIVE: usize = 2_000;
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
    /// Cached documents with keys, each usable while `now < expires` (unix
    /// seconds), bounded overall.
    cache: Grouped<Arc<KeySet>>,
    /// Cached negatives (no keys), usable on the same terms, bounded per
    /// target group and overall. A source is in at most one of `cache` and
    /// `negative`.
    negative: Grouped<Arc<KeySet>>,
    /// Fetches in flight, so concurrent lookups share one.
    pub flights: HashMap<Source, Flight>,
    /// When each source was last re-fetched for a `fresh` lookup, expiring
    /// when its re-fetch interval ends.
    refetched: Grouped<i64>,
    /// Known sources: those whose last completed fetch returned a
    /// non-empty key list. Their expiry re-fetches are charged to the
    /// targets' known budgets (docs/decisions/0006).
    known: KnownSources,
}

impl Default for Tables {
    fn default() -> Self {
        Self::with_cache_caps(MAX_CACHED, MAX_NEGATIVE_PER_GROUP, MAX_NEGATIVE)
    }
}

impl Tables {
    /// Tables caching at most `cached` documents with keys, and at most
    /// `negative_per_group` negatives of one target group and `negative`
    /// in all.
    pub fn with_cache_caps(cached: usize, negative_per_group: usize, negative: usize) -> Self {
        Self {
            cache: Grouped::with_total(cached),
            negative: Grouped::with_caps(negative_per_group, negative),
            flights: HashMap::new(),
            refetched: Grouped::with_total(MAX_ENTRIES),
            known: KnownSources::default(),
        }
    }

    /// `source`'s keys (empty for a cached negative) and when its entry
    /// expires, if it has not expired at `now`.
    pub fn live_entry(&self, source: &Source, now: i64) -> Option<(&Arc<KeySet>, i64)> {
        let entry = self.cache.get(source).or_else(|| self.negative.get(source));
        match entry {
            Some((keys, Some(expires))) if now < expires => Some((keys, expires)),
            _ => None,
        }
    }

    /// The key `key_id` of `source` from an entry still unexpired at `now`,
    /// with the entry's expiry. Only such a key may stand in for a fetch
    /// that failed, was refused or was rate-limited: an expired entry never
    /// counts (lost-conn/ofscp#20), so a revoked key cannot outlive its
    /// cache because fetches keep failing.
    pub fn cached_key(
        &self,
        source: &Source,
        key_id: &str,
        now: i64,
    ) -> Option<(VerifyingKey, i64)> {
        self.live_entry(source, now)
            .and_then(|(keys, expires)| keys.get(key_id).map(|k| (*k, expires)))
    }

    /// Record a completed fetch. Cacheable until `expires`, or (for
    /// `None`) not at all, which also drops what was cached before: it is
    /// superseded. A document with keys goes in the document cache and a
    /// negative in the negative table, and either drops the source's entry
    /// in the other. Making room drops an expired entry or one of the
    /// largest group's ([`Grouped`]); in the negative table a group at its
    /// cap gives up its own. It never touches a fetch in flight, which
    /// lookups keep joining whatever the cache holds.
    pub fn store(&mut self, source: &Source, keys: Arc<KeySet>, expires: Option<i64>, now: i64) {
        let Some(expires) = expires.filter(|&t| t > now) else {
            self.cache.remove(source);
            self.negative.remove(source);
            return;
        };
        let (table, other) = if keys.is_empty() {
            (&mut self.negative, &mut self.cache)
        } else {
            (&mut self.cache, &mut self.negative)
        };
        other.remove(source);
        table.insert(source, keys, Some(expires), now);
    }

    /// Seconds until `source` may be re-fetched for a `fresh` lookup, or
    /// `None` if it may be now.
    pub fn refetch_wait(&self, source: &Source, now: i64) -> Option<u64> {
        let (&last, _) = self.refetched.get(source)?;
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
    /// about the source and are not recorded. The table is bounded overall
    /// ([`KnownSources`]); a source it forgets is charged as a first-time
    /// lookup until a fetch finds its keys again.
    pub fn note_found(&mut self, source: &Source, found: bool, now: i64) {
        if found {
            self.known.confirm(source, now);
        } else {
            self.known.forget(source);
        }
    }

    /// Note a `fresh` re-fetch of `source` at `now`. The entry expires when
    /// the re-fetch interval ends; past [`MAX_ENTRIES`], an expired entry
    /// makes room first, else one of the largest group's ([`Grouped`]).
    pub fn note_refetch(&mut self, source: &Source, now: i64) {
        self.refetched
            .insert(source, now, Some(now + REFETCH_INTERVAL_SECS), now);
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
        assert!(t.live_entry(&s, 109).is_some());
        assert!(t.live_entry(&s, 110).is_none(), "expired at its expiry");
        t.store(&s, Arc::new(KeySet::new()), None, 105);
        assert!(
            t.live_entry(&s, 106).is_none(),
            "superseded by an uncacheable answer"
        );
        t.store(&s, Arc::new(KeySet::new()), Some(105), 105);
        assert!(
            t.live_entry(&s, 105).is_none(),
            "already expired: not stored"
        );
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

    /// A document with one key.
    fn keys() -> Arc<KeySet> {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key();
        Arc::new([("dk_1".to_owned(), key)].into_iter().collect())
    }

    fn user(id: &str) -> Source {
        Source::User(re_ofscp_types::Actor::parse_canonical(id).unwrap())
    }

    #[test]
    fn a_crowd_of_free_subdomains_cannot_evict_a_large_peer() {
        // A real peer with 4 000 active users: their documents cached,
        // each known, each just re-fetched.
        let mut t = Tables::default();
        let doc = keys();
        let peer: Vec<_> = (0..4_000)
            .map(|i| user(&format!("user{i}@big.example")))
            .collect();
        for p in &peer {
            t.store(p, doc.clone(), Some(100_000), 1);
            t.note_found(p, true, 1);
            t.note_refetch(p, 1);
        }
        // An attacker takes 2 000 free subdomains of a private-section
        // suffix, each serving keys for five handles: 10 000 sources, all
        // more recent than the peer's. Were each subdomain a group of its
        // own (as with the PSL's private section), every group would be
        // smaller than the peer's, so the peer, as the largest group,
        // would give way on every insert past the table's 10 000.
        for host in 0..2_000 {
            for handle in 0..5 {
                let s = user(&format!("hhh{handle}@s{host}.workers.dev"));
                t.store(&s, doc.clone(), Some(100_000), 2);
                t.note_found(&s, true, 2);
                t.note_refetch(&s, 2);
            }
        }
        // They are one group, which grows only to the room left (it would
        // grow until no larger than the peer's, half the table) and then
        // cycles its own entries.
        let rest = MAX_ENTRIES - peer.len();
        assert_eq!(t.cache.group_len("workers.dev"), rest);
        assert_eq!(t.known.len(), MAX_ENTRIES);
        assert_eq!(t.refetched.group_len("workers.dev"), rest);
        for p in &peer {
            assert!(t.live_entry(p, 3).is_some(), "{p:?} still cached");
            assert!(t.is_known(p), "{p:?} still known");
            assert!(t.refetch_wait(p, 3).is_some(), "{p:?} still timed");
        }
    }

    #[test]
    fn the_cache_is_bounded_dropping_expired_then_the_largest_groups_oldest() {
        let mut t = Tables::with_cache_caps(4, 100, 100);
        let sub = Source::Provider(Authority::parse_canonical("a.p1.example").unwrap());
        // p0 expires at 50; p1.example holds two entries. The table is full.
        t.store(&source(0), keys(), Some(50), 0);
        t.store(&source(1), keys(), Some(1000), 1);
        t.store(&sub, keys(), Some(1000), 2);
        t.store(&source(2), keys(), Some(1000), 3);
        // An expired entry goes first, whatever its group.
        t.store(&source(3), keys(), Some(1000), 60);
        assert!(t.cache.get(&source(0)).is_none(), "expired entry dropped");
        assert!(t.live_entry(&source(1), 60).is_some());
        // Then the oldest entry of the largest group.
        t.store(&source(4), keys(), Some(1000), 61);
        assert!(t.cache.get(&source(1)).is_none(), "p1.example was cut back");
        for s in [&sub, &source(2), &source(3), &source(4)] {
            assert!(t.live_entry(s, 62).is_some(), "{s:?}");
        }
        t.cache.assert_consistent();
    }

    #[test]
    fn negatives_are_cached_apart_and_a_change_of_kind_moves_the_entry() {
        let mut t = Tables::default();
        let s = source(0);
        t.store(&s, Arc::new(KeySet::new()), Some(110), 100);
        assert!(t.live_entry(&s, 109).is_some_and(|(k, _)| k.is_empty()));
        assert!(t.negative.contains(&s) && !t.cache.contains(&s));
        assert!(t.live_entry(&s, 110).is_none(), "a negative expires too");
        t.store(&s, keys(), Some(200), 101);
        assert!(t.cache.contains(&s) && !t.negative.contains(&s));
        assert_eq!(t.live_entry(&s, 150).map(|(k, _)| k.len()), Some(1));
        t.store(&s, Arc::new(KeySet::new()), Some(300), 102);
        assert!(t.negative.contains(&s) && !t.cache.contains(&s));
        t.store(&s, keys(), None, 103);
        assert!(!t.negative.contains(&s) && !t.cache.contains(&s));
        t.cache.assert_consistent();
        t.negative.assert_consistent();
    }

    #[test]
    fn a_flood_of_negatives_never_displaces_a_peers_documents() {
        let mut t = Tables::default();
        // More real users than any per-group cap ever was, filling the
        // group, then thousands of handles that do not exist (404s and
        // empty lists) at the same domain and at others.
        let users: Vec<_> = (0..2_000)
            .map(|i| user(&format!("user{i}@victim.example")))
            .collect();
        for user in &users {
            t.store(user, keys(), Some(10_000), 1);
        }
        for i in 0..5 * MAX_NEGATIVE {
            let at = if i % 2 == 0 { "victim" } else { "other" };
            let s = user(&format!("ghost{i}@{at}.example"));
            t.store(&s, Arc::new(KeySet::new()), Some(10_000), 2);
        }
        assert!(
            users
                .iter()
                .all(|u| t.live_entry(u, 3).is_some_and(|(k, _)| k.len() == 1))
        );
        assert_eq!(
            t.negative.group_len("victim.example"),
            MAX_NEGATIVE_PER_GROUP
        );
        t.cache.assert_consistent();
        t.negative.assert_consistent();
    }

    #[test]
    fn the_refetch_table_is_bounded_dropping_expired_then_the_largest_groups() {
        let mut t = Tables::default();
        let victim = source(0);
        t.note_refetch(&victim, 990);
        // An attacker fills the rest of the table under one domain.
        for i in 1..MAX_ENTRIES {
            t.note_refetch(&user(&format!("uuu{i}@evil.example")), 1000);
        }
        t.note_refetch(&source(1), 1000);
        assert_eq!(t.refetched.len(), MAX_ENTRIES);
        assert!(t.refetched.contains(&victim), "the smaller group stays");
        assert!(
            !t.refetched.contains(&user("uuu1@evil.example")),
            "the largest group's oldest dropped"
        );
        // Once an entry lapses, it is the one to make room.
        t.note_refetch(&source(2), 1050);
        assert!(!t.refetched.contains(&victim), "lapsed at 1050");
        assert!(t.refetched.contains(&source(1)));
        assert_eq!(t.refetched.len(), MAX_ENTRIES);
        t.refetched.assert_consistent();
    }
}
