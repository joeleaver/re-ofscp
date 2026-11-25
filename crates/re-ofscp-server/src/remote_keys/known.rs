//! The known sources: those whose last completed fetch returned a
//! non-empty key list (docs/decisions/0006). Their expiry re-fetches are
//! charged to the targets' known budgets.
//!
//! The table is a [`Grouped`] one, grouped by target group (registrable
//! domain) and bounded overall ([`MAX_KNOWN`]). A group may hold any number
//! of sources while there is room, so a peer with many active users keeps
//! them all. Known sources never expire, so a full table forgets a source
//! of the largest group (the inserting group's own if none is larger),
//! confirmed longest ago: one domain cannot push another domain's sources
//! out by filling the table with its own. Every operation is O(log n).

use super::fetch::Source;
use super::grouped::Grouped;
use super::state::MAX_ENTRIES;

/// Most known sources in all.
pub const MAX_KNOWN: usize = MAX_ENTRIES;

/// The known sources, grouped by target group and bounded overall.
pub struct KnownSources(Grouped<()>);

impl Default for KnownSources {
    fn default() -> Self {
        Self::with_total(MAX_KNOWN)
    }
}

impl KnownSources {
    /// A table holding at most `total` sources.
    pub fn with_total(total: usize) -> Self {
        Self(Grouped::with_total(total))
    }

    /// Whether `source` is known.
    pub fn contains(&self, source: &Source) -> bool {
        self.0.contains(source)
    }

    /// How many sources are known.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Record that a fetch of `source` found keys at `now`, making room
    /// first if it is new and the table is full.
    pub fn confirm(&mut self, source: &Source, now: i64) {
        self.0.insert(source, (), None, now);
    }

    /// Forget `source` (a fetch found no keys for it).
    pub fn forget(&mut self, source: &Source) {
        self.0.remove(source);
    }
}

#[cfg(test)]
mod tests {
    use re_ofscp_types::Actor;

    use super::*;

    fn user(id: &str) -> Source {
        Source::User(Actor::parse_canonical(id).unwrap())
    }

    fn assert_consistent(k: &KnownSources) {
        k.0.assert_consistent();
    }

    #[test]
    fn sources_are_confirmed_and_forgotten() {
        let mut k = KnownSources::default();
        let alice = user("alice@victim.example");
        assert!(!k.contains(&alice));
        k.confirm(&alice, 100);
        k.confirm(&alice, 200);
        assert!(k.contains(&alice));
        assert_eq!(k.len(), 1);
        k.forget(&alice);
        assert!(!k.contains(&alice));
        k.forget(&alice);
        assert_eq!(k.len(), 0);
        assert_consistent(&k);
    }

    #[test]
    fn a_large_peer_keeps_all_its_sources_while_there_is_room() {
        let mut k = KnownSources::default();
        for i in 0..2_000 {
            k.confirm(&user(&format!("user{i}@big.example")), i);
        }
        assert_eq!(size(&k, "big.example"), 2_000);
        assert_consistent(&k);
    }

    #[test]
    fn a_flood_of_another_domains_sources_leaves_a_peers_intact() {
        let mut k = KnownSources::default();
        let peers: Vec<_> = (0..50)
            .map(|i| user(&format!("user{i}@victim.example")))
            .collect();
        for (i, peer) in peers.iter().enumerate() {
            k.confirm(peer, i as i64);
        }
        // An attacker's provider serves keys for any handle: twice the
        // table's worth of its sources are confirmed, all more recently
        // than the victim's.
        for i in 0..2 * MAX_KNOWN {
            k.confirm(&user(&format!("rrr{i}@evil.example")), 1000 + i as i64);
        }
        assert_eq!(k.len(), MAX_KNOWN);
        assert!(peers.iter().all(|p| k.contains(p)));
        assert_consistent(&k);
    }

    fn size(k: &KnownSources, name: &str) -> usize {
        k.0.group_len(name)
    }

    #[test]
    fn a_full_table_cuts_back_the_largest_group() {
        let mut k = KnownSources::with_total(10);
        // victim: 3 sources; evil and bad: 5 each would overflow the table.
        for i in 0..3 {
            k.confirm(&user(&format!("vvv{i}@victim.example")), i);
        }
        for i in 0..5 {
            k.confirm(&user(&format!("eee{i}@evil.example")), 10 + i);
        }
        for i in 0..5 {
            k.confirm(&user(&format!("bbb{i}@bad.example")), 20 + i);
        }
        assert_eq!(k.len(), 10);
        // Past the total, the largest group gave way each time, never the
        // smaller victim group.
        for i in 0..3 {
            assert!(k.contains(&user(&format!("vvv{i}@victim.example"))));
        }
        assert_eq!(size(&k, "victim.example"), 3);
        assert_eq!(size(&k, "evil.example") + size(&k, "bad.example"), 7);
        assert!(size(&k, "evil.example").abs_diff(size(&k, "bad.example")) <= 1);
        // A newcomer group still gets in, at the largest group's expense.
        k.confirm(&user("nnn0@new.example"), 30);
        assert!(k.contains(&user("nnn0@new.example")));
        assert_eq!(size(&k, "victim.example"), 3);
        assert_eq!(k.len(), 10);
        assert_consistent(&k);
    }
}
