//! The known sources: those whose last completed fetch returned a
//! non-empty key list (docs/decisions/0006). Their expiry re-fetches are
//! charged to the targets' known budgets.
//!
//! The table is a [`Grouped`] one, bounded per target group (registrable
//! domain) as well as overall, so that one domain cannot push every other
//! domain's sources out. Known sources never expire, so a group at
//! [`MAX_KNOWN_PER_GROUP`] forgets its own source confirmed longest ago,
//! and a full table ([`MAX_KNOWN`]) the one confirmed longest ago in the
//! largest group. Every operation is O(log n).

use super::fetch::Source;
use super::grouped::Grouped;
use super::state::MAX_ENTRIES;

/// Most known sources in one target group.
pub const MAX_KNOWN_PER_GROUP: usize = 500;
/// Most known sources in all.
pub const MAX_KNOWN: usize = MAX_ENTRIES;

/// The known sources, bounded per target group and overall.
pub struct KnownSources(Grouped<()>);

impl Default for KnownSources {
    fn default() -> Self {
        Self::with_caps(MAX_KNOWN_PER_GROUP, MAX_KNOWN)
    }
}

impl KnownSources {
    /// A table holding at most `per_group` sources of one target group and
    /// `total` in all.
    pub fn with_caps(per_group: usize, total: usize) -> Self {
        Self(Grouped::with_caps(per_group, total))
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
    /// first if it is new and its group or the table is full.
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
    fn a_full_group_forgets_its_own_longest_unconfirmed_source() {
        let mut k = KnownSources::with_caps(3, 100);
        let victim = user("alice@victim.example");
        k.confirm(&victim, 1);
        for i in 0..3 {
            k.confirm(&user(&format!("uuu{i}@evil.example")), 10 + i);
        }
        // u0 is re-confirmed, so u1 is now the longest unconfirmed.
        k.confirm(&user("uuu0@evil.example"), 20);
        k.confirm(&user("uuu3@a.evil.example:8443"), 30);
        assert!(!k.contains(&user("uuu1@evil.example")));
        for id in [
            "uuu0@evil.example",
            "uuu2@evil.example",
            "uuu3@a.evil.example:8443",
        ] {
            assert!(k.contains(&user(id)), "{id}");
        }
        assert!(k.contains(&victim), "another group is untouched");
        assert_consistent(&k);
    }

    #[test]
    fn one_group_filling_its_quota_and_beyond_leaves_other_groups_intact() {
        let mut k = KnownSources::default();
        let peers: Vec<_> = (0..50)
            .map(|i| user(&format!("user{i}@victim.example")))
            .collect();
        for (i, peer) in peers.iter().enumerate() {
            k.confirm(peer, i as i64);
        }
        // An attacker's provider serves keys for any handle: thousands of
        // its sources are confirmed, far past its group's quota, all more
        // recently than the victim's.
        for i in 0..5 * MAX_KNOWN_PER_GROUP {
            k.confirm(&user(&format!("rrr{i}@evil.example")), 1000 + i as i64);
        }
        assert_eq!(k.len(), peers.len() + MAX_KNOWN_PER_GROUP);
        assert!(peers.iter().all(|p| k.contains(p)));
        assert_consistent(&k);
    }

    fn size(k: &KnownSources, name: &str) -> usize {
        k.0.group_len(name)
    }

    #[test]
    fn a_full_table_cuts_back_the_largest_group() {
        let mut k = KnownSources::with_caps(5, 10);
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
        // Past the total, the largest group gave way each time (on a tie,
        // the one that grew last), never the smaller victim group.
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
