//! The known sources: those whose last completed fetch returned a
//! non-empty key list (docs/decisions/0006). Their expiry re-fetches are
//! charged to the targets' known budgets.
//!
//! The table is bounded per target group (registrable domain) as well as
//! overall, so that one domain cannot push every other domain's sources
//! out. Anyone running a provider that serves keys for any handle can make
//! its own sources known; the per-group cap keeps that to its own share:
//!
//! * a group at [`MAX_KNOWN_PER_GROUP`] makes room by forgetting **its own**
//!   source confirmed longest ago;
//! * a full table ([`MAX_KNOWN`]) makes room in the **largest** group (on a
//!   tie, the one that most recently gained a source), so a group is only
//!   ever cut back while no other group is bigger.
//!
//! Every operation is O(log n).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use super::budget::target_group;
use super::fetch::Source;
use super::state::MAX_ENTRIES;

/// Most known sources in one target group.
pub const MAX_KNOWN_PER_GROUP: usize = 500;
/// Most known sources in all.
pub const MAX_KNOWN: usize = MAX_ENTRIES;

/// Where a source sits in its group's order: when it was last confirmed,
/// then a sequence number that makes the order total.
type Order = (i64, u64);

/// A group's rank among groups: its size, when it last gained a source,
/// and its name. The last rank is the group to cut back first.
type Rank = (usize, u64, Arc<str>);

/// A known source's place.
struct Slot {
    group: Arc<str>,
    order: Order,
}

/// The known sources of one target group.
struct Group {
    /// Its sources, confirmed longest ago first.
    entries: BTreeMap<Order, Source>,
    /// The sequence number of the last source it gained.
    grown: u64,
}

/// The known sources, bounded per target group and overall.
pub struct KnownSources {
    slots: HashMap<Source, Slot>,
    groups: HashMap<Arc<str>, Group>,
    /// Every non-empty group, by [`Rank`].
    ranks: BTreeSet<Rank>,
    seq: u64,
    per_group: usize,
    total: usize,
}

impl Default for KnownSources {
    fn default() -> Self {
        Self::with_caps(MAX_KNOWN_PER_GROUP, MAX_KNOWN)
    }
}

impl KnownSources {
    /// A table holding at most `per_group` sources of one target group and
    /// `total` in all.
    pub fn with_caps(per_group: usize, total: usize) -> Self {
        Self {
            slots: HashMap::new(),
            groups: HashMap::new(),
            ranks: BTreeSet::new(),
            seq: 0,
            per_group: per_group.max(1),
            total: total.max(1),
        }
    }

    /// Whether `source` is known.
    pub fn contains(&self, source: &Source) -> bool {
        self.slots.contains_key(source)
    }

    /// How many sources are known.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// Record that a fetch of `source` found keys at `now`, making room
    /// first if it is new and its group or the table is full.
    pub fn confirm(&mut self, source: &Source, now: i64) {
        self.seq += 1;
        let order = (now, self.seq);
        if let Some(slot) = self.slots.get_mut(source) {
            // Re-confirmed: moves to the back of its group's order. The
            // group's size and rank do not change.
            if let Some(group) = self.groups.get_mut(&slot.group) {
                group.entries.remove(&slot.order);
                group.entries.insert(order, source.clone());
            }
            slot.order = order;
            return;
        }
        let name: Arc<str> = target_group(source).into();
        let size = self.groups.get(&name).map_or(0, |g| g.entries.len());
        if size >= self.per_group {
            self.evict_oldest(&name);
        } else if self.slots.len() >= self.total
            && let Some((_, _, largest)) = self.ranks.last().cloned()
        {
            self.evict_oldest(&largest);
        }
        self.unrank(&name);
        let group = self.groups.entry(name.clone()).or_insert_with(|| Group {
            entries: BTreeMap::new(),
            grown: 0,
        });
        group.entries.insert(order, source.clone());
        group.grown = self.seq;
        self.rerank(&name);
        self.slots
            .insert(source.clone(), Slot { group: name, order });
    }

    /// Forget `source` (a fetch found no keys for it).
    pub fn forget(&mut self, source: &Source) {
        let Some(slot) = self.slots.remove(source) else {
            return;
        };
        self.unrank(&slot.group);
        if let Some(group) = self.groups.get_mut(&slot.group) {
            group.entries.remove(&slot.order);
        }
        self.rerank(&slot.group);
    }

    /// Forget the source of group `name` confirmed longest ago.
    fn evict_oldest(&mut self, name: &Arc<str>) {
        self.unrank(name);
        if let Some(group) = self.groups.get_mut(name)
            && let Some((_, source)) = group.entries.pop_first()
        {
            self.slots.remove(&source);
        }
        self.rerank(name);
    }

    /// Take group `name` out of the ranking, before it changes size.
    fn unrank(&mut self, name: &Arc<str>) {
        if let Some(group) = self.groups.get(name) {
            self.ranks
                .remove(&(group.entries.len(), group.grown, name.clone()));
        }
    }

    /// Put group `name` back in the ranking after a change, or drop it if
    /// it is now empty.
    fn rerank(&mut self, name: &Arc<str>) {
        match self.groups.get(name) {
            Some(group) if !group.entries.is_empty() => {
                self.ranks
                    .insert((group.entries.len(), group.grown, name.clone()));
            }
            _ => {
                self.groups.remove(name);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use re_ofscp_types::Actor;

    use super::*;

    fn user(id: &str) -> Source {
        Source::User(Actor::parse_canonical(id).unwrap())
    }

    /// The tables agree with each other: every slot is in its group at its
    /// order, every group is ranked by its true size, none is empty.
    fn assert_consistent(k: &KnownSources) {
        let in_groups: usize = k.groups.values().map(|g| g.entries.len()).sum();
        assert_eq!(in_groups, k.slots.len());
        assert_eq!(k.ranks.len(), k.groups.len());
        for (name, group) in &k.groups {
            assert!(!group.entries.is_empty());
            assert!(
                k.ranks
                    .contains(&(group.entries.len(), group.grown, name.clone()))
            );
        }
        for (source, slot) in &k.slots {
            assert_eq!(k.groups[&slot.group].entries.get(&slot.order), Some(source));
        }
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
        assert!(k.groups.is_empty() && k.ranks.is_empty());
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
        k.groups.get(name).map_or(0, |g| g.entries.len())
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
