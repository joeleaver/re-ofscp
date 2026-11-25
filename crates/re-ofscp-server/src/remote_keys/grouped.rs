//! A table of sources bounded per target group (registrable domain) as well
//! as overall, so that one domain cannot push every other domain's entries
//! out (docs/decisions/0006). Anyone running a provider that serves keys
//! for any handle can fill a table with its own sources; the per-group cap
//! keeps that to its own share. Both the cached documents and the known
//! sources are kept in one.
//!
//! Making room for a new entry:
//!
//! * a group at its cap gives up **its own** entry: an expired one if it
//!   has any, else the one stored longest ago;
//! * a full table gives up an expired entry of any group if there is one,
//!   else the oldest entry of the **largest** group (on a tie, the one that
//!   most recently gained an entry), so a group is only ever cut back while
//!   no other group is bigger.
//!
//! Eviction only ever removes an entry; it never changes another entry's
//! expiry (lost-conn/ofscp#20). Every operation is O(log n).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use super::budget::target_group;
use super::fetch::Source;

/// Where an entry sits in its group's age order: when it was stored, then a
/// sequence number that makes the order total.
type Order = (i64, u64);

/// Where an entry sits in the expiry orders: when it expires, then its
/// sequence number.
type Expiry = (i64, u64);

/// A group's rank among groups: its size, when it last gained an entry, and
/// its name. The last rank is the group to cut back first.
type Rank = (usize, u64, Arc<str>);

/// An entry and its place in the orders.
struct Slot<V> {
    group: Arc<str>,
    order: Order,
    /// When it expires (unix seconds), if it does.
    expires: Option<i64>,
    value: V,
}

impl<V> Slot<V> {
    fn expiry(&self) -> Option<Expiry> {
        self.expires.map(|at| (at, self.order.1))
    }
}

/// The entries of one target group.
struct Group {
    /// Its entries, stored longest ago first.
    by_age: BTreeMap<Order, Source>,
    /// Its entries that expire, soonest first.
    by_expiry: BTreeMap<Expiry, Source>,
    /// The sequence number of the last entry it gained.
    grown: u64,
}

/// Entries keyed by source, bounded per target group and overall.
pub struct Grouped<V> {
    slots: HashMap<Source, Slot<V>>,
    groups: HashMap<Arc<str>, Group>,
    /// Every non-empty group, by [`Rank`].
    ranks: BTreeSet<Rank>,
    /// Every entry that expires, soonest first.
    expiries: BTreeMap<Expiry, Source>,
    seq: u64,
    per_group: usize,
    total: usize,
}

impl<V> Grouped<V> {
    /// A table holding at most `per_group` entries of one target group and
    /// `total` in all.
    pub fn with_caps(per_group: usize, total: usize) -> Self {
        Self {
            slots: HashMap::new(),
            groups: HashMap::new(),
            ranks: BTreeSet::new(),
            expiries: BTreeMap::new(),
            seq: 0,
            per_group: per_group.max(1),
            total: total.max(1),
        }
    }

    /// `source`'s entry and its expiry, if it has one.
    pub fn get(&self, source: &Source) -> Option<(&V, Option<i64>)> {
        self.slots.get(source).map(|s| (&s.value, s.expires))
    }

    /// Whether `source` has an entry.
    pub fn contains(&self, source: &Source) -> bool {
        self.slots.contains_key(source)
    }

    /// How many entries there are.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// How many entries group `name` has.
    #[cfg(test)]
    pub fn group_len(&self, name: &str) -> usize {
        self.groups.get(name).map_or(0, |g| g.by_age.len())
    }

    /// Store `value` for `source` at `now`, expiring at `expires` (never,
    /// for `None`). An existing entry is replaced and moves to the back of
    /// its group's age order; a new one first makes room if its group or
    /// the table is full.
    pub fn insert(&mut self, source: &Source, value: V, expires: Option<i64>, now: i64) {
        self.seq += 1;
        let order = (now, self.seq);
        if let Some(old) = self.slots.remove(source) {
            // Replaced: the group's size and rank do not change.
            self.unindex(&old);
            let slot = Slot {
                group: old.group,
                order,
                expires,
                value,
            };
            self.index(source, &slot);
            self.slots.insert(source.clone(), slot);
            return;
        }
        let name: Arc<str> = target_group(source).into();
        self.make_room(&name, now);
        self.unrank(&name);
        let group = self.groups.entry(name.clone()).or_insert_with(|| Group {
            by_age: BTreeMap::new(),
            by_expiry: BTreeMap::new(),
            grown: 0,
        });
        group.grown = self.seq;
        let slot = Slot {
            group: name.clone(),
            order,
            expires,
            value,
        };
        self.index(source, &slot);
        self.rerank(&name);
        self.slots.insert(source.clone(), slot);
    }

    /// Remove `source`'s entry, if any.
    pub fn remove(&mut self, source: &Source) {
        let Some(slot) = self.slots.remove(source) else {
            return;
        };
        self.unrank(&slot.group);
        self.unindex(&slot);
        self.rerank(&slot.group);
    }

    /// Make room for a new entry of group `name` at `now`.
    fn make_room(&mut self, name: &Arc<str>, now: i64) {
        let size = self.groups.get(name).map_or(0, |g| g.by_age.len());
        if size >= self.per_group {
            self.evict_from(name, now);
            return;
        }
        if self.slots.len() < self.total {
            return;
        }
        if let Some((&(at, _), source)) = self.expiries.first_key_value()
            && at <= now
        {
            let source = source.clone();
            self.remove(&source);
        } else if let Some((_, _, largest)) = self.ranks.last().cloned() {
            self.evict_from(&largest, now);
        }
    }

    /// Remove one entry of group `name`: an expired one at `now` if there
    /// is one, else the one stored longest ago.
    fn evict_from(&mut self, name: &Arc<str>, now: i64) {
        let Some(group) = self.groups.get(name) else {
            return;
        };
        let expired = group
            .by_expiry
            .first_key_value()
            .filter(|(expiry, _)| expiry.0 <= now);
        let victim = expired.or_else(|| group.by_age.first_key_value());
        if let Some((_, source)) = victim {
            let source = source.clone();
            self.remove(&source);
        }
    }

    /// Put `slot` (of `source`) in its group's orders and the expiry order.
    /// Its group must exist.
    fn index(&mut self, source: &Source, slot: &Slot<V>) {
        if let Some(group) = self.groups.get_mut(&slot.group) {
            group.by_age.insert(slot.order, source.clone());
            if let Some(expiry) = slot.expiry() {
                group.by_expiry.insert(expiry, source.clone());
            }
        }
        if let Some(expiry) = slot.expiry() {
            self.expiries.insert(expiry, source.clone());
        }
    }

    /// Take `slot` out of its group's orders and the expiry order.
    fn unindex(&mut self, slot: &Slot<V>) {
        if let Some(group) = self.groups.get_mut(&slot.group) {
            group.by_age.remove(&slot.order);
            if let Some(expiry) = slot.expiry() {
                group.by_expiry.remove(&expiry);
            }
        }
        if let Some(expiry) = slot.expiry() {
            self.expiries.remove(&expiry);
        }
    }

    /// Take group `name` out of the ranking, before it changes size.
    fn unrank(&mut self, name: &Arc<str>) {
        if let Some(group) = self.groups.get(name) {
            self.ranks
                .remove(&(group.by_age.len(), group.grown, name.clone()));
        }
    }

    /// Put group `name` back in the ranking after a change, or drop it if
    /// it is now empty.
    fn rerank(&mut self, name: &Arc<str>) {
        match self.groups.get(name) {
            Some(group) if !group.by_age.is_empty() => {
                self.ranks
                    .insert((group.by_age.len(), group.grown, name.clone()));
            }
            _ => {
                self.groups.remove(name);
            }
        }
    }

    /// The tables agree with each other: every slot is in its group's
    /// orders and the expiry order, nothing else is, every group is ranked
    /// by its true size, none is empty, and the caps hold.
    #[cfg(test)]
    pub fn assert_consistent(&self) {
        let in_groups: usize = self.groups.values().map(|g| g.by_age.len()).sum();
        assert_eq!(in_groups, self.slots.len());
        let expiring = self.slots.values().filter(|s| s.expires.is_some()).count();
        assert_eq!(self.expiries.len(), expiring);
        let in_group_expiries: usize = self.groups.values().map(|g| g.by_expiry.len()).sum();
        assert_eq!(in_group_expiries, expiring);
        assert_eq!(self.ranks.len(), self.groups.len());
        assert!(self.slots.len() <= self.total);
        for (name, group) in &self.groups {
            assert!(!group.by_age.is_empty());
            assert!(group.by_age.len() <= self.per_group);
            assert!(
                self.ranks
                    .contains(&(group.by_age.len(), group.grown, name.clone()))
            );
        }
        for (source, slot) in &self.slots {
            let group = &self.groups[&slot.group];
            assert_eq!(group.by_age.get(&slot.order), Some(source));
            if let Some(expiry) = slot.expiry() {
                assert_eq!(group.by_expiry.get(&expiry), Some(source));
                assert_eq!(self.expiries.get(&expiry), Some(source));
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

    #[test]
    fn entries_are_replaced_and_removed() {
        let mut t = Grouped::with_caps(3, 10);
        let alice = user("alice@victim.example");
        t.insert(&alice, 1, Some(50), 10);
        t.insert(&alice, 2, None, 20);
        assert_eq!(t.get(&alice), Some((&2, None)));
        assert_eq!(t.len(), 1);
        t.assert_consistent();
        t.insert(&alice, 3, Some(70), 30);
        assert_eq!(t.get(&alice), Some((&3, Some(70))));
        t.assert_consistent();
        t.remove(&alice);
        t.remove(&alice);
        assert!(!t.contains(&alice));
        assert!(t.groups.is_empty() && t.ranks.is_empty() && t.expiries.is_empty());
    }

    #[test]
    fn a_full_group_gives_up_its_own_expired_entry_then_its_oldest() {
        let mut t = Grouped::with_caps(3, 100);
        let victim = user("alice@victim.example");
        t.insert(&victim, (), Some(5), 1);
        // uuu1 is the only one expired by time 50; uuu0 is the oldest.
        t.insert(&user("uuu0@evil.example"), (), Some(1000), 10);
        t.insert(&user("uuu1@evil.example"), (), Some(40), 11);
        t.insert(&user("uuu2@evil.example"), (), Some(1000), 12);
        t.insert(&user("uuu3@a.evil.example:8443"), (), Some(1000), 50);
        assert!(!t.contains(&user("uuu1@evil.example")), "expired first");
        assert!(t.contains(&user("uuu0@evil.example")));
        t.insert(&user("uuu4@evil.example"), (), Some(1000), 60);
        assert!(!t.contains(&user("uuu0@evil.example")), "then the oldest");
        for id in [
            "uuu2@evil.example",
            "uuu3@a.evil.example:8443",
            "uuu4@evil.example",
        ] {
            assert!(t.contains(&user(id)), "{id}");
        }
        assert!(
            t.contains(&victim),
            "another group's entry stays, even expired"
        );
        t.assert_consistent();
    }

    #[test]
    fn one_group_filling_its_quota_and_beyond_leaves_other_groups_intact() {
        let mut t = Grouped::with_caps(50, 200);
        let peers: Vec<_> = (0..40)
            .map(|i| user(&format!("user{i}@victim.example")))
            .collect();
        for (i, peer) in peers.iter().enumerate() {
            t.insert(peer, (), Some(100_000), i as i64);
        }
        for i in 0..500 {
            t.insert(
                &user(&format!("rrr{i}@evil.example")),
                (),
                Some(100_000),
                1000 + i,
            );
        }
        assert_eq!(t.len(), peers.len() + 50);
        assert!(peers.iter().all(|p| t.contains(p)));
        t.assert_consistent();
    }

    #[test]
    fn a_full_table_drops_an_expired_entry_anywhere_first() {
        let mut t = Grouped::with_caps(5, 6);
        t.insert(&user("vvv0@victim.example"), (), Some(20), 1);
        for i in 0..5 {
            t.insert(
                &user(&format!("eee{i}@evil.example")),
                (),
                Some(1000),
                2 + i,
            );
        }
        t.insert(&user("nnn0@new.example"), (), Some(1000), 30);
        assert!(!t.contains(&user("vvv0@victim.example")), "it had expired");
        assert_eq!(t.group_len("evil.example"), 5);
        assert_eq!(t.len(), 6);
        t.assert_consistent();
    }

    #[test]
    fn a_full_table_cuts_back_the_largest_group() {
        let mut t = Grouped::with_caps(5, 10);
        for i in 0..3 {
            t.insert(&user(&format!("vvv{i}@victim.example")), (), Some(1000), i);
        }
        for i in 0..5 {
            t.insert(
                &user(&format!("eee{i}@evil.example")),
                (),
                Some(1000),
                10 + i,
            );
        }
        for i in 0..5 {
            t.insert(
                &user(&format!("bbb{i}@bad.example")),
                (),
                Some(1000),
                20 + i,
            );
        }
        assert_eq!(t.len(), 10);
        // Past the total, the largest group gave way each time (on a tie,
        // the one that grew last), never the smaller victim group.
        assert_eq!(t.group_len("victim.example"), 3);
        assert_eq!(t.group_len("evil.example") + t.group_len("bad.example"), 7);
        assert!(
            t.group_len("evil.example")
                .abs_diff(t.group_len("bad.example"))
                <= 1
        );
        // The largest group lost its oldest entries.
        assert!(!t.contains(&user("eee0@evil.example")));
        assert!(t.contains(&user("eee4@evil.example")));
        t.insert(&user("nnn0@new.example"), (), Some(1000), 30);
        assert!(t.contains(&user("nnn0@new.example")));
        assert_eq!(t.group_len("victim.example"), 3);
        assert_eq!(t.len(), 10);
        t.assert_consistent();
    }

    #[test]
    fn eviction_never_changes_another_entrys_expiry() {
        let mut t = Grouped::with_caps(2, 3);
        t.insert(&user("aaa@one.example"), (), Some(100), 1);
        t.insert(&user("bbb@one.example"), (), Some(200), 2);
        t.insert(&user("ccc@two.example"), (), Some(300), 3);
        t.insert(&user("ddd@three.example"), (), Some(400), 4);
        assert!(!t.contains(&user("aaa@one.example")));
        assert_eq!(t.get(&user("bbb@one.example")), Some((&(), Some(200))));
        assert_eq!(t.get(&user("ccc@two.example")), Some((&(), Some(300))));
        t.assert_consistent();
    }
}
