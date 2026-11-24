//! Live-entry counters used to cap how much of the replay store one signer,
//! or one remote provider, may occupy.

use std::collections::BTreeMap;

/// Counts live entries and remembers when each expires, so the earliest
/// expiry (and therefore a truthful `Retry-After`) is cheap to find.
#[derive(Debug, Default)]
pub(super) struct Counter {
    total: usize,
    by_expiry: BTreeMap<i64, u32>,
}

impl Counter {
    pub(super) fn total(&self) -> usize {
        self.total
    }

    pub(super) fn add(&mut self, expires: i64) {
        self.total += 1;
        *self.by_expiry.entry(expires).or_insert(0) += 1;
    }

    /// Remove one entry expiring at `expires`. Returns whether the counter is
    /// now empty (so the caller can drop it).
    pub(super) fn remove(&mut self, expires: i64) -> bool {
        if let Some(n) = self.by_expiry.get_mut(&expires) {
            *n -= 1;
            if *n == 0 {
                self.by_expiry.remove(&expires);
            }
            self.total -= 1;
        }
        self.total == 0
    }

    /// When the earliest live entry expires.
    pub(super) fn earliest(&self) -> Option<i64> {
        self.by_expiry.keys().next().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracks_total_and_earliest() {
        let mut c = Counter::default();
        c.add(30);
        c.add(10);
        c.add(10);
        assert_eq!(c.total(), 3);
        assert_eq!(c.earliest(), Some(10));
        assert!(!c.remove(10));
        assert_eq!(c.earliest(), Some(10));
        assert!(!c.remove(10));
        assert_eq!(c.earliest(), Some(30));
        assert!(c.remove(30));
        assert_eq!(c.earliest(), None);
    }
}
