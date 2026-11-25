//! The per-target cap on requests in flight (docs/decisions/0006).
//!
//! Without it, a few hosts that stall every response until the timeout
//! could hold all of the process-wide slots and starve requests to everyone
//! else. Targets are grouped by registrable domain, so subdomains and ports
//! of one host share a cap. A request over the cap fails at once rather
//! than queueing behind the stalled ones.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// Requests in flight per target group.
#[derive(Debug)]
pub struct PerTarget {
    counts: Mutex<HashMap<String, usize>>,
    cap: usize,
}

impl PerTarget {
    /// At most `cap` (at least one) requests in flight per group.
    pub fn new(cap: usize) -> Self {
        Self {
            counts: Mutex::new(HashMap::new()),
            cap: cap.max(1),
        }
    }

    fn counts(&self) -> MutexGuard<'_, HashMap<String, usize>> {
        self.counts.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Take a slot for `group`, or `None` when it already has `cap` requests
    /// in flight. The slot is released when the returned guard drops; it
    /// owns a handle to the table, so it can move into a spawned task.
    pub fn try_acquire(self: &Arc<Self>, group: String) -> Option<TargetSlot> {
        let mut counts = self.counts();
        let count = counts.entry(group.clone()).or_insert(0);
        if *count >= self.cap {
            return None;
        }
        *count += 1;
        Some(TargetSlot {
            owner: Arc::clone(self),
            group,
        })
    }

    /// Requests in flight for `group`.
    #[cfg(test)]
    fn in_flight(&self, group: &str) -> usize {
        self.counts().get(group).copied().unwrap_or(0)
    }
}

/// One request in flight to a group. Dropping it frees the slot; a group
/// with none left is forgotten, so the table holds only groups in use.
#[derive(Debug)]
pub struct TargetSlot {
    owner: Arc<PerTarget>,
    group: String,
}

impl Drop for TargetSlot {
    fn drop(&mut self) {
        let mut counts = self.owner.counts();
        if let Some(count) = counts.get_mut(&self.group) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&self.group);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cap_is_per_group_and_slots_are_released() {
        let t = Arc::new(PerTarget::new(2));
        let a1 = t.try_acquire("a.example".to_owned()).unwrap();
        let _a2 = t.try_acquire("a.example".to_owned()).unwrap();
        assert!(t.try_acquire("a.example".to_owned()).is_none());
        let _b = t.try_acquire("b.example".to_owned()).unwrap();
        drop(a1);
        assert_eq!(t.in_flight("a.example"), 1);
        assert!(t.try_acquire("a.example".to_owned()).is_some());
    }

    #[test]
    fn idle_groups_are_forgotten() {
        let t = Arc::new(PerTarget::new(1));
        drop(t.try_acquire("a.example".to_owned()));
        assert!(t.counts().is_empty());
    }
}
