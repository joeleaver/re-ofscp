//! One async lock per channel, so that this process takes a channel's
//! positions, commits and fans out its events one writer at a time: live
//! events then leave in timeline order (§7.1 *Delivery, ordering*).
//!
//! The map is keyed by any string: the notification feed (decision 0023)
//! uses one keyed by user, for turns at a user's feed positions and
//! settings.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};

use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

/// Above this many entries, dead ones are swept on the next lock.
const SWEEP_ABOVE: usize = 1024;

/// The per-channel locks. An entry lives while someone holds or waits for
/// its lock.
#[derive(Debug, Default)]
pub struct ChannelLocks {
    locks: Mutex<HashMap<String, Weak<AsyncMutex<()>>>>,
}

impl ChannelLocks {
    /// Wait for, and take, `channel_id`'s lock.
    pub async fn lock(&self, channel_id: &str) -> OwnedMutexGuard<()> {
        let lock = {
            let mut map = self.locks.lock().unwrap_or_else(|p| p.into_inner());
            if map.len() > SWEEP_ABOVE {
                map.retain(|_, w| w.strong_count() > 0);
            }
            match map.get(channel_id).and_then(Weak::upgrade) {
                Some(l) => l,
                None => {
                    let l = Arc::new(AsyncMutex::new(()));
                    map.insert(channel_id.to_owned(), Arc::downgrade(&l));
                    l
                }
            }
        };
        lock.lock_owned().await
    }

    /// How many entries the map holds (tests).
    #[cfg(test)]
    fn len(&self) -> usize {
        self.locks.lock().unwrap_or_else(|p| p.into_inner()).len()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn one_writer_per_channel_and_dead_entries_are_swept() {
        let locks = Arc::new(ChannelLocks::default());
        let held = locks.lock("chn_a").await;
        // Another channel is not blocked.
        drop(locks.lock("chn_b").await);
        let waiter = {
            let locks = locks.clone();
            tokio::spawn(async move { drop(locks.lock("chn_a").await) })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiter.is_finished());
        drop(held);
        waiter.await.unwrap();
        for i in 0..=SWEEP_ABOVE {
            drop(locks.lock(&format!("chn_{i}")).await);
        }
        drop(locks.lock("chn_last").await);
        // The sweep ran when the map passed the bound, leaving only the
        // entries made after it.
        assert!(locks.len() < 8, "{}", locks.len());
    }
}
