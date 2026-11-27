//! The work a message create does not wait for: making its `message`
//! entries for the users whose mode is `all` (docs/decisions/0023,
//! *Making entries*).
//!
//! Each piece runs in a task of its own, so it finishes whatever becomes of
//! the request that started it. At most [`SLOTS`] pieces run at once, the
//! rest waiting their turn in order, so however many `all` settings exist
//! the feed's background work holds a bounded share of the database.
//! Nothing is dropped: a piece that waits still runs. [`Background::flush`]
//! waits for every piece started so far (tests, and graceful shutdown).

use std::future::Future;
use std::sync::Arc;

use tokio::sync::{Semaphore, watch};

/// Pieces of work that run at once.
const SLOTS: usize = 4;

/// The feed's background work and how much of it is unfinished.
#[derive(Debug)]
pub struct Background {
    /// Pieces started and not yet finished.
    pending: watch::Sender<usize>,
    /// Turns at running.
    slots: Arc<Semaphore>,
}

impl Default for Background {
    fn default() -> Self {
        Self {
            pending: watch::Sender::new(0),
            slots: Arc::new(Semaphore::new(SLOTS)),
        }
    }
}

/// Counts a piece as unfinished until dropped, a panic's unwinding
/// included.
struct Unfinished(watch::Sender<usize>);

impl Drop for Unfinished {
    fn drop(&mut self) {
        self.0.send_modify(|n| *n = n.saturating_sub(1));
    }
}

impl Background {
    /// Run `work` in a task of its own when a slot is free. It counts as
    /// unfinished from this call on, so a [`Self::flush`] after it returns
    /// waits for it.
    pub fn spawn<F>(&self, work: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.pending.send_modify(|n| *n += 1);
        let unfinished = Unfinished(self.pending.clone());
        let slots = self.slots.clone();
        tokio::spawn(async move {
            let _unfinished = unfinished;
            match slots.acquire_owned().await {
                Ok(_slot) => work.await,
                // The semaphore is never closed.
                Err(e) => tracing::error!(error = %e, "notification background work not run"),
            }
        });
    }

    /// Wait until every piece started so far, and any started meanwhile,
    /// has finished.
    pub async fn flush(&self) {
        let mut idle = self.pending.subscribe();
        // `Err` only once the sender is gone, which `self` holds.
        let _ = idle.wait_for(|n| *n == 0).await;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[tokio::test]
    async fn flush_waits_for_every_piece_including_queued_ones() {
        let bg = Background::default();
        let done = Arc::new(AtomicUsize::new(0));
        let (open, gate) = watch::channel(false);
        for _ in 0..(3 * SLOTS) {
            let done = done.clone();
            let mut gate = gate.clone();
            bg.spawn(async move {
                let _ = gate.wait_for(|o| *o).await;
                done.fetch_add(1, Ordering::SeqCst);
            });
        }
        assert_eq!(*bg.pending.borrow(), 3 * SLOTS);
        open.send_replace(true);
        bg.flush().await;
        assert_eq!(done.load(Ordering::SeqCst), 3 * SLOTS);
        assert_eq!(*bg.pending.borrow(), 0);
    }

    #[tokio::test]
    async fn a_panicking_piece_still_counts_as_finished() {
        let bg = Background::default();
        bg.spawn(async { panic!("boom") });
        bg.flush().await;
        assert_eq!(*bg.pending.borrow(), 0);
    }

    #[tokio::test]
    async fn flush_with_nothing_started_returns_at_once() {
        Background::default().flush().await;
    }
}
