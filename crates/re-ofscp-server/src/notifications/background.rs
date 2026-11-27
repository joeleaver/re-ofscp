//! The work a message create does not wait for: making its `message`
//! entries for the users whose mode is `all` (docs/decisions/0023,
//! *The background queue*).
//!
//! The queue holds message ids, not messages, coalesced per channel: each
//! channel with work has one entry holding its ids in arrival order. At most
//! [`Limits::slots`] drainer tasks run, each taking a *turn*: the channel at
//! the front of the ready list, and up to [`Limits::batch`] of its ids. A
//! channel whose ids outlast its turn goes to the back of the list, so
//! channels take turns round-robin and a flood in one delays another by at
//! most one turn per channel ahead of it. A channel is in at most one turn at
//! a time, so its ids are handled in order.
//!
//! The queue is bounded: at most [`Limits::per_channel`] ids wait per
//! channel and at most [`Limits::total`] in all (with at most
//! `slots × batch` more in the turns being run). Nothing is dropped when a
//! bound is reached: [`Background::enqueue`] waits for room instead, which
//! holds up the create that called it (back-pressure on whoever posts
//! faster than the queue drains), and logs that it waited. What is lost is
//! what is still queued when the process stops: [`Background::flush`]
//! waits for every id enqueued so far, and graceful shutdown gives it a
//! bounded time, logging how many messages it leaves behind.

use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tokio::sync::{Notify, watch};

/// The queue's bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Drainer tasks that run at once.
    pub slots: usize,
    /// Most ids of one channel handled in one turn.
    pub batch: usize,
    /// Most ids that wait for one channel.
    pub per_channel: usize,
    /// Most ids that wait in all.
    pub total: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            slots: 4,
            batch: 64,
            per_channel: 256,
            total: 8192,
        }
    }
}

/// One created message whose `message` entries are still to be made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    /// Its channel.
    pub channel_id: String,
    /// The channel's group.
    pub group_id: String,
    /// The message.
    pub message_id: String,
}

/// One turn's work: ids of one channel's messages, in arrival order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Batch {
    /// The channel.
    pub channel_id: String,
    /// The channel's group.
    pub group_id: String,
    /// The messages.
    pub message_ids: Vec<String>,
}

/// What a turn runs. It handles its own failures (logging them).
pub type Run = Arc<dyn Fn(Batch) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

/// One channel's queued ids.
#[derive(Debug)]
struct Channel {
    group_id: String,
    ids: VecDeque<String>,
    /// Whether a turn holds it now (it is then not in `ready`).
    running: bool,
}

#[derive(Debug, Default)]
struct State {
    channels: BTreeMap<String, Channel>,
    /// Channels with queued ids and no turn, in the order they take one.
    ready: VecDeque<String>,
    /// Ids queued in `channels` (not those taken by a turn).
    queued: usize,
    /// Drainer tasks running.
    drainers: usize,
    /// Live [`Hold`]s.
    held: usize,
}

impl State {
    fn has_room(&self, channel_id: &str, limits: &Limits) -> bool {
        let here = self.channels.get(channel_id).map_or(0, |c| c.ids.len());
        self.queued < limits.total && here < limits.per_channel
    }

    fn push(&mut self, job: Job) {
        match self.channels.get_mut(&job.channel_id) {
            Some(c) => c.ids.push_back(job.message_id),
            None => {
                self.ready.push_back(job.channel_id.clone());
                self.channels.insert(
                    job.channel_id,
                    Channel {
                        group_id: job.group_id,
                        ids: VecDeque::from([job.message_id]),
                        running: false,
                    },
                );
            }
        }
        self.queued += 1;
    }

    /// How many more drainers to start now, counted as running.
    fn drainers_wanted(&mut self, limits: &Limits) -> usize {
        if self.held > 0 {
            return 0;
        }
        let n = limits
            .slots
            .saturating_sub(self.drainers)
            .min(self.ready.len());
        self.drainers += n;
        n
    }
}

struct Shared {
    limits: Limits,
    run: Run,
    state: Mutex<State>,
    /// Woken when a turn takes ids out of the queue.
    room: Notify,
    /// Ids enqueued and not yet handled.
    unfinished: watch::Sender<usize>,
}

impl Shared {
    /// The state. Nothing panics while holding it, so a poisoned lock
    /// still holds consistent state.
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Start `n` drainers, already counted in `drainers`.
    fn start(self: &Arc<Self>, n: usize) {
        if n == 0 {
            return;
        }
        let Ok(rt) = tokio::runtime::Handle::try_current() else {
            self.lock().drainers -= n;
            tracing::error!("no runtime to make notification entries on");
            return;
        };
        for _ in 0..n {
            rt.spawn(drain(self.clone()));
        }
    }

    /// The next turn, or `None` (the calling drainer then stops, and is no
    /// longer counted) when no channel is ready or the queue is held.
    fn take_turn(self: &Arc<Self>) -> Option<Turn> {
        let mut s = self.lock();
        let (channel_id, group_id, message_ids) = loop {
            let next = if s.held > 0 {
                None
            } else {
                s.ready.pop_front()
            };
            let Some(channel_id) = next else {
                s.drainers -= 1;
                return None;
            };
            // Every ready channel has an entry; one without is skipped.
            let Some(c) = s.channels.get_mut(&channel_id) else {
                continue;
            };
            c.running = true;
            let n = self.limits.batch.max(1).min(c.ids.len());
            let ids: Vec<String> = c.ids.drain(..n).collect();
            let group_id = c.group_id.clone();
            s.queued -= n;
            break (channel_id, group_id, ids);
        };
        drop(s);
        self.room.notify_waiters();
        Some(Turn {
            shared: self.clone(),
            batch: Batch {
                channel_id,
                group_id,
                message_ids,
            },
        })
    }
}

/// A channel's turn: on drop (a panic's unwinding included) its ids count
/// as handled, and the channel goes to the back of the ready list if more
/// of its ids wait, or leaves the queue.
struct Turn {
    shared: Arc<Shared>,
    batch: Batch,
}

impl Drop for Turn {
    fn drop(&mut self) {
        let mut s = self.shared.lock();
        let id = &self.batch.channel_id;
        let more = s.channels.get_mut(id).is_some_and(|c| {
            c.running = false;
            !c.ids.is_empty()
        });
        if more {
            s.ready.push_back(id.clone());
        } else {
            s.channels.remove(id);
        }
        let n = self.batch.message_ids.len();
        self.shared
            .unfinished
            .send_modify(|u| *u = u.saturating_sub(n));
    }
}

/// A drainer's place among the running ones. Dropped by a panic, it gives
/// the place up and starts a replacement if work is waiting.
struct Drainer(Option<Arc<Shared>>);

impl Drop for Drainer {
    fn drop(&mut self) {
        if let Some(shared) = self.0.take() {
            let n = {
                let mut s = shared.lock();
                s.drainers -= 1;
                s.drainers_wanted(&shared.limits)
            };
            shared.start(n);
        }
    }
}

/// Take turns until none is left.
async fn drain(shared: Arc<Shared>) {
    let mut place = Drainer(Some(shared.clone()));
    loop {
        let Some(turn) = shared.take_turn() else {
            // `take_turn` gave the place up.
            place.0 = None;
            return;
        };
        (shared.run)(turn.batch.clone()).await;
    }
}

/// While one lives, no new turn starts; turns already running finish.
/// For tests that need work to stay queued.
pub struct Hold(Arc<Shared>);

impl Drop for Hold {
    fn drop(&mut self) {
        let n = {
            let mut s = self.0.lock();
            s.held -= 1;
            s.drainers_wanted(&self.0.limits)
        };
        self.0.start(n);
    }
}

/// The feed's background queue.
pub struct Background {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for Background {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Background")
            .field("limits", &self.shared.limits)
            .field("unfinished", &self.unfinished())
            .finish_non_exhaustive()
    }
}

impl Background {
    /// A queue whose turns run `run`, with the default [`Limits`].
    pub fn new(run: Run) -> Self {
        Self::with_limits(run, Limits::default())
    }

    /// A queue whose turns run `run`, within `limits`.
    pub fn with_limits(run: Run, limits: Limits) -> Self {
        Self {
            shared: Arc::new(Shared {
                limits,
                run,
                state: Mutex::new(State::default()),
                room: Notify::new(),
                unfinished: watch::Sender::new(0),
            }),
        }
    }

    /// Queue `job`, waiting for room while its channel's or the whole
    /// queue's bound is reached. It counts as unfinished once this
    /// returns, so a [`Self::flush`] after that waits for it.
    pub async fn enqueue(&self, job: Job) {
        let shared = &self.shared;
        let mut waited = false;
        loop {
            let room = shared.room.notified();
            tokio::pin!(room);
            // Registered before the check, so room made after it wakes us.
            room.as_mut().enable();
            if let Some(n) = Self::try_push(shared, &job) {
                shared.start(n);
                return;
            }
            if !waited {
                waited = true;
                tracing::warn!(
                    channel = %job.channel_id,
                    "notification queue full; the create waits for room"
                );
            }
            room.await;
        }
    }

    /// Queue `job` if there is room for it: then the drainers to start.
    fn try_push(shared: &Shared, job: &Job) -> Option<usize> {
        let mut s = shared.lock();
        if !s.has_room(&job.channel_id, &shared.limits) {
            return None;
        }
        s.push(job.clone());
        shared.unfinished.send_modify(|u| *u += 1);
        Some(s.drainers_wanted(&shared.limits))
    }

    /// Ids enqueued and not yet handled.
    pub fn unfinished(&self) -> usize {
        *self.shared.unfinished.borrow()
    }

    /// Start no new turn until the returned [`Hold`] is dropped.
    pub fn hold(&self) -> Hold {
        self.shared.lock().held += 1;
        Hold(self.shared.clone())
    }

    /// Wait until every id enqueued so far, and any enqueued meanwhile,
    /// has been handled.
    pub async fn flush(&self) {
        let mut idle = self.shared.unfinished.subscribe();
        // `Err` only once the sender is gone, which `self` holds.
        let _ = idle.wait_for(|n| *n == 0).await;
    }
}

#[cfg(test)]
#[path = "background_tests.rs"]
mod tests;
