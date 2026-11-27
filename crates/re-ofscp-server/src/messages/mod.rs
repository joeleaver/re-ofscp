//! Channel messages (spec §5.3, §7.1, §7.2): the message log, its REST
//! endpoints, reactions, and what live delivery and resume read from it.
//! The design is docs/decisions/0017-messages.md.
//!
//! * `store.rs`, `store_reactions.rs`, `log.rs`, `tally.rs`: rows in
//!   rhypedb.
//! * `ordinals.rs`: message ordinals and exact counts for unread counts
//!   (§7.7; docs/decisions/0021), and numbering channels from before them.
//! * `validate.rs`, `sanitize.rs`: checking bodies before storing them.
//! * `ops.rs`, `reactions.rs`: the operations, with §7.1's order of checks.
//! * `pager.rs`: paging over timeline, reply and reaction positions.
//! * `routes.rs`: the REST endpoints.
//! * `fanout.rs`: the seam live delivery plugs into.
//! * `timeline.rs`: replaying the timeline after a resume cursor.
//! * `typing.rs`: typing indicators.

use std::sync::Arc;
use std::time::Duration;

use ofscp_core::Authority;
use ofscp_core::wire::MessageType;

use crate::db::{Db, DbError};
use crate::groups::Groups;
use crate::signing::Clock;

pub mod fanout;
mod locks;
pub mod log;
pub mod model;
mod ops;
pub mod ordinals;
pub mod pager;
mod reactions;
pub mod routes;
pub mod sanitize;
pub mod store;
mod store_reactions;
pub mod tally;
mod timeline;
mod typing;
pub mod uploads;
pub mod validate;

pub use fanout::{Fanout, Live, Origin};
use locks::ChannelLocks;
pub use ops::{Created, Deleted, MessageError, channel_message, message_deleted};
pub use reactions::Added;
use store::MessageStore;
pub use timeline::{MAX_REPLAY, MessageTimeline};
use uploads::Uploads;

/// How long the author of a chat message may edit it (§7.1: providers
/// choose). Articles have no limit.
pub const MESSAGE_EDIT_WINDOW: Duration = Duration::from_secs(60 * 60);
/// How long the author of a memo may edit it.
pub const MEMO_EDIT_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);
/// How often the sweeper purges deleted channels' messages.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(60);
/// How long after a deleted channel's first purge its second one runs,
/// catching a write that took its position before the close. Far longer
/// than any request takes.
pub const PURGE_GRACE: Duration = Duration::from_secs(15 * 60);
/// Closed channel logs the sweeper handles per batch.
const SWEEP_BATCH: usize = 100;

/// The edit window of a new message of `kind`: `None` is unlimited.
pub fn edit_window(kind: &MessageType) -> Option<Duration> {
    match kind {
        MessageType::Article => None,
        MessageType::Memo => Some(MEMO_EDIT_WINDOW),
        _ => Some(MESSAGE_EDIT_WINDOW),
    }
}

/// Channel messages.
pub struct Messages {
    store: MessageStore,
    groups: Arc<Groups>,
    uploads: Arc<dyn Uploads>,
    fanout: Arc<dyn Fanout>,
    clock: Arc<dyn Clock>,
    home: Authority,
    locks: ChannelLocks,
}

impl std::fmt::Debug for Messages {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Messages")
            .field("home", &self.home)
            .finish_non_exhaustive()
    }
}

impl Messages {
    /// The messages of `groups`' channels, stored in `db`, attachments
    /// checked against `uploads`, live events handed to `fanout`.
    pub fn new(
        db: Arc<Db>,
        groups: Arc<Groups>,
        uploads: Arc<dyn Uploads>,
        fanout: Arc<dyn Fanout>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            store: MessageStore::new(db),
            home: groups.home().clone(),
            groups,
            uploads,
            fanout,
            clock,
            locks: ChannelLocks::default(),
        }
    }

    /// The storage.
    pub fn store(&self) -> &MessageStore {
        &self.store
    }

    /// Now, in unix seconds.
    fn now(&self) -> i64 {
        self.clock.now().unix_timestamp()
    }

    /// One sweeper pass at `now` (unix seconds): purge the rows of deleted
    /// channels (their logs closed), authors' tallies and readers' markers
    /// included, and a [`PURGE_GRACE`] later purge them again and drop the
    /// log. Returns how many logs it handled.
    pub async fn sweep(&self, now: i64) -> Result<usize, DbError> {
        let db = self.store.db();
        let cutoff = now.saturating_sub(PURGE_GRACE.as_secs() as i64);
        let mut handled = 0;
        loop {
            let batch = log::closed(db, cutoff, SWEEP_BATCH).await?;
            let full = batch.len() == SWEEP_BATCH;
            for closed in batch {
                self.store.purge_channel(&closed.channel_id).await?;
                // Readers' markers there go too (decision 0021); a marker
                // write racing the first purge is caught by the second.
                crate::read_markers::store::MarkerStore::purge_scope(db, &closed.channel_id)
                    .await?;
                match closed.purged_at {
                    None => log::mark_purged(db, &closed.channel_id, now).await?,
                    Some(_) => log::delete_closed(db, &closed.channel_id).await?,
                }
                handled += 1;
            }
            if !full {
                return Ok(handled);
            }
        }
    }

    /// Run [`Messages::sweep`] now and every [`SWEEP_INTERVAL`] until the
    /// task is dropped.
    pub async fn sweep_forever(self: Arc<Self>) {
        let mut tick = tokio::time::interval(SWEEP_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            match self.sweep(self.now()).await {
                Ok(0) => {}
                Ok(n) => tracing::info!(logs = n, "purged deleted channels' messages"),
                Err(e) => tracing::warn!(error = %e, "purging deleted channels' messages failed"),
            }
        }
    }
}
