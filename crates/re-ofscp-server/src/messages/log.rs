//! A channel's timeline counter (`ChannelLog` in `schema.rhype`), and its
//! closing when the channel or its group is deleted.
//!
//! Positions are taken by a compare-and-set on `last_seq` that also
//! requires the log to be open (rhypedb #59 makes a filtered update a real
//! compare-and-set), so once a log is closed no write can take a position
//! in it. A write that took its position just before the close may still
//! land after the close's purge; the sweeper's second purge, a grace period
//! later, removes it, and the writer itself re-checks the log after writing
//! (`ops.rs`). See docs/decisions/0017.

use serde::Deserialize;

use crate::db::lookup::lookup;
use crate::db::{Db, DbError, Ql};

/// `ChannelLog.state` values.
mod state {
    /// Positions may be taken.
    pub const OPEN: &str = "open";
    /// The channel was deleted: no position may be taken.
    pub const CLOSED: &str = "closed";
}

/// How often a position is tried for while other writers keep winning.
/// Writers in this process take turns under a per-channel lock, so this
/// is met only by writers in other processes.
const TAKE_ATTEMPTS: usize = 32;

#[derive(Deserialize)]
struct LogRow {
    channel_id: String,
    last_seq: i64,
    state: String,
    purged_at: i64,
}

/// What a log says about its channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogState {
    /// The channel has no log yet: nothing was ever written to it.
    Absent,
    /// Open, with positions `1..=last` handed out.
    Open {
        /// The last position handed out.
        last: i64,
    },
    /// Closed: the channel was deleted.
    Closed,
}

impl LogState {
    /// The last position handed out, as far as readers are concerned.
    pub fn last(self) -> i64 {
        match self {
            LogState::Open { last } => last,
            LogState::Absent | LogState::Closed => 0,
        }
    }
}

fn by_channel(channel_id: &str) -> Ql {
    Ql::new("ChannelLog.filter(.channel_id == ").str(channel_id)
}

/// The log of `channel_id`.
pub async fn read(db: &Db, channel_id: &str) -> Result<LogState, DbError> {
    let q = by_channel(channel_id).raw(")");
    Ok(match db.fetch::<LogRow>(&q).await?.into_iter().next() {
        None => LogState::Absent,
        Some(r) if r.data.state == state::OPEN => LogState::Open {
            last: r.data.last_seq,
        },
        Some(_) => LogState::Closed,
    })
}

/// The last position handed out in each of `channel_ids`' open logs, by
/// channel id. A channel with no log, or a closed one, is left out: it
/// has nothing to read (as [`LogState::last`] is `0` for those).
pub async fn last_positions(
    db: &Db,
    channel_ids: &[String],
) -> Result<std::collections::BTreeMap<String, i64>, DbError> {
    let rows: Vec<LogRow> =
        lookup(db, "ChannelLog.filter(", ".channel_id == ", channel_ids).await?;
    Ok(rows
        .into_iter()
        .filter(|r| r.state == state::OPEN)
        .map(|r| (r.channel_id, r.last_seq))
        .collect())
}

/// Create the open log of `channel_id` if it has none. Returns the log as
/// it then stands (a concurrent creator, or a close, may have won).
pub async fn open(db: &Db, group_id: &str, channel_id: &str) -> Result<LogState, DbError> {
    match read(db, channel_id).await? {
        LogState::Absent => {}
        other => return Ok(other),
    }
    let q = Ql::new("ChannelLog.create({ channel_id: ")
        .str(channel_id)
        .raw(", group_id: ")
        .str(group_id)
        .raw(", last_seq: 0, state: ")
        .str(state::OPEN)
        .raw(", purged_at: 0 })");
    match db.execute(&q).await {
        Ok(()) | Err(DbError::Conflict(_)) => read(db, channel_id).await,
        Err(e) => Err(e),
    }
}

/// Take the next position of the open log of `channel_id`: `None` if the
/// log is absent or closed.
pub async fn take(db: &Db, channel_id: &str) -> Result<Option<i64>, DbError> {
    for _ in 0..TAKE_ATTEMPTS {
        let LogState::Open { last } = read(db, channel_id).await? else {
            return Ok(None);
        };
        let next = last.saturating_add(1);
        let q = by_channel(channel_id)
            .raw(" && .state == ")
            .str(state::OPEN)
            .raw(" && .last_seq == ")
            .int(last)
            .raw(").update({ last_seq: ")
            .int(next)
            .raw(" })");
        if !db.write_one_object(&q).await?.into_objects().is_empty() {
            return Ok(Some(next));
        }
    }
    Err(DbError::Contended(format!(
        "channel log {channel_id}: no position after {TAKE_ATTEMPTS} attempts"
    )))
}

/// Close the log of `channel_id`, creating it closed if the channel never
/// had one, so that nothing can be written to it from now on.
pub async fn close_channel(db: &Db, group_id: &str, channel_id: &str) -> Result<(), DbError> {
    let close = by_channel(channel_id)
        .raw(").update({ state: ")
        .str(state::CLOSED)
        .raw(" })");
    if !db.write_one_object(&close).await?.into_objects().is_empty() {
        return Ok(());
    }
    let create = Ql::new("ChannelLog.create({ channel_id: ")
        .str(channel_id)
        .raw(", group_id: ")
        .str(group_id)
        .raw(", last_seq: 0, state: ")
        .str(state::CLOSED)
        .raw(", purged_at: 0 })");
    match db.execute(&create).await {
        Ok(()) => Ok(()),
        // A writer opened it meanwhile: close that.
        Err(DbError::Conflict(_)) => db.write_one_object(&close).await.map(|_| ()),
        Err(e) => Err(e),
    }
}

/// Close every log of `group_id`'s channels. A channel of the group with no
/// log yet gets none: a writer that opens one afterwards finds the channel
/// gone when it re-checks, and closes the log itself (`ops.rs`).
pub async fn close_group(db: &Db, group_id: &str) -> Result<(), DbError> {
    let q = Ql::new("ChannelLog.filter(.group_id == ")
        .str(group_id)
        .raw(" && .state == ")
        .str(state::OPEN)
        .raw(").update({ state: ")
        .str(state::CLOSED)
        .raw(" })");
    db.execute(&q).await
}

/// A closed log the sweeper has work for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosedLog {
    /// The deleted channel.
    pub channel_id: String,
    /// When its rows were first purged (unix seconds), if they were.
    pub purged_at: Option<i64>,
}

/// Up to `limit` closed logs that are not yet purged, or whose first purge
/// was before `cutoff` (unix seconds).
pub async fn closed(db: &Db, cutoff: i64, limit: usize) -> Result<Vec<ClosedLog>, DbError> {
    let q = Ql::new("ChannelLog.filter(.state == ")
        .str(state::CLOSED)
        .raw(" && (.purged_at == 0 || .purged_at < ")
        .int(cutoff)
        .raw(")).limit(")
        .uint(limit as u64)
        .raw(")");
    Ok(db
        .fetch::<LogRow>(&q)
        .await?
        .into_iter()
        .map(|r| ClosedLog {
            channel_id: r.data.channel_id,
            purged_at: (r.data.purged_at > 0).then_some(r.data.purged_at),
        })
        .collect())
}

/// Record the first purge of the closed log of `channel_id` at `now`.
pub async fn mark_purged(db: &Db, channel_id: &str, now: i64) -> Result<(), DbError> {
    let q = by_channel(channel_id)
        .raw(" && .state == ")
        .str(state::CLOSED)
        .raw(" && .purged_at == 0).update({ purged_at: ")
        .int(now.max(1))
        .raw(" })");
    db.write_one_object(&q).await.map(|_| ())
}

/// Delete the closed log of `channel_id`, its rows purged twice.
pub async fn delete_closed(db: &Db, channel_id: &str) -> Result<(), DbError> {
    let q = by_channel(channel_id)
        .raw(" && .state == ")
        .str(state::CLOSED)
        .raw(").delete()");
    db.write_one_object(&q).await.map(|_| ())
}
