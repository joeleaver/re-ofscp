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
//!
//! The log also counts the channel's messages, for exact unread counts
//! (§7.7, lost-conn/ofscp#41; docs/decisions/0022): a create takes its
//! position and its creation ordinal together ([`take_create`]), and is
//! *pending* on the log until its message is written. `ordinals.rs`
//! settles a pending create, and `numbering.rs` numbers logs from before
//! ordinals.

use std::collections::BTreeMap;

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

/// The `counted` value of a log whose messages all have ordinals.
const COUNTED: i64 = 1;

#[derive(Deserialize)]
struct LogRow {
    channel_id: String,
    last_seq: i64,
    state: String,
    purged_at: i64,
    // Absent on logs from before ordinals: rhypedb reads an absent field
    // as missing, and no filter comparison matches it.
    #[serde(default)]
    counted: Option<i64>,
    #[serde(default)]
    message_count: Option<i64>,
    #[serde(default)]
    pending_id: Option<String>,
    #[serde(default)]
    pending_author: Option<String>,
}

impl LogRow {
    /// What the log says for counting: its counts if open, or that it is
    /// closed.
    fn standing(&self) -> Standing {
        match self.counts() {
            Some(c) => Standing::Open(c),
            None => Standing::Closed,
        }
    }

    /// The counts of an open log; `None` for a closed one.
    fn counts(&self) -> Option<Counts> {
        if self.state != state::OPEN {
            return None;
        }
        let pending = match (self.pending_id.as_deref(), self.pending_author.as_deref()) {
            (Some(id), Some(author)) if !id.is_empty() => Some(Pending {
                message_id: id.to_owned(),
                author: author.to_owned(),
            }),
            _ => None,
        };
        Some(Counts {
            last_seq: self.last_seq,
            messages: (self.counted == Some(COUNTED)).then(|| self.message_count.unwrap_or(0)),
            pending,
        })
    }
}

/// A create that took its position and ordinal and is not yet settled:
/// its message may or may not have been written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    /// The id the message is written under.
    pub message_id: String,
    /// Its canonical author.
    pub author: String,
}

/// What an open log says about its channel's messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Counts {
    /// The last position handed out.
    pub last_seq: i64,
    /// How many messages the channel holds, tombstones included (a pending
    /// create among them); `None` until its messages are numbered.
    pub messages: Option<i64>,
    /// The create in flight, if any.
    pub pending: Option<Pending>,
}

impl Counts {
    /// The message count, if the log is numbered and nothing is pending:
    /// only then does it agree with the messages and tallies stored.
    pub fn settled(&self) -> Option<i64> {
        match self.pending {
            None => self.messages,
            Some(_) => None,
        }
    }
}

/// What a channel's log, where it has one, says for counting. A channel
/// with no log at all holds no messages, or held some and was deleted
/// (its closed log since removed by the sweeper).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Standing {
    /// Open: the channel takes messages, and these are its counts.
    Open(Counts),
    /// Closed: the channel was deleted, its row perhaps not yet. Nothing
    /// there is counted or readable any more.
    Closed,
}

/// What [`take_create`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateTake {
    /// The create holds position `seq` and creation ordinal `n`, and is
    /// pending on the log.
    Taken {
        /// Its timeline position.
        seq: i64,
        /// Its creation ordinal (`Message.n`).
        n: i64,
    },
    /// The log is absent or closed: the channel takes no messages.
    Closed,
    /// The log is not numbered, or another create is pending: settle it
    /// first (`ordinals.rs`).
    Unsettled,
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

/// The [`Standing`] of each of `channel_ids`' logs, by channel id, in a
/// batch of point lookups. A channel with no log is left out.
pub async fn counts(
    db: &Db,
    channel_ids: &[String],
) -> Result<BTreeMap<String, Standing>, DbError> {
    let rows: Vec<LogRow> =
        lookup(db, "ChannelLog.filter(", ".channel_id == ", channel_ids).await?;
    Ok(rows
        .into_iter()
        .map(|r| {
            let standing = r.standing();
            (r.channel_id, standing)
        })
        .collect())
}

/// The [`Standing`] of `channel_id`'s log: `None` if it has none.
pub async fn standing(db: &Db, channel_id: &str) -> Result<Option<Standing>, DbError> {
    let q = by_channel(channel_id).raw(")");
    Ok(db
        .fetch::<LogRow>(&q)
        .await?
        .into_iter()
        .next()
        .map(|r| r.data.standing()))
}

/// The counts of `channel_id`'s log, if it is open.
pub async fn read_counts(db: &Db, channel_id: &str) -> Result<Option<Counts>, DbError> {
    Ok(match standing(db, channel_id).await? {
        Some(Standing::Open(c)) => Some(c),
        Some(Standing::Closed) | None => None,
    })
}

/// Up to `limit` open logs after skipping the first `offset`, with their
/// counts: one page of a pass over every channel. rhypedb returns them in
/// no set order, and a log closed meanwhile can shift a later one into a
/// page already read, so the numbering pass that uses this repeats until
/// a pass finds nothing to do (`numbering.rs`).
pub async fn open_page(db: &Db, offset: u64, limit: u64) -> Result<Vec<(String, Counts)>, DbError> {
    let q = Ql::new("ChannelLog.filter(.state == ")
        .str(state::OPEN)
        .raw(").offset(")
        .uint(offset)
        .raw(").limit(")
        .uint(limit)
        .raw(")");
    Ok(db
        .fetch::<LogRow>(&q)
        .await?
        .into_iter()
        .filter_map(|r| r.data.counts().map(|c| (r.data.channel_id, c)))
        .collect())
}

/// A new log's count fields: numbered, empty, nothing pending.
fn new_counts(q: Ql) -> Ql {
    q.raw(", counted: ")
        .int(COUNTED)
        .raw(", message_count: 0, pending_id: \"\", pending_author: \"\" })")
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
        .raw(", purged_at: 0");
    let q = new_counts(q);
    match db.execute(&q).await {
        Ok(()) | Err(DbError::Conflict(_)) => read(db, channel_id).await,
        Err(e) => Err(e),
    }
}

/// Take the next position of the open log of `channel_id` for an edit or
/// a delete: `None` if the log is absent or closed. A create takes its
/// position with [`take_create`].
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

/// Take the next position and the next creation ordinal of the open,
/// numbered log of `channel_id` for a create of message `message_id` by
/// `author`, in one compare-and-set that leaves the create pending on the
/// log. The caller then writes the message and settles the create: it
/// clears the pending create ([`clear_pending`]) once the message is
/// written, or gives the ordinal back ([`give_back`]) when it is not.
pub async fn take_create(
    db: &Db,
    channel_id: &str,
    message_id: &str,
    author: &str,
) -> Result<CreateTake, DbError> {
    for _ in 0..TAKE_ATTEMPTS {
        let Some(c) = read_counts(db, channel_id).await? else {
            return Ok(CreateTake::Closed);
        };
        let (Some(count), None) = (c.messages, &c.pending) else {
            return Ok(CreateTake::Unsettled);
        };
        let (seq, n) = (c.last_seq.saturating_add(1), count.saturating_add(1));
        let q = by_channel(channel_id)
            .raw(" && .state == ")
            .str(state::OPEN)
            .raw(" && .counted == ")
            .int(COUNTED)
            .raw(" && .pending_id == \"\" && .last_seq == ")
            .int(c.last_seq)
            .raw(" && .message_count == ")
            .int(count)
            .raw(").update({ last_seq: ")
            .int(seq)
            .raw(", message_count: ")
            .int(n)
            .raw(", pending_id: ")
            .str(message_id)
            .raw(", pending_author: ")
            .str(author)
            .raw(" })");
        if !db.write_one_object(&q).await?.into_objects().is_empty() {
            return Ok(CreateTake::Taken { seq, n });
        }
    }
    Err(DbError::Contended(format!(
        "channel log {channel_id}: no position after {TAKE_ATTEMPTS} attempts"
    )))
}

/// Settle the pending create of `message_id`, whose message is written.
/// Returns whether it was still pending.
pub async fn clear_pending(db: &Db, channel_id: &str, message_id: &str) -> Result<bool, DbError> {
    let q = by_channel(channel_id)
        .raw(" && .pending_id == ")
        .str(message_id)
        .raw(").update({ pending_id: \"\", pending_author: \"\" })");
    Ok(!db.write_one_object(&q).await?.into_objects().is_empty())
}

/// Settle the pending create of `message_id`, whose message was not
/// written, giving its ordinal back: the count drops by one. Its author's
/// tally must be given back first (`ordinals.rs`), since once this returns
/// nothing records that the create was pending. Returns whether it was
/// still pending. Works on a closed log too.
pub async fn give_back(db: &Db, channel_id: &str, message_id: &str) -> Result<bool, DbError> {
    for _ in 0..TAKE_ATTEMPTS {
        let q = by_channel(channel_id).raw(")");
        let Some(row) = db.fetch::<LogRow>(&q).await?.into_iter().next() else {
            return Ok(false);
        };
        if row.data.pending_id.as_deref() != Some(message_id) {
            return Ok(false);
        }
        let count = row.data.message_count.unwrap_or(0);
        let q = by_channel(channel_id)
            .raw(" && .pending_id == ")
            .str(message_id)
            .raw(" && .message_count == ")
            .int(count)
            .raw(").update({ message_count: ")
            .int(count.saturating_sub(1).max(0))
            .raw(", pending_id: \"\", pending_author: \"\" })");
        if !db.write_one_object(&q).await?.into_objects().is_empty() {
            return Ok(true);
        }
    }
    Err(DbError::Contended(format!(
        "channel log {channel_id}: its pending create kept changing"
    )))
}

/// Mark the open log of `channel_id` numbered, holding `messages`
/// messages, if no position was taken after `last_seq`, the last one the
/// numbering read. Returns whether it applied.
///
/// A position taken meanwhile may be a create's, whose message the count
/// must include, so this cannot ignore it. It does not undo the
/// numbering, though: a position at or before `last_seq` never gains a
/// message later (a message is written only at the position its create
/// took, and an edit or a delete moves `last_seq` without writing one), so
/// the numbering reads only the positions after `last_seq` and tries again
/// (`numbering.rs`).
pub async fn mark_counted(
    db: &Db,
    channel_id: &str,
    last_seq: i64,
    messages: i64,
) -> Result<bool, DbError> {
    let q = by_channel(channel_id)
        .raw(" && .state == ")
        .str(state::OPEN)
        .raw(" && .last_seq == ")
        .int(last_seq)
        .raw(").update({ counted: ")
        .int(COUNTED)
        .raw(", message_count: ")
        .int(messages)
        .raw(", pending_id: \"\", pending_author: \"\" })");
    Ok(!db.write_one_object(&q).await?.into_objects().is_empty())
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
        .raw(", purged_at: 0");
    let create = new_counts(create);
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
