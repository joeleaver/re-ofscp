//! Numbering channels written before message ordinals existed (the
//! backfill for exact unread counts, §7.7; docs/decisions/0022 *Existing
//! data*).
//!
//! A log from before ordinals has no `counted`, and a create refuses it
//! (its compare-and-set requires `counted == 1`; rhypedb never matches an
//! absent field). Numbering gives every message there, in `seq` order, its
//! `n`, `author_n` and `apos`, sets every author's tally, and only then
//! marks the log counted ([`log::mark_counted`]). Every value written
//! depends only on the messages stored, so a numbering cut short is redone
//! by the next one, writing the same values (and skipping the messages
//! that already hold them).
//!
//! **Where it runs, and its bounds.**
//! - A background task started with the server ([`Messages::number_forever`])
//!   numbers every channel once ([`Messages::number_all`]), then whatever
//!   a request hands it. Between the channels of that first pass it
//!   numbers what requests handed it meanwhile, so a channel a request is
//!   waiting on waits for the channel being numbered and for the others
//!   handed over by then (each numbered to the end, once, in no promised
//!   order), never for the rest of the pass. It is not bounded (one pass over each channel), and no
//!   request waits on it: a request answers `503` and is retried.
//! - A request (a create, a marker update, a count) that meets channels
//!   not yet numbered numbers them itself only within its
//!   [`InlineBudget`]: [`INLINE_LIMIT`] positions over every channel it
//!   meets, so at most `INLINE_LIMIT / BATCH` batched reads (plus one per
//!   channel) and `INLINE_LIMIT` writes, [`WRITES`] at a time. A channel
//!   past what is left of the budget is handed to the background task and
//!   the request answers `503` with `Retry-After` [`RETRY_AFTER_SECS`]
//!   ([`CountError::Numbering`]): an exact count is not known yet, and
//!   none is guessed.
//! - Every numbering of a channel takes the channel's numbering lock, so
//!   numberings of one channel take turns. The background task takes only
//!   that lock, never the channel's write lock, so edits, deletes and
//!   reactions in a long channel go on while it is numbered. A request
//!   numbers under the channel's write lock as well (it first settles a
//!   pending create, which needs that lock), so edits, deletes and
//!   reactions there wait for it, within the budget above. Creates in a
//!   channel are refused until it is numbered (a create's compare-and-set
//!   requires `counted == 1`), so no create runs beside a numbering.
//! - An edit or a delete moves `last_seq` without adding a message, which
//!   fails the final compare-and-set. That costs only a read of the
//!   positions taken since, never a restart ([`Numbering`]), so the
//!   [`ATTEMPTS`] bound is met only by a channel whose positions are taken
//!   faster than one batch of point lookups.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use futures_util::stream::{self, StreamExt, TryStreamExt};
use serde::Deserialize;
use tokio::sync::Notify;

use super::ordinals::CountError;
use super::store::{author_position, position};
use super::{Messages, log, tally};
use crate::db::lookup::lookup;
use crate::db::{Db, DbError, Ql};

/// The most positions one request numbers itself, over every channel it
/// meets ([`InlineBudget`]); the rest are left to the background task.
pub const INLINE_LIMIT: i64 = 1_000;
/// `Retry-After` while a channel is being numbered in the background.
pub const RETRY_AFTER_SECS: u64 = 5;
/// Positions read per batch of point lookups.
const BATCH: i64 = 100;
/// Messages given their ordinals at once.
const WRITES: usize = 16;
/// How often a numbering re-reads the positions taken since its last read
/// before giving up (`503`); each attempt reads only those positions.
const ATTEMPTS: usize = 32;
/// The most open logs a pass over every channel numbers from one read
/// ([`Messages::number_all`]).
const PASS_PAGE: u64 = 100;

#[derive(Deserialize)]
struct OrdinalRow {
    message_id: String,
    seq: i64,
    author: String,
    #[serde(default)]
    n: Option<i64>,
    #[serde(default)]
    author_n: Option<i64>,
}

/// One numbering of a channel, a step at a time: [`Messages`] drives it,
/// and tests drive the steps to put writes between them.
///
/// It reads positions `1..=through` once each, across however many
/// [`Numbering::scan`]s, keeping the count and each author's tally in
/// memory. A message is never written at a position already read (see
/// [`log::mark_counted`]), so what it has counted stays right when
/// `last_seq` moves on, and the next scan reads only the new positions.
#[derive(Debug)]
pub struct Numbering {
    channel_id: String,
    /// The last position read.
    through: i64,
    /// Messages counted so far.
    n: i64,
    /// Each author's messages counted so far.
    tallies: BTreeMap<String, i64>,
    /// Authors whose tally changed since it was last written.
    dirty: BTreeSet<String>,
    /// Positions read, over every scan (tests).
    positions_read: i64,
}

impl Numbering {
    /// A numbering of `channel_id`, nothing read yet.
    pub fn new(channel_id: &str) -> Self {
        Self {
            channel_id: channel_id.to_owned(),
            through: 0,
            n: 0,
            tallies: BTreeMap::new(),
            dirty: BTreeSet::new(),
            positions_read: 0,
        }
    }

    /// How many positions every scan so far has read together.
    pub fn positions_read(&self) -> i64 {
        self.positions_read
    }

    /// Read the positions after the last one read, through `last_seq`, in
    /// batches, and give each message there its ordinals.
    pub async fn scan(&mut self, db: &Db, last_seq: i64) -> Result<(), DbError> {
        while self.through < last_seq {
            let from = self.through + 1;
            let to = last_seq.min(self.through + BATCH);
            let keys: Vec<String> = (from..=to).map(|p| position(&self.channel_id, p)).collect();
            let mut rows: Vec<OrdinalRow> =
                lookup(db, "Message.filter(", ".pos == ", &keys).await?;
            rows.sort_by_key(|r| r.seq);
            let mut writes = Vec::new();
            for row in rows {
                self.n += 1;
                let author_n = self.tallies.entry(row.author.clone()).or_insert(0);
                *author_n += 1;
                self.dirty.insert(row.author.clone());
                if row.n != Some(self.n) || row.author_n != Some(*author_n) {
                    writes.push((row, self.n, *author_n));
                }
            }
            let channel_id = self.channel_id.as_str();
            stream::iter(writes)
                .map(|(row, n, author_n)| set_ordinals(db, channel_id, row, n, author_n))
                .buffer_unordered(WRITES)
                .try_collect::<Vec<()>>()
                .await?;
            self.positions_read += to - from + 1;
            self.through = to;
        }
        Ok(())
    }

    /// Write the tallies that changed and mark the log counted, if no
    /// position was taken after the last one read. Returns whether it
    /// applied; if not, [`Numbering::scan`] the new positions and finish
    /// again.
    pub async fn finish(&mut self, db: &Db) -> Result<bool, DbError> {
        for author in std::mem::take(&mut self.dirty) {
            let count = self.tallies.get(&author).copied().unwrap_or(0);
            tally::set(db, &self.channel_id, &author, count).await?;
        }
        log::mark_counted(db, &self.channel_id, self.through, self.n).await
    }

    /// Messages counted so far.
    pub fn messages(&self) -> i64 {
        self.n
    }
}

/// Give `row`'s message the ordinals `n` and `author_n`.
async fn set_ordinals(
    db: &Db,
    channel_id: &str,
    row: OrdinalRow,
    n: i64,
    author_n: i64,
) -> Result<(), DbError> {
    let q = Ql::new("Message.filter(.message_id == ")
        .str(&row.message_id)
        .raw(").update({ n: ")
        .int(n)
        .raw(", author_n: ")
        .int(author_n)
        .raw(", apos: ")
        .str(&author_position(channel_id, &row.author, author_n))
        .raw(" })");
    db.write_one_object(&q).await.map(|_| ())
}

/// What one request may still number itself, in positions: [`INLINE_LIMIT`]
/// over every channel it meets (module docs). The channels a request
/// settles at once share it.
#[derive(Debug)]
pub struct InlineBudget {
    left: AtomicI64,
}

impl InlineBudget {
    /// A request's whole budget.
    pub fn new() -> Self {
        Self {
            left: AtomicI64::new(INLINE_LIMIT),
        }
    }

    /// Take `positions` from the budget if that many are left. Returns
    /// whether it took them.
    fn take(&self, positions: i64) -> bool {
        self.left
            .try_update(Ordering::AcqRel, Ordering::Acquire, |left| {
                (positions <= left).then_some(left - positions)
            })
            .is_ok()
    }
}

impl Default for InlineBudget {
    fn default() -> Self {
        Self::new()
    }
}

/// Channels handed to the background task, each once until it takes them.
#[derive(Debug, Default)]
pub(super) struct Queue {
    channels: Mutex<BTreeSet<String>>,
    wake: Notify,
}

impl Queue {
    /// Hand `channel_id` to the background task.
    fn push(&self, channel_id: &str) {
        let added = self
            .channels
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(channel_id.to_owned());
        if added {
            self.wake.notify_one();
        }
    }

    /// Everything handed over so far.
    fn take(&self) -> BTreeSet<String> {
        std::mem::take(&mut *self.channels.lock().unwrap_or_else(|p| p.into_inner()))
    }
}

impl Messages {
    /// Number `channel_id` for a request, if its log predates ordinals:
    /// itself when its positions fit what is left of the request's
    /// `budget`, otherwise by handing it to the background task and
    /// answering [`CountError::Numbering`] (see the module docs for the
    /// bounds).
    pub(super) async fn number_for_request(
        &self,
        channel_id: &str,
        counts: &log::Counts,
        budget: &InlineBudget,
    ) -> Result<(), CountError> {
        if counts.messages.is_some() {
            return Ok(());
        }
        if !budget.take(counts.last_seq) {
            self.numbering_queue.push(channel_id);
            return Err(CountError::Numbering(channel_id.to_owned()));
        }
        self.number(channel_id).await?;
        Ok(())
    }

    /// Number `channel_id` if its log predates ordinals, to the end,
    /// under its numbering lock. Returns whether this call numbered it
    /// (`false`: it was numbered already, or is gone).
    pub async fn number(&self, channel_id: &str) -> Result<bool, DbError> {
        let db = self.store.db();
        let _turn = self.numbering.lock(channel_id).await;
        let mut run = Numbering::new(channel_id);
        for _ in 0..ATTEMPTS {
            let Some(counts) = log::read_counts(db, channel_id).await? else {
                // Deleted meanwhile: nothing to count.
                return Ok(false);
            };
            if counts.messages.is_some() {
                return Ok(false);
            }
            run.scan(db, counts.last_seq).await?;
            if run.finish(db).await? {
                tracing::info!(
                    channel = channel_id,
                    messages = run.messages(),
                    "numbered a channel"
                );
                return Ok(true);
            }
        }
        Err(DbError::Contended(format!(
            "channel log {channel_id}: positions kept being taken while numbering"
        )))
    }

    /// Number every channel whose log predates ordinals, in one pass over
    /// the open logs, numbering what requests hand over between channels.
    /// A channel that fails is logged and left for a later request to hand
    /// over again. Returns how many channels the pass numbered itself,
    /// leaving out those numbered from the queue between them.
    ///
    /// rhypedb returns rows in no set order and has no ordered paging, so
    /// the pass reads key ranges rather than offsets ([`log::open_range`]):
    /// a read of the open logs with `after < channel_id <= through` that
    /// returns at most [`PASS_PAGE`] of them returned all of them, and the
    /// pass numbers those and goes on to the range after `through`. A read
    /// that comes back full narrows `through` to the middle of what it
    /// returned (strictly fewer logs in range) and reads again, keeping the
    /// bound it narrowed to come back to. The ranges cover every channel id
    /// once, each read whole, so a log missed is one closed or opened since
    /// its range was read: a closed one needs no numbering, and every log
    /// opened since ordinals is counted from the start. Nothing open from
    /// before ordinals is skipped, however logs close meanwhile.
    pub async fn number_all(&self) -> Result<usize, DbError> {
        let db = self.store.db();
        let mut numbered = 0;
        let mut after = String::new();
        let mut through: Option<String> = None;
        // Upper bounds narrowed away, the innermost last; `None` is no bound.
        let mut bounds: Vec<Option<String>> = Vec::new();
        loop {
            let page = log::open_range(db, &after, through.as_deref(), PASS_PAGE + 1).await?;
            if page.len() as u64 > PASS_PAGE {
                let mut ids: Vec<&str> = page.iter().map(|(c, _)| c.as_str()).collect();
                ids.sort_unstable();
                // At least half of what was read lies above the new bound.
                let middle = ids[ids.len() / 2 - 1].to_owned();
                bounds.push(through.replace(middle));
                continue;
            }
            for (channel_id, counts) in &page {
                if counts.messages.is_some() {
                    continue;
                }
                self.drain_queue().await;
                match self.number(channel_id).await {
                    Ok(true) => numbered += 1,
                    Ok(false) => {}
                    Err(e) => {
                        tracing::warn!(error = %e, channel = %channel_id, "numbering a channel failed");
                    }
                }
            }
            match through {
                None => return Ok(numbered),
                Some(read) => {
                    after = read;
                    through = bounds.pop().flatten();
                }
            }
        }
    }

    /// Number every channel handed over so far.
    async fn drain_queue(&self) {
        for channel_id in self.numbering_queue.take() {
            if let Err(e) = self.number(&channel_id).await.map(drop) {
                tracing::warn!(error = %e, channel = %channel_id, "numbering a channel failed");
            }
        }
    }

    /// The background numbering task: [`Messages::number_all`] once, then
    /// every channel a request hands over, until the task is dropped.
    pub async fn number_forever(self: Arc<Self>) {
        match self.number_all().await {
            Ok(0) => {}
            Ok(n) => tracing::info!(channels = n, "numbered channels from before ordinals"),
            Err(e) => tracing::warn!(error = %e, "numbering channels from before ordinals failed"),
        }
        loop {
            // A hand-over after the pass's last drain left a wake-up behind.
            self.drain_queue().await;
            self.numbering_queue.wake.notified().await;
        }
    }
}
