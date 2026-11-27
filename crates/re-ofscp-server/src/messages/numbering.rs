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
//!   numbers every channel once, then whatever a request hands it. It is
//!   not bounded (one pass over each channel), and nothing waits on it.
//! - A request (a create, a marker, a count) that meets a channel not yet
//!   numbered numbers it itself only if its log has handed out at most
//!   [`INLINE_LIMIT`] positions: at most `INLINE_LIMIT / BATCH` batched
//!   reads and `INLINE_LIMIT` writes, [`WRITES`] at a time. A longer
//!   channel is handed to the background task and the request answers
//!   `503` with `Retry-After` [`RETRY_AFTER_SECS`] ([`CountError::Numbering`]):
//!   an exact count is not known yet, and none is guessed.
//! - Numbering takes its own per-channel lock, never the channel's write
//!   lock, so edits, deletes and reactions in a channel being numbered go
//!   on. Numberings of one channel take turns; creates in it are refused
//!   until it is numbered (above), so no create runs beside one.
//! - An edit or a delete moves `last_seq` without adding a message, which
//!   fails the final compare-and-set. That costs only a read of the
//!   positions taken since, never a restart ([`Numbering`]), so the
//!   [`ATTEMPTS`] bound is met only by a channel whose positions are taken
//!   faster than one batch of point lookups.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use futures_util::stream::{self, StreamExt, TryStreamExt};
use serde::Deserialize;
use tokio::sync::Notify;

use super::ordinals::CountError;
use super::store::{author_position, position};
use super::{Messages, log, tally};
use crate::db::lookup::lookup;
use crate::db::{Db, DbError, Ql};

/// The most positions a request numbers itself; longer channels are left
/// to the background task.
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
/// Open logs read per page of a pass over every channel.
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
    /// itself when the channel is short, otherwise by handing it to the
    /// background task and answering [`CountError::Numbering`] (see the
    /// module docs for the bounds).
    pub(super) async fn number_for_request(
        &self,
        channel_id: &str,
        counts: &log::Counts,
    ) -> Result<(), CountError> {
        if counts.messages.is_some() {
            return Ok(());
        }
        if counts.last_seq > INLINE_LIMIT {
            self.numbering_queue.push(channel_id);
            return Err(CountError::Numbering(channel_id.to_owned()));
        }
        Ok(self.number(channel_id).await?)
    }

    /// Number `channel_id` if its log predates ordinals, to the end,
    /// under its numbering lock.
    pub async fn number(&self, channel_id: &str) -> Result<(), DbError> {
        let db = self.store.db();
        let _turn = self.numbering.lock(channel_id).await;
        let mut run = Numbering::new(channel_id);
        for _ in 0..ATTEMPTS {
            let Some(counts) = log::read_counts(db, channel_id).await? else {
                // Deleted meanwhile: nothing to count.
                return Ok(());
            };
            if counts.messages.is_some() {
                return Ok(());
            }
            run.scan(db, counts.last_seq).await?;
            if run.finish(db).await? {
                tracing::info!(
                    channel = channel_id,
                    messages = run.messages(),
                    "numbered a channel"
                );
                return Ok(());
            }
        }
        Err(DbError::Contended(format!(
            "channel log {channel_id}: positions kept being taken while numbering"
        )))
    }

    /// Number every channel whose log predates ordinals. Repeats its pass
    /// until one numbers nothing, since a log closed during a pass can
    /// shift another past it ([`log::open_page`]). A channel that fails is
    /// logged and left for a later request to hand over again. Returns how
    /// many channels it numbered.
    pub async fn number_all(&self) -> Result<usize, DbError> {
        let db = self.store.db();
        let mut total = 0;
        loop {
            let mut numbered = 0;
            let mut offset = 0;
            loop {
                let page = log::open_page(db, offset, PASS_PAGE).await?;
                for (channel_id, counts) in &page {
                    if counts.messages.is_some() {
                        continue;
                    }
                    match self.number(channel_id).await {
                        Ok(()) => numbered += 1,
                        Err(e) => {
                            tracing::warn!(error = %e, channel = %channel_id, "numbering a channel failed");
                        }
                    }
                }
                if (page.len() as u64) < PASS_PAGE {
                    break;
                }
                offset += PASS_PAGE;
            }
            total += numbered;
            if numbered == 0 {
                return Ok(total);
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
            self.numbering_queue.wake.notified().await;
            for channel_id in self.numbering_queue.take() {
                if let Err(e) = self.number(&channel_id).await {
                    tracing::warn!(error = %e, channel = %channel_id, "numbering a channel failed");
                }
            }
        }
    }
}
