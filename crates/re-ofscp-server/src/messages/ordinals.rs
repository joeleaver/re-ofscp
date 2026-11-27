//! Message ordinals and the counts built on them, for exact unread counts
//! (§7.7: "MUST be exact", lost-conn/ofscp#41; docs/decisions/0021).
//!
//! Every message has `n`, its creation ordinal among its channel's
//! messages, and `author_n`, its ordinal among its author's messages there
//! (`Message.apos` finds it by that). The channel's log counts its messages
//! (`log.rs`) and each author's tally counts theirs (`tally.rs`). A create
//! takes all three under the channel's lock (`ops.rs`), so ordinals are
//! dense and in creation order, and a reader's unread count is
//! `(messages − marker.n) − (own tally − marker.own)` from a few point
//! lookups, however long the channel.
//!
//! This module settles what a create left unfinished (a create *pending*
//! on the log), numbers channels written before ordinals existed, and
//! reads counts that agree with each other.
//!
//! **Numbering existing channels (the backfill).** A log from before
//! ordinals has no `counted`, and a create refuses it (its compare-and-set
//! requires `counted == 1`; rhypedb never matches an absent field). The
//! first create, marker update or count that meets such a channel numbers
//! it under the channel's lock: every message in `seq` order gets `n` and
//! `author_n`, every author's tally is set, and only then is the log marked
//! counted, by a compare-and-set that also requires `last_seq` unchanged.
//! Each step writes values that depend only on the messages stored, so a
//! numbering cut short is redone from the start by the next one, writing
//! the same values.

use std::collections::BTreeMap;

use futures_util::stream::{self, StreamExt, TryStreamExt};
use ofscp_core::LocalId;
use serde::Deserialize;

use super::store::{author_position, position};
use super::{Messages, log, tally};
use crate::db::lookup::lookup;
use crate::db::{DbError, Ql};

/// Positions read per query while numbering a channel.
const NUMBER_BATCH: i64 = 100;
/// How often numbering starts over when a position was taken meanwhile.
const NUMBER_ATTEMPTS: usize = 4;
/// Channels settled at once by [`Messages::totals`].
const SETTLE_CONCURRENCY: usize = 4;

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

#[derive(Deserialize)]
struct NRow {
    message_id: String,
    #[serde(default)]
    n: Option<i64>,
}

/// A channel's message count and one reader's tally there, read so that
/// they agree: no create was part-way between them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Totals {
    /// Messages in the channel, tombstones included.
    pub messages: i64,
    /// Of those, the reader's.
    pub own: i64,
}

/// Where a read marker at a message stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarkPoint {
    /// The message.
    pub message_id: LocalId,
    /// Its creation ordinal.
    pub n: i64,
    /// How many of the reader's messages have an ordinal of at most `n`.
    pub own: i64,
}

impl Messages {
    /// Make `channel_id`'s counts settled: number its messages if it
    /// predates ordinals, and settle a create left pending. The caller
    /// holds the channel's lock, so no create of this process is part-way.
    pub(super) async fn settle_counts(&self, channel_id: &str) -> Result<(), DbError> {
        let Some(counts) = log::read_counts(self.store.db(), channel_id).await? else {
            // No log, or a closed one: nothing is counted there.
            return Ok(());
        };
        if let Some(p) = &counts.pending {
            self.settle_pending(channel_id, p).await?;
        }
        if counts.messages.is_none() {
            self.number(channel_id).await?;
        }
        Ok(())
    }

    /// Settle the create `p` pending on `channel_id`'s log: if its message
    /// was written, only clear it; if not, give back its author's ordinal
    /// (when it took one) and then its creation ordinal.
    pub(super) async fn settle_pending(
        &self,
        channel_id: &str,
        p: &log::Pending,
    ) -> Result<(), DbError> {
        let db = self.store.db();
        if self
            .store
            .message(channel_id, &p.message_id)
            .await?
            .is_some()
        {
            log::clear_pending(db, channel_id, &p.message_id).await?;
            return Ok(());
        }
        // The author's last ordinal is the create's exactly when no message
        // holds it: only the pending create takes one, and it is the last.
        let last = tally::get(db, channel_id, &p.author).await?;
        if last >= 1 && self.n_of(channel_id, &p.author, last).await?.is_none() {
            tally::give_back(db, channel_id, &p.author, last).await?;
        }
        log::give_back(db, channel_id, &p.message_id).await?;
        Ok(())
    }

    /// Number the messages of `channel_id`, whose log predates ordinals
    /// (see the module docs). The caller holds the channel's lock.
    async fn number(&self, channel_id: &str) -> Result<(), DbError> {
        let db = self.store.db();
        for _ in 0..NUMBER_ATTEMPTS {
            let Some(counts) = log::read_counts(db, channel_id).await? else {
                return Ok(());
            };
            if counts.messages.is_some() {
                return Ok(());
            }
            let mut n: i64 = 0;
            let mut tallies: BTreeMap<String, i64> = BTreeMap::new();
            let mut from = 1;
            while from <= counts.last_seq {
                let to = counts.last_seq.min(from + NUMBER_BATCH - 1);
                let keys: Vec<String> = (from..=to).map(|p| position(channel_id, p)).collect();
                let mut rows: Vec<OrdinalRow> =
                    lookup(db, "Message.filter(", ".pos == ", &keys).await?;
                rows.sort_by_key(|r| r.seq);
                for row in rows {
                    n += 1;
                    let author_n = tallies.entry(row.author.clone()).or_insert(0);
                    *author_n += 1;
                    if row.n != Some(n) || row.author_n != Some(*author_n) {
                        self.set_ordinals(channel_id, &row, n, *author_n).await?;
                    }
                }
                from = to + 1;
            }
            for (author, count) in &tallies {
                tally::set(db, channel_id, author, *count).await?;
            }
            if log::mark_counted(db, channel_id, counts.last_seq, n).await? {
                tracing::info!(channel = channel_id, messages = n, "numbered a channel");
                return Ok(());
            }
        }
        Err(DbError::Contended(format!(
            "channel log {channel_id}: positions kept being taken while numbering"
        )))
    }

    /// Give `row`'s message the ordinals `n` and `author_n`.
    async fn set_ordinals(
        &self,
        channel_id: &str,
        row: &OrdinalRow,
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
        self.store.db().write_one_object(&q).await.map(|_| ())
    }

    /// The creation ordinal of `author`'s `author_n`th message in
    /// `channel_id`, if it is written.
    async fn n_of(
        &self,
        channel_id: &str,
        author: &str,
        author_n: i64,
    ) -> Result<Option<i64>, DbError> {
        let q = Ql::new("Message.filter(.apos == ")
            .str(&author_position(channel_id, author, author_n))
            .raw(")");
        match self.store.db().fetch::<NRow>(&q).await?.into_iter().next() {
            None => Ok(None),
            Some(row) => row.data.n.map(Some).ok_or_else(|| {
                DbError::Decode(format!("message {}: apos without n", row.data.message_id))
            }),
        }
    }

    /// Where a read marker of `reader` at message `message_id` of
    /// `channel_id` stands: `None` if the channel holds no such message.
    /// Numbers the channel first if it predates ordinals. `own` is found by
    /// a binary search over the reader's ordinals, O(log) point lookups.
    pub async fn mark_point(
        &self,
        channel_id: &str,
        message_id: &str,
        reader: &str,
    ) -> Result<Option<MarkPoint>, DbError> {
        let db = self.store.db();
        let numbered = log::read_counts(db, channel_id)
            .await?
            .is_some_and(|c| c.messages.is_some());
        if !numbered {
            let _turn = self.locks.lock(channel_id).await;
            self.settle_counts(channel_id).await?;
        }
        let Some(message) = self.store.message(channel_id, message_id).await? else {
            return Ok(None);
        };
        let Some(n) = message.n else {
            // A channel deleted meanwhile is never numbered: no marker there.
            return match log::read_counts(db, channel_id).await? {
                None => Ok(None),
                Some(_) => Err(DbError::Decode(format!(
                    "message {}: no ordinal in a numbered channel",
                    message.id
                ))),
            };
        };
        // The reader's ordinals 1..=hi, in creation order; the answer is the
        // last whose message is at or before `n`. One not yet written is a
        // pending create, later than every written message.
        let (mut lo, mut hi) = (0, tally::get(db, channel_id, reader).await?);
        while lo < hi {
            let mid = lo + (hi - lo + 1) / 2;
            match self.n_of(channel_id, reader, mid).await? {
                Some(at) if at <= n => lo = mid,
                _ => hi = mid - 1,
            }
        }
        Ok(Some(MarkPoint {
            message_id: message.id,
            n,
            own: lo,
        }))
    }

    /// The [`Totals`] of each of `channel_ids` for `reader`, by channel id.
    ///
    /// Bounded: two batched reads of the logs around one batched read of
    /// the reader's tallies. A tally only changes while a create is pending
    /// on its channel's log, and every create moves `last_seq`, so where
    /// both log reads agree and show nothing pending, the tally between
    /// them agrees with the count. A channel where they do not (a create
    /// ran meanwhile, or one is pending, or the channel predates ordinals)
    /// is settled and read under its lock instead.
    pub async fn totals(
        &self,
        channel_ids: &[String],
        reader: &str,
    ) -> Result<BTreeMap<String, Totals>, DbError> {
        let db = self.store.db();
        let before = log::counts(db, channel_ids).await?;
        let tallies = tally::for_author(db, channel_ids, reader).await?;
        let after = log::counts(db, channel_ids).await?;
        let mut out = BTreeMap::new();
        let mut unsettled = Vec::new();
        for id in channel_ids {
            let agreed = match (before.get(id), after.get(id)) {
                // No open log: nothing was ever written there.
                (None, None) => Some(Totals::default()),
                (Some(a), Some(b)) if a == b => a.settled().map(|messages| Totals {
                    messages,
                    own: tallies.get(id).copied().unwrap_or(0),
                }),
                _ => None,
            };
            match agreed {
                Some(totals) => {
                    out.insert(id.clone(), totals);
                }
                None => unsettled.push(id.clone()),
            }
        }
        let settled: Vec<(String, Totals)> = stream::iter(unsettled)
            .map(|id| async move {
                let totals = self.totals_locked(&id, reader).await?;
                Ok::<_, DbError>((id, totals))
            })
            .buffer_unordered(SETTLE_CONCURRENCY)
            .try_collect()
            .await?;
        out.extend(settled);
        Ok(out)
    }

    /// [`Totals`] of `channel_id` for `reader`, settled and read under the
    /// channel's lock, so no create of this process is part-way.
    async fn totals_locked(&self, channel_id: &str, reader: &str) -> Result<Totals, DbError> {
        let db = self.store.db();
        let _turn = self.locks.lock(channel_id).await;
        self.settle_counts(channel_id).await?;
        let Some(counts) = log::read_counts(db, channel_id).await? else {
            return Ok(Totals::default());
        };
        let messages = counts.settled().ok_or_else(|| {
            DbError::Contended(format!(
                "channel log {channel_id}: counts unsettled under its lock"
            ))
        })?;
        Ok(Totals {
            messages,
            own: tally::get(db, channel_id, reader).await?,
        })
    }
}
