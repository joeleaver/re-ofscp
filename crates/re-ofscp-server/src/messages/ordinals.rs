//! Message ordinals and the counts built on them, for exact unread counts
//! (§7.7: "MUST be exact", lost-conn/ofscp#41; docs/decisions/0022).
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
//! on the log) and reads counts that agree with each other. Channels
//! written before ordinals existed are numbered by `numbering.rs`.
//!
//! **Deleted channels.** Deleting a channel or its group closes the
//! channel's logs before it removes the channel rows (`groups/store.rs`),
//! so a reader can still list a channel whose log is closed. Nothing there
//! is counted or readable any more: [`Messages::totals`] reports it as
//! [`ChannelTotals::Closed`], and the read markers leave it out.

use std::collections::BTreeMap;

use futures_util::stream::{self, StreamExt, TryStreamExt};
use ofscp_core::LocalId;
use serde::Deserialize;

use super::store::author_position;
use super::{Messages, log, tally};
use crate::db::{DbError, Ql};

/// Channels settled at once by [`Messages::totals`].
const SETTLE_CONCURRENCY: usize = 4;

/// Why counts could not be read.
#[derive(Debug, thiserror::Error)]
pub enum CountError {
    /// The database failed.
    #[error(transparent)]
    Db(#[from] DbError),
    /// The channel predates ordinals and is too long to number within a
    /// request; the background task is numbering it (`503` with
    /// `Retry-After`, `numbering.rs`).
    #[error("channel {0} is being numbered")]
    Numbering(String),
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

/// What a channel's log says for one reader's counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelTotals {
    /// The log is open: these are the exact totals.
    Counted(Totals),
    /// The channel has no log. Either nothing was ever written there (the
    /// totals are zero), or it was deleted and its closed log since
    /// removed; a reader who holds a marker there knows it was written to,
    /// so for them it is the latter.
    NoLog,
    /// The log is closed: the channel was deleted, its row perhaps not yet.
    Closed,
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
    /// predates ordinals (`numbering.rs`), and settle a create left
    /// pending. The caller holds the channel's lock, so no create of this
    /// process is part-way.
    pub(super) async fn settle_counts(&self, channel_id: &str) -> Result<(), CountError> {
        let Some(counts) = log::read_counts(self.store.db(), channel_id).await? else {
            // No log, or a closed one: nothing is counted there.
            return Ok(());
        };
        if let Some(p) = &counts.pending {
            self.settle_pending(channel_id, p).await?;
        }
        self.number_for_request(channel_id, &counts).await
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
    /// `channel_id` stands: `None` if the channel holds no such message,
    /// or its log is not open (a channel being deleted takes no new
    /// markers; one set while the close lands is purged with the channel). Numbers the channel first if it predates ordinals. `own`
    /// is found by a binary search over the reader's ordinals, O(log)
    /// point lookups.
    pub async fn mark_point(
        &self,
        channel_id: &str,
        message_id: &str,
        reader: &str,
    ) -> Result<Option<MarkPoint>, CountError> {
        let db = self.store.db();
        let Some(counts) = log::read_counts(db, channel_id).await? else {
            return Ok(None);
        };
        if counts.messages.is_none() {
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
                ))
                .into()),
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

    /// The [`ChannelTotals`] of each of `channel_ids` for `reader`, by
    /// channel id.
    ///
    /// Bounded: two batched reads of the logs around one batched read of
    /// the reader's tallies. A tally only changes while a create is pending
    /// on its channel's log, and every create moves `last_seq`, so where
    /// both log reads agree and show nothing pending, the tally between
    /// them agrees with the count. A log closed by either read is
    /// [`ChannelTotals::Closed`] (a closed log never opens again). A
    /// channel where the reads do not agree (a create ran meanwhile, or one
    /// is pending, or the channel predates ordinals) is settled and read
    /// under its lock instead, within the bounds `numbering.rs` gives.
    pub async fn totals(
        &self,
        channel_ids: &[String],
        reader: &str,
    ) -> Result<BTreeMap<String, ChannelTotals>, CountError> {
        let db = self.store.db();
        let before = log::counts(db, channel_ids).await?;
        let tallies = tally::for_author(db, channel_ids, reader).await?;
        let after = log::counts(db, channel_ids).await?;
        let mut out = BTreeMap::new();
        let mut unsettled = Vec::new();
        for id in channel_ids {
            let agreed = match (before.get(id), after.get(id)) {
                (Some(log::Standing::Closed), _) | (_, Some(log::Standing::Closed)) => {
                    Some(ChannelTotals::Closed)
                }
                (None, None) => Some(ChannelTotals::NoLog),
                (Some(log::Standing::Open(a)), Some(log::Standing::Open(b))) if a == b => {
                    a.settled().map(|messages| {
                        ChannelTotals::Counted(Totals {
                            messages,
                            own: tallies.get(id).copied().unwrap_or(0),
                        })
                    })
                }
                _ => None,
            };
            match agreed {
                Some(totals) => {
                    out.insert(id.clone(), totals);
                }
                None => unsettled.push(id.clone()),
            }
        }
        let settled: Vec<(String, ChannelTotals)> = stream::iter(unsettled)
            .map(|id| async move {
                let totals = self.totals_locked(&id, reader).await?;
                Ok::<_, CountError>((id, totals))
            })
            .buffer_unordered(SETTLE_CONCURRENCY)
            .try_collect()
            .await?;
        out.extend(settled);
        Ok(out)
    }

    /// [`ChannelTotals`] of `channel_id` for `reader`, settled and read
    /// under the channel's lock, so no create of this process is part-way.
    async fn totals_locked(
        &self,
        channel_id: &str,
        reader: &str,
    ) -> Result<ChannelTotals, CountError> {
        let db = self.store.db();
        let _turn = self.locks.lock(channel_id).await;
        self.settle_counts(channel_id).await?;
        let counts = match log::standing(db, channel_id).await? {
            None => return Ok(ChannelTotals::NoLog),
            Some(log::Standing::Closed) => return Ok(ChannelTotals::Closed),
            Some(log::Standing::Open(counts)) => counts,
        };
        let messages = counts.settled().ok_or_else(|| {
            DbError::Contended(format!(
                "channel log {channel_id}: counts unsettled under its lock"
            ))
        })?;
        Ok(ChannelTotals::Counted(Totals {
            messages,
            own: tally::get(db, channel_id, reader).await?,
        }))
    }
}
