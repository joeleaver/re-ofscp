//! Feed entries in rhypedb (`NotificationFeed`, `Notification` in
//! `schema.rhype`; docs/decisions/0023).
//!
//! Each owner's entries are numbered by a compare-and-set counter
//! (`NotificationFeed.last_n`), and only the newest [`FEED_CAP`] positions
//! count: a create prunes what fell out of that window, and reads never
//! look below it. So a feed is read whole by one query bounded by
//! [`FEED_CAP`] rows (rhypedb has no ordering or counting), and sorted here.

use std::sync::Arc;

use serde::Deserialize;

use crate::db::{Db, DbError, Ql};
use crate::messages::locks::ChannelLocks;

/// Entries kept per user: the newest this many positions.
pub const FEED_CAP: i64 = 500;
/// How often a position is tried for while other writers keep winning.
/// Writers in this process take turns per owner, so this is met only by
/// writers in other processes.
const TAKE_ATTEMPTS: usize = 32;
/// The longest a batched write's query text may grow before it is split
/// (rhypedb takes at most 16 KiB of query).
const MAX_BATCH_TEXT: usize = 12 * 1024;

/// `Notification.kind` values (§10.1).
pub mod kind {
    /// The user is mentioned.
    pub const MENTION: &str = "mention";
    /// A reply to the user's message.
    pub const REPLY: &str = "reply";
    /// A new message where the user's mode is `all`.
    pub const MESSAGE: &str = "message";
}

/// A stored entry.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct StoredEntry {
    /// `ntf_…`.
    pub id: String,
    /// Its position in the owner's feed.
    pub n: i64,
    /// One of [`kind`].
    pub kind: String,
    /// The message that made it.
    pub message_id: String,
    /// That message's channel.
    pub channel_id: String,
    /// The channel's group.
    pub group_id: String,
    /// The message's canonical author.
    pub author: String,
    /// Unix seconds.
    pub created_at: i64,
    /// Unix seconds; 0 while unseen.
    pub seen_at: i64,
    /// Unix seconds; 0 while unread.
    pub read_at: i64,
}

/// A new entry, before it has a position.
#[derive(Debug, Clone)]
pub struct NewEntry<'a> {
    /// The local user it is for, canonical.
    pub owner: &'a str,
    /// One of [`kind`].
    pub kind: &'static str,
    /// The message that made it.
    pub message_id: &'a str,
    /// That message's channel.
    pub channel_id: &'a str,
    /// The channel's group.
    pub group_id: &'a str,
    /// The message's canonical author.
    pub author: &'a str,
    /// Unix seconds.
    pub now: i64,
}

#[derive(Deserialize)]
struct FeedRow {
    last_n: i64,
}

/// What [`FeedStore::mark`] sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mark {
    /// `seen_at`.
    Seen,
    /// `read_at`, and `seen_at` where it is unset.
    Read,
}

/// Storage for feed entries.
#[derive(Debug)]
pub struct FeedStore {
    db: Arc<Db>,
    /// Per-owner turns at taking positions, in this process.
    turns: ChannelLocks,
}

impl FeedStore {
    /// Entries stored in `db`.
    pub fn new(db: Arc<Db>) -> Self {
        Self {
            db,
            turns: ChannelLocks::default(),
        }
    }

    /// The last position handed out in `owner`'s feed (0 for none).
    pub async fn last(&self, owner: &str) -> Result<i64, DbError> {
        let q = Ql::new("NotificationFeed.filter(.owner == ")
            .str(owner)
            .raw(")");
        Ok(self
            .db
            .fetch::<FeedRow>(&q)
            .await?
            .into_iter()
            .next()
            .map_or(0, |r| r.data.last_n))
    }

    /// Take the next position of `owner`'s feed.
    async fn take(&self, owner: &str) -> Result<i64, DbError> {
        let _turn = self.turns.lock(owner).await;
        for _ in 0..TAKE_ATTEMPTS {
            let last = self.last(owner).await?;
            let next = last.saturating_add(1);
            let written = if last == 0 {
                let q = Ql::new("NotificationFeed.create({ owner: ")
                    .str(owner)
                    .raw(", last_n: 1 })");
                match self.db.execute(&q).await {
                    Ok(()) => true,
                    // Another process created it first: read it again.
                    Err(DbError::Conflict(_) | DbError::Contended(_)) => false,
                    Err(e) => return Err(e),
                }
            } else {
                let q = Ql::new("NotificationFeed.filter(.owner == ")
                    .str(owner)
                    .raw(" && .last_n == ")
                    .int(last)
                    .raw(").update({ last_n: ")
                    .int(next)
                    .raw(" })");
                !self
                    .db
                    .write_one_object(&q)
                    .await?
                    .into_objects()
                    .is_empty()
            };
            if written {
                return Ok(next);
            }
        }
        Err(DbError::Contended(format!(
            "notification feed of {owner}: no position after {TAKE_ATTEMPTS} attempts"
        )))
    }

    /// Store `entry` at the next position of its owner's feed, and prune
    /// what falls out of the kept window. `None` if the owner already has
    /// an entry for that message (at most one per user per message).
    pub async fn insert(&self, entry: &NewEntry<'_>) -> Result<Option<StoredEntry>, DbError> {
        let n = self.take(entry.owner).await?;
        let id = crate::db::doc::new_id("ntf_")?;
        let q = Ql::new("Notification.create({ id: ")
            .str(&id)
            .raw(", source_key: ")
            .str(&format!("{} {}", entry.owner, entry.message_id))
            .raw(", owner: ")
            .str(entry.owner)
            .raw(", n: ")
            .int(n)
            .raw(", kind: ")
            .str(entry.kind)
            .raw(", message_id: ")
            .str(entry.message_id)
            .raw(", channel_id: ")
            .str(entry.channel_id)
            .raw(", group_id: ")
            .str(entry.group_id)
            .raw(", author: ")
            .str(entry.author)
            .raw(", created_at: ")
            .int(entry.now)
            .raw(", seen_at: 0, read_at: 0 })");
        let stored = match self.db.write_one_object_as::<StoredEntry>(&q).await {
            Ok(rows) => rows
                .into_iter()
                .next()
                .map(|r| r.data)
                .ok_or_else(|| DbError::Decode("a create returned nothing".to_owned()))?,
            // The position stays a gap; it costs nothing.
            Err(DbError::Conflict(_)) => return Ok(None),
            Err(e) => return Err(e),
        };
        if n <= FEED_CAP {
            return Ok(Some(stored));
        }
        let prune = Ql::new("Notification.filter(.owner == ")
            .str(entry.owner)
            .raw(" && .n <= ")
            .int(n.saturating_sub(FEED_CAP))
            .raw(").delete()");
        // A failed prune leaves rows no read looks at; the next create's
        // prune takes them.
        if let Err(e) = self.db.execute(&prune).await {
            tracing::warn!(error = %e, "pruning a notification feed failed");
        }
        Ok(Some(stored))
    }

    /// Every entry in `owner`'s kept window, in no particular order.
    pub async fn entries(&self, owner: &str) -> Result<Vec<StoredEntry>, DbError> {
        let last = self.last(owner).await?;
        let q = Ql::new("Notification.filter(.owner == ")
            .str(owner)
            .raw(" && .n > ")
            .int(last.saturating_sub(FEED_CAP))
            .raw(").limit(")
            .int(FEED_CAP)
            .raw(")");
        Ok(self
            .db
            .fetch::<StoredEntry>(&q)
            .await?
            .into_iter()
            .map(|r| r.data)
            .collect())
    }

    /// Set `mark` at `now` on those of `owner`'s entries `ids` that lack
    /// it. Returns the entries changed, as they now stand.
    pub async fn mark(
        &self,
        owner: &str,
        ids: &[String],
        mark: Mark,
        now: i64,
    ) -> Result<Vec<StoredEntry>, DbError> {
        let mut changed = Vec::new();
        match mark {
            Mark::Seen => {
                changed.extend(self.batched(owner, ids, Guard::Unseen, now).await?);
            }
            Mark::Read => {
                // Unseen first: an entry seen meanwhile is skipped there and
                // taken by the second pass, which keeps its `seen_at`.
                changed.extend(self.batched(owner, ids, Guard::UnreadUnseen, now).await?);
                changed.extend(self.batched(owner, ids, Guard::UnreadSeen, now).await?);
            }
        }
        Ok(changed)
    }

    /// One guarded update over `ids`, split so no query outgrows
    /// [`MAX_BATCH_TEXT`]. Each row is written by a compare-and-set on its
    /// guard, so every row returned really changed.
    async fn batched(
        &self,
        owner: &str,
        ids: &[String],
        guard: Guard,
        now: i64,
    ) -> Result<Vec<StoredEntry>, DbError> {
        let mut out = Vec::new();
        let mut rest = ids;
        while !rest.is_empty() {
            let mut q = Ql::new("Notification.filter(.owner == ")
                .str(owner)
                .raw(guard.filter())
                .raw(" && (");
            let mut taken = 0;
            for (i, id) in rest.iter().enumerate() {
                if i > 0 && q.as_str().len() + 2 * id.len() + 64 > MAX_BATCH_TEXT {
                    break;
                }
                q = q
                    .raw(if i == 0 { ".id == " } else { " || .id == " })
                    .str(id);
                taken += 1;
            }
            q = q.raw(")).update({ ").raw(guard.sets()).int(now);
            if guard == Guard::UnreadUnseen {
                q = q.raw(", seen_at: ").int(now);
            }
            q = q.raw(" })");
            out.extend(
                self.db
                    .write_many::<StoredEntry>(&q)
                    .await?
                    .into_iter()
                    .map(|r| r.data),
            );
            rest = &rest[taken..];
        }
        Ok(out)
    }
}

/// Which rows a [`FeedStore::batched`] update may change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Guard {
    Unseen,
    UnreadUnseen,
    UnreadSeen,
}

impl Guard {
    fn filter(self) -> &'static str {
        match self {
            Guard::Unseen => " && .seen_at == 0",
            Guard::UnreadUnseen => " && .read_at == 0 && .seen_at == 0",
            Guard::UnreadSeen => " && .read_at == 0 && .seen_at != 0",
        }
    }

    fn sets(self) -> &'static str {
        match self {
            Guard::Unseen => "seen_at: ",
            Guard::UnreadUnseen | Guard::UnreadSeen => "read_at: ",
        }
    }
}

/// Remove every entry about the deleted channel `channel_id`. Idempotent.
pub async fn purge_channel(db: &Db, channel_id: &str) -> Result<(), DbError> {
    let q = Ql::new("Notification.filter(.channel_id == ")
        .str(channel_id)
        .raw(").delete()");
    db.execute(&q).await
}
