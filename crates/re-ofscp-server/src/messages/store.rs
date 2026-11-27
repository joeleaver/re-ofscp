//! Messages and timeline events in rhypedb (`Message`, `TimelineEvent` in
//! `schema.rhype`). Every query goes through [`Ql`]. Reactions are in
//! `store_reactions.rs`, the timeline counter in `log.rs`.

use std::sync::Arc;

use ofscp_core::wire::MessageType;
use ofscp_core::{Actor, LocalId};
use serde::Deserialize;

use super::model::{MessageDoc, StoredMessage};
use crate::db::doc::{json, new_id};
use crate::db::lookup::lookup;
use crate::db::{Db, DbError, Ql};
use crate::timefmt;

/// `TimelineEvent.kind` values.
pub mod event_kind {
    /// An edit.
    pub const UPDATED: &str = "updated";
    /// A delete.
    pub const DELETED: &str = "deleted";
}

/// A timeline position's key: `"{scope}:{n}"`.
pub(super) fn position(scope: &str, n: i64) -> String {
    format!("{scope}:{n}")
}

/// The `n` of a position key of `scope`.
pub(super) fn position_n(scope: &str, key: &str) -> Option<i64> {
    key.strip_prefix(scope)?.strip_prefix(':')?.parse().ok()
}

#[derive(Deserialize)]
struct MessageRow {
    message_id: String,
    channel_id: String,
    group_id: String,
    seq: i64,
    client_key: String,
    author: String,
    kind: String,
    parent_id: String,
    reply_pos: String,
    reply_seq: i64,
    reaction_seq: i64,
    doc: String,
    created_at: String,
    edit_until: i64,
    edited_at: i64,
    revision: i64,
    deleted_at: i64,
}

impl MessageRow {
    fn decode(self) -> Result<StoredMessage, DbError> {
        let bad = |what: &str| DbError::Decode(format!("message {}: bad {what}", self.message_id));
        let id = LocalId::new(&self.message_id).map_err(|_| bad("id"))?;
        let parent_id = match self.parent_id.as_str() {
            "" => None,
            p => Some(LocalId::new(p).map_err(|_| bad("parent_id"))?),
        };
        let client_message_id = client_message_id(&self.client_key, &self.channel_id, &self.author);
        let reply_n = match &parent_id {
            Some(p) => position_n(p.as_str(), &self.reply_pos),
            None => None,
        };
        Ok(StoredMessage {
            author: Actor::parse_canonical(&self.author).map_err(|_| bad("author"))?,
            kind: MessageType::from(self.kind.as_str()),
            doc: serde_json::from_str::<MessageDoc>(&self.doc).map_err(|_| bad("doc"))?,
            edit_until: (self.edit_until > 0).then_some(self.edit_until),
            edited_at: (self.edited_at > 0).then_some(self.edited_at),
            revision: self.revision,
            deleted_at: (self.deleted_at > 0).then_some(self.deleted_at),
            id,
            parent_id,
            reply_n,
            client_message_id,
            channel_id: LocalId::new(&self.channel_id).map_err(|_| bad("channel_id"))?,
            group_id: LocalId::new(&self.group_id).map_err(|_| bad("group_id"))?,
            seq: self.seq,
            reply_seq: self.reply_seq,
            reaction_seq: self.reaction_seq,
            created_at: timefmt::parse_timestamp(&self.created_at)
                .ok_or_else(|| bad("created_at"))?,
        })
    }
}

/// The idempotency key of a create by `author` in `channel_id` carrying
/// `client_message_id` (§7.1: keyed per channel and author).
pub fn client_key(channel_id: &str, author: &Actor, client_message_id: &str) -> String {
    format!("c {channel_id} {author} {client_message_id}")
}

/// The `clientMessageId` a stored `client_key` carries.
fn client_message_id(key: &str, channel_id: &str, author: &str) -> Option<String> {
    let rest = key.strip_prefix("c ")?.strip_prefix(channel_id)?;
    let rest = rest.strip_prefix(' ')?.strip_prefix(author)?;
    rest.strip_prefix(' ').map(str::to_owned)
}

#[derive(Deserialize)]
struct EventRow {
    seq: i64,
    kind: String,
    message_id: String,
}

/// An edit or delete at a timeline position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEvent {
    /// Its position.
    pub seq: i64,
    /// [`event_kind::UPDATED`] or [`event_kind::DELETED`].
    pub kind: String,
    /// The message it changed.
    pub message_id: String,
}

/// A message about to be written.
#[derive(Debug, Clone)]
pub struct NewMessage<'a> {
    /// Its channel.
    pub channel_id: &'a str,
    /// The channel's group.
    pub group_id: &'a str,
    /// Its timeline position.
    pub seq: i64,
    /// Its idempotency key, if the create carried one.
    pub client_message_id: Option<&'a str>,
    /// The canonical author.
    pub author: &'a Actor,
    /// Its type.
    pub kind: &'a MessageType,
    /// The parent and the reply position under it, for a reply.
    pub reply: Option<(&'a LocalId, i64)>,
    /// The body.
    pub doc: &'a MessageDoc,
    /// Now (unix seconds).
    pub now: i64,
    /// The end of its edit window (unix seconds), if limited.
    pub edit_until: Option<i64>,
}

/// Message and timeline-event storage.
#[derive(Debug, Clone)]
pub struct MessageStore {
    pub(super) db: Arc<Db>,
}

impl MessageStore {
    /// A store over `db`.
    pub fn new(db: Arc<Db>) -> Self {
        Self { db }
    }

    /// The database.
    pub fn db(&self) -> &Db {
        &self.db
    }

    /// Write a new message. `Conflict` when its idempotency key is taken
    /// (a duplicate create), or, astronomically rarely, its id.
    pub async fn insert(&self, m: &NewMessage<'_>) -> Result<StoredMessage, DbError> {
        let id = new_id("msg_")?;
        let key = match m.client_message_id {
            Some(c) => client_key(m.channel_id, m.author, c),
            None => format!("m {id}"),
        };
        let (parent, reply_pos) = match m.reply {
            Some((p, n)) => (p.as_str().to_owned(), position(p.as_str(), n)),
            None => (String::new(), format!("m {id}")),
        };
        let q = Ql::new("Message.create({ message_id: ")
            .str(&id)
            .raw(", channel_id: ")
            .str(m.channel_id)
            .raw(", group_id: ")
            .str(m.group_id)
            .raw(", pos: ")
            .str(&position(m.channel_id, m.seq))
            .raw(", seq: ")
            .int(m.seq)
            .raw(", client_key: ")
            .str(&key)
            .raw(", author: ")
            .str(&m.author.to_string())
            .raw(", kind: ")
            .str(m.kind.as_str())
            .raw(", parent_id: ")
            .str(&parent)
            .raw(", reply_pos: ")
            .str(&reply_pos)
            .raw(", reply_seq: 0, reaction_seq: 0, doc: ")
            .str(&json(m.doc)?)
            .raw(", created_at: ")
            .unix_seconds(m.now)
            .raw(", edit_until: ")
            .int(m.edit_until.unwrap_or(0))
            .raw(", edited_at: 0, revision: 0, deleted_at: 0 })");
        self.db.write_one::<MessageRow>(&q).await?.data.decode()
    }

    async fn one_by(&self, q: Ql) -> Result<Option<StoredMessage>, DbError> {
        match self.db.fetch::<MessageRow>(&q).await?.into_iter().next() {
            Some(r) => r.data.decode().map(Some),
            None => Ok(None),
        }
    }

    /// Message `id` of `channel_id`, tombstone or not.
    pub async fn message(
        &self,
        channel_id: &str,
        id: &str,
    ) -> Result<Option<StoredMessage>, DbError> {
        let found = self
            .one_by(Ql::new("Message.filter(.message_id == ").str(id).raw(")"))
            .await?;
        Ok(found.filter(|m| m.channel_id.as_str() == channel_id))
    }

    /// The message `author` created in `channel_id` with
    /// `client_message_id`, if any.
    pub async fn by_client_key(
        &self,
        channel_id: &str,
        author: &Actor,
        client_message_id: &str,
    ) -> Result<Option<StoredMessage>, DbError> {
        self.one_by(
            Ql::new("Message.filter(.client_key == ")
                .str(&client_key(channel_id, author, client_message_id))
                .raw(")"),
        )
        .await
    }

    /// The messages created at `positions` of `channel_id`'s timeline.
    pub async fn at_positions(
        &self,
        channel_id: &str,
        positions: &[i64],
    ) -> Result<Vec<(i64, StoredMessage)>, DbError> {
        let keys: Vec<String> = positions.iter().map(|p| position(channel_id, *p)).collect();
        let rows: Vec<MessageRow> = lookup(&self.db, "Message.filter(", ".pos == ", &keys).await?;
        rows.into_iter()
            .map(|r| r.decode().map(|m| (m.seq, m)))
            .collect()
    }

    /// The creation position and author of each message created at
    /// `positions` of `channel_id`'s timeline, without decoding bodies
    /// (unread counts, §7.7). Positions holding no message are left out.
    pub async fn authors_at(
        &self,
        channel_id: &str,
        positions: &[i64],
    ) -> Result<Vec<(i64, String)>, DbError> {
        #[derive(Deserialize)]
        struct AuthorRow {
            seq: i64,
            author: String,
        }
        let keys: Vec<String> = positions.iter().map(|p| position(channel_id, *p)).collect();
        let rows: Vec<AuthorRow> = lookup(&self.db, "Message.filter(", ".pos == ", &keys).await?;
        Ok(rows.into_iter().map(|r| (r.seq, r.author)).collect())
    }

    /// The replies at positions `ns` under `parent`.
    pub async fn replies_at(
        &self,
        parent: &LocalId,
        ns: &[i64],
    ) -> Result<Vec<(i64, StoredMessage)>, DbError> {
        let keys: Vec<String> = ns.iter().map(|n| position(parent.as_str(), *n)).collect();
        let rows: Vec<MessageRow> =
            lookup(&self.db, "Message.filter(", ".reply_pos == ", &keys).await?;
        rows.into_iter()
            .map(|r| {
                let m = r.decode()?;
                let n = m
                    .reply_n
                    .ok_or_else(|| DbError::Decode(format!("message {}: bad reply_pos", m.id)))?;
                Ok((n, m))
            })
            .collect()
    }

    /// The messages with `ids`, in no particular order.
    pub async fn by_ids(&self, ids: &[String]) -> Result<Vec<StoredMessage>, DbError> {
        let rows: Vec<MessageRow> =
            lookup(&self.db, "Message.filter(", ".message_id == ", ids).await?;
        rows.into_iter().map(MessageRow::decode).collect()
    }

    /// Take the next position of one of `m`'s counters (`reply_seq` or
    /// `reaction_seq`): a compare-and-set from the value last read, retried
    /// from a fresh read while another writer wins. `None` if the message
    /// is gone.
    pub(super) async fn take_counter(
        &self,
        id: &LocalId,
        counter: Counter,
    ) -> Result<Option<i64>, DbError> {
        for _ in 0..32 {
            let Some(m) = self
                .one_by(
                    Ql::new("Message.filter(.message_id == ")
                        .str(id.as_str())
                        .raw(")"),
                )
                .await?
            else {
                return Ok(None);
            };
            let (field, last): (&'static str, i64) = match counter {
                Counter::Replies => (".reply_seq == ", m.reply_seq),
                Counter::Reactions => (".reaction_seq == ", m.reaction_seq),
            };
            let set: &'static str = match counter {
                Counter::Replies => ").update({ reply_seq: ",
                Counter::Reactions => ").update({ reaction_seq: ",
            };
            let next = last.saturating_add(1);
            let q = Ql::new("Message.filter(.message_id == ")
                .str(id.as_str())
                .raw(" && ")
                .raw(field)
                .int(last)
                .raw(set)
                .int(next)
                .raw(" })");
            if !self
                .db
                .write_one_object(&q)
                .await?
                .into_objects()
                .is_empty()
            {
                return Ok(Some(next));
            }
        }
        Err(DbError::Contended(format!(
            "message {id}: counter kept moving"
        )))
    }

    /// Replace the body of message `id` (not a tombstone) with `doc`,
    /// edited at `now`, if it is still at `revision`: a compare-and-set,
    /// so an edit built from an older body never overwrites a newer one.
    /// `None` if it is gone, deleted or edited meanwhile.
    pub async fn update_doc(
        &self,
        id: &LocalId,
        revision: i64,
        doc: &MessageDoc,
        now: i64,
    ) -> Result<Option<StoredMessage>, DbError> {
        let q = Ql::new("Message.filter(.message_id == ")
            .str(id.as_str())
            .raw(" && .deleted_at == 0 && .revision == ")
            .int(revision)
            .raw(").update({ doc: ")
            .str(&json(doc)?)
            .raw(", edited_at: ")
            .int(now.max(1))
            .raw(", revision: ")
            .int(revision + 1)
            .raw(" })");
        self.updated(q).await
    }

    /// Make message `id` a tombstone at `now` (§7.1). `None` if it is gone
    /// or already a tombstone.
    pub async fn tombstone(
        &self,
        id: &LocalId,
        now: i64,
    ) -> Result<Option<StoredMessage>, DbError> {
        let q = Ql::new("Message.filter(.message_id == ")
            .str(id.as_str())
            .raw(" && .deleted_at == 0).update({ doc: ")
            .str(&json(&MessageDoc::default())?)
            .raw(", deleted_at: ")
            .int(now.max(1))
            .raw(" })");
        self.updated(q).await
    }

    async fn updated(&self, q: Ql) -> Result<Option<StoredMessage>, DbError> {
        let rows = self.db.write_one_object_as::<MessageRow>(&q).await?;
        match rows.into_iter().next() {
            Some(r) => r.data.decode().map(Some),
            None => Ok(None),
        }
    }

    /// Remove message `id` outright: only to take back a write that landed
    /// in a channel deleted meanwhile.
    pub async fn remove(&self, id: &LocalId) -> Result<(), DbError> {
        let q = Ql::new("Message.filter(.message_id == ")
            .str(id.as_str())
            .raw(").delete()");
        self.db.write_one_object(&q).await.map(|_| ())
    }

    /// Record an edit or delete of `message_id` at position `seq`.
    pub async fn insert_event(
        &self,
        channel_id: &str,
        group_id: &str,
        seq: i64,
        kind: &'static str,
        message_id: &LocalId,
        now: i64,
    ) -> Result<(), DbError> {
        let q = Ql::new("TimelineEvent.create({ pos: ")
            .str(&position(channel_id, seq))
            .raw(", channel_id: ")
            .str(channel_id)
            .raw(", group_id: ")
            .str(group_id)
            .raw(", seq: ")
            .int(seq)
            .raw(", kind: ")
            .str(kind)
            .raw(", message_id: ")
            .str(message_id.as_str())
            .raw(", at: ")
            .unix_seconds(now)
            .raw(" })");
        self.db.execute(&q).await
    }

    /// Remove the event at `seq` of `channel_id`: only to take back a write
    /// that landed in a channel deleted meanwhile.
    pub async fn remove_event(&self, channel_id: &str, seq: i64) -> Result<(), DbError> {
        let q = Ql::new("TimelineEvent.filter(.pos == ")
            .str(&position(channel_id, seq))
            .raw(").delete()");
        self.db.write_one_object(&q).await.map(|_| ())
    }

    /// The edits and deletes at `positions` of `channel_id`'s timeline.
    pub async fn events_at(
        &self,
        channel_id: &str,
        positions: &[i64],
    ) -> Result<Vec<StoredEvent>, DbError> {
        let keys: Vec<String> = positions.iter().map(|p| position(channel_id, *p)).collect();
        let rows: Vec<EventRow> =
            lookup(&self.db, "TimelineEvent.filter(", ".pos == ", &keys).await?;
        Ok(rows
            .into_iter()
            .map(|r| StoredEvent {
                seq: r.seq,
                kind: r.kind,
                message_id: r.message_id,
            })
            .collect())
    }

    /// Remove every message, event and reaction of the deleted channel
    /// `channel_id`. Idempotent.
    pub async fn purge_channel(&self, channel_id: &str) -> Result<(), DbError> {
        for head in [
            "Reaction.filter(.channel_id == ",
            "TimelineEvent.filter(.channel_id == ",
            "Message.filter(.channel_id == ",
        ] {
            let q = Ql::new(head).str(channel_id).raw(").delete()");
            self.db.execute(&q).await?;
        }
        Ok(())
    }
}

/// A message's position counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Counter {
    /// `reply_seq`.
    Replies,
    /// `reaction_seq`.
    Reactions,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_keys_round_trip_and_positions_parse() {
        let a = Actor::parse_canonical("jane@a.example").unwrap();
        let key = client_key("chn_1", &a, "c 1 x");
        assert_eq!(
            client_message_id(&key, "chn_1", "jane@a.example").as_deref(),
            Some("c 1 x")
        );
        assert_eq!(
            client_message_id("m msg_1", "chn_1", "jane@a.example"),
            None
        );
        assert_eq!(client_message_id(&key, "chn_2", "jane@a.example"), None);
        assert_eq!(position_n("msg_1", &position("msg_1", 42)), Some(42));
        assert_eq!(position_n("msg_1", "msg_12:4"), None);
        assert_eq!(position_n("msg_1", "m msg_1"), None);
    }
}
