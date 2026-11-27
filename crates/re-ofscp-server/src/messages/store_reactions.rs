//! Reactions in rhypedb (`Reaction` in `schema.rhype`). A message's
//! reactions sit at positions 1, 2, 3… under it (`rpos`), taken from the
//! message's `reaction_seq` counter, so the reaction listing pages like
//! history does. At most one reaction per (message, author, key) (§7.1):
//! the `@unique` `key` column enforces it.

use ofscp_core::{Actor, LocalId};
use serde::Deserialize;

use super::model::StoredReaction;
use super::store::{MessageStore, position, position_n};
use crate::db::doc::new_id;
use crate::db::lookup::lookup;
use crate::db::{DbError, Ql};
use crate::timefmt;

#[derive(Deserialize)]
struct ReactionRow {
    rpos: String,
    reaction_id: String,
    message_id: String,
    author: String,
    rkey: String,
    unicode: String,
    image: String,
    created_at: String,
}

impl ReactionRow {
    fn decode(self) -> Result<StoredReaction, DbError> {
        let bad =
            |what: &str| DbError::Decode(format!("reaction {}: bad {what}", self.reaction_id));
        let n = position_n(&self.message_id, &self.rpos).ok_or_else(|| bad("rpos"))?;
        Ok(StoredReaction {
            id: LocalId::new(&self.reaction_id).map_err(|_| bad("id"))?,
            message_id: LocalId::new(&self.message_id).map_err(|_| bad("message_id"))?,
            author: Actor::parse_canonical(&self.author).map_err(|_| bad("author"))?,
            n,
            unicode: (!self.unicode.is_empty()).then_some(self.unicode),
            image: (!self.image.is_empty()).then_some(self.image),
            key: self.rkey,
            created_at: timefmt::parse_timestamp(&self.created_at)
                .ok_or_else(|| bad("created_at"))?,
        })
    }
}

/// The unique key of `author`'s reaction `key` on `message_id`.
fn reaction_key(message_id: &LocalId, author: &Actor, key: &str) -> String {
    format!("{message_id} {author} {key}")
}

/// A reaction about to be written.
#[derive(Debug, Clone)]
pub struct NewReaction<'a> {
    /// The message it is on.
    pub message_id: &'a LocalId,
    /// The message's channel.
    pub channel_id: &'a str,
    /// The channel's group.
    pub group_id: &'a str,
    /// Its position among the message's reactions.
    pub n: i64,
    /// Who reacted.
    pub author: &'a Actor,
    /// Which reaction.
    pub key: &'a str,
    /// Its emoji, if given.
    pub unicode: Option<&'a str>,
    /// Its picture, if given.
    pub image: Option<&'a str>,
    /// Now (unix seconds).
    pub now: i64,
}

impl MessageStore {
    /// `author`'s reaction `key` on `message_id`, if any.
    pub async fn reaction(
        &self,
        message_id: &LocalId,
        author: &Actor,
        key: &str,
    ) -> Result<Option<StoredReaction>, DbError> {
        let q = Ql::new("Reaction.filter(.key == ")
            .str(&reaction_key(message_id, author, key))
            .raw(")");
        match self.db.fetch::<ReactionRow>(&q).await?.into_iter().next() {
            Some(r) => r.data.decode().map(Some),
            None => Ok(None),
        }
    }

    /// Write a reaction. `Conflict` when the author already holds it.
    pub async fn insert_reaction(&self, r: &NewReaction<'_>) -> Result<StoredReaction, DbError> {
        let q = Ql::new("Reaction.create({ key: ")
            .str(&reaction_key(r.message_id, r.author, r.key))
            .raw(", rpos: ")
            .str(&position(r.message_id.as_str(), r.n))
            .raw(", reaction_id: ")
            .str(&new_id("rct_")?)
            .raw(", message_id: ")
            .str(r.message_id.as_str())
            .raw(", channel_id: ")
            .str(r.channel_id)
            .raw(", group_id: ")
            .str(r.group_id)
            .raw(", author: ")
            .str(&r.author.to_string())
            .raw(", rkey: ")
            .str(r.key)
            .raw(", unicode: ")
            .str(r.unicode.unwrap_or_default())
            .raw(", image: ")
            .str(r.image.unwrap_or_default())
            .raw(", created_at: ")
            .unix_seconds(r.now)
            .raw(" })");
        self.db.write_one::<ReactionRow>(&q).await?.data.decode()
    }

    /// Remove `author`'s reaction `key` on `message_id`. Whether there was
    /// one.
    ///
    /// rhypedb's `delete` reports nothing about what it removed, so the row
    /// is read first and then deleted by its id. Callers hold the
    /// channel's lock, so within this process one of two concurrent
    /// removes finds the row; across processes both may, and both report
    /// a removal (the `reaction.removed` they fan out is idempotent).
    pub async fn remove_reaction(
        &self,
        message_id: &LocalId,
        author: &Actor,
        key: &str,
    ) -> Result<bool, DbError> {
        let Some(existing) = self.reaction(message_id, author, key).await? else {
            return Ok(false);
        };
        let q = Ql::new("Reaction.filter(.reaction_id == ")
            .str(existing.id.as_str())
            .raw(").delete()");
        self.db.write_one_object(&q).await?;
        Ok(true)
    }

    /// The reactions at positions `ns` of `message_id`.
    pub async fn reactions_at(
        &self,
        message_id: &LocalId,
        ns: &[i64],
    ) -> Result<Vec<(i64, StoredReaction)>, DbError> {
        let keys: Vec<String> = ns
            .iter()
            .map(|n| position(message_id.as_str(), *n))
            .collect();
        let rows: Vec<ReactionRow> =
            lookup(&self.db, "Reaction.filter(", ".rpos == ", &keys).await?;
        rows.into_iter()
            .map(|r| r.decode().map(|x| (x.n, x)))
            .collect()
    }
}
