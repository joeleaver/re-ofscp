//! Follows in rhypedb (`Follow` in `schema.rhype`): one row per (owner,
//! channel), keyed `@unique` by `"{owner} {channel}"`, where `channel` is
//! a local channel id or a remote channel's canonical object URI. Neither
//! part can hold a space (a canonical actor, and a local id or an object
//! URI of RFC 3986 characters), so the key is unambiguous.
//!
//! Each follow also holds one of its owner's slots, `@unique` `"{owner}
//! {i}"` for `i` below the per-user limit (as a limited invite's uses,
//! decision 0019). The create is the one serialized step: however many
//! creates race, no two hold the same slot, so an owner never has more
//! follows than slots, and a delete frees its slot with the row.

use std::collections::BTreeSet;
use std::sync::Arc;

use re_ofscp_types::Actor;
use serde::Deserialize;

use crate::db::{Db, DbError, Ql};

/// A stored follow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredFollow {
    /// A local channel id, or a remote channel's canonical object URI.
    pub channel: String,
    /// The owner's slot it holds, if its slot key is well formed.
    pub slot: Option<usize>,
    /// RFC 3339 time it was created.
    pub created_at: String,
}

#[derive(Deserialize)]
struct FollowRow {
    owner: String,
    channel: String,
    slot: String,
    created_at: String,
}

impl FollowRow {
    fn decode(self) -> StoredFollow {
        StoredFollow {
            slot: slot_number(&self.slot, &self.owner),
            channel: self.channel,
            created_at: self.created_at,
        }
    }
}

fn key(owner: &Actor, channel: &str) -> String {
    format!("{owner} {channel}")
}

/// The `@unique` key of `owner`'s slot `i`.
pub fn slot_key(owner: &Actor, i: usize) -> String {
    format!("{owner} {i}")
}

/// The slot number of a slot key of `owner`.
fn slot_number(slot: &str, owner: &str) -> Option<usize> {
    slot.strip_prefix(owner)?.strip_prefix(' ')?.parse().ok()
}

/// The slots below `limit` that none of `follows` holds.
pub fn free_slots(follows: &[StoredFollow], limit: usize) -> Vec<usize> {
    let taken: BTreeSet<usize> = follows.iter().filter_map(|f| f.slot).collect();
    (0..limit).filter(|i| !taken.contains(i)).collect()
}

/// What [`FollowStore::create`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Created {
    /// Written.
    Written(StoredFollow),
    /// Not written: a follow with this key, or one holding this slot,
    /// already exists.
    Taken,
}

/// Storage for follows.
#[derive(Debug, Clone)]
pub struct FollowStore {
    db: Arc<Db>,
}

impl FollowStore {
    /// Follows stored in `db`.
    pub fn new(db: Arc<Db>) -> Self {
        Self { db }
    }

    /// `owner`'s follows, at most `cap`, in no particular order.
    pub async fn list(&self, owner: &Actor, cap: usize) -> Result<Vec<StoredFollow>, DbError> {
        let q = Ql::new("Follow.filter(.owner == ")
            .str(&owner.to_string())
            .raw(").limit(")
            .uint(cap as u64)
            .raw(")");
        Ok(self
            .db
            .fetch::<FollowRow>(&q)
            .await?
            .into_iter()
            .map(|r| r.data.decode())
            .collect())
    }

    /// `owner`'s follow of `channel`, if any.
    pub async fn get(&self, owner: &Actor, channel: &str) -> Result<Option<StoredFollow>, DbError> {
        let q = Ql::new("Follow.filter(.key == ")
            .str(&key(owner, channel))
            .raw(")");
        Ok(self
            .db
            .fetch::<FollowRow>(&q)
            .await?
            .into_iter()
            .next()
            .map(|r| r.data.decode()))
    }

    /// Record that `owner` follows `channel` in their slot `slot`, at `now`
    /// (unix seconds).
    pub async fn create(
        &self,
        owner: &Actor,
        channel: &str,
        slot: usize,
        now: i64,
    ) -> Result<Created, DbError> {
        let q = Ql::new("Follow.create({ key: ")
            .str(&key(owner, channel))
            .raw(", slot: ")
            .str(&slot_key(owner, slot))
            .raw(", owner: ")
            .str(&owner.to_string())
            .raw(", channel: ")
            .str(channel)
            .raw(", created_at: ")
            .unix_seconds(now)
            .raw(" })");
        match self.db.write_one_object_as::<FollowRow>(&q).await {
            Ok(rows) => match rows.into_iter().next() {
                Some(row) => Ok(Created::Written(row.data.decode())),
                None => Err(DbError::Decode("a create returned nothing".to_owned())),
            },
            // The key or the slot is taken, or another create of either won
            // at commit.
            Err(DbError::Conflict(_) | DbError::Contended(_)) => Ok(Created::Taken),
            Err(e) => Err(e),
        }
    }

    /// Remove `owner`'s follow of `channel`, if there is one, freeing its
    /// slot.
    pub async fn delete(&self, owner: &Actor, channel: &str) -> Result<(), DbError> {
        let q = Ql::new("Follow.filter(.key == ")
            .str(&key(owner, channel))
            .raw(").delete()");
        self.db.write_one_object(&q).await.map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_parse_back_and_free_slots_skip_taken_ones() {
        let owner = Actor::parse_canonical("jane@a.example").unwrap();
        let key = slot_key(&owner, 7);
        assert_eq!(slot_number(&key, "jane@a.example"), Some(7));
        assert_eq!(slot_number(&key, "jan@a.example"), None);
        assert_eq!(slot_number("jane@a.example x", "jane@a.example"), None);
        let f = |slot| StoredFollow {
            channel: String::new(),
            slot,
            created_at: String::new(),
        };
        let follows = [f(Some(0)), f(Some(2)), f(None), f(Some(9))];
        assert_eq!(free_slots(&follows, 4), [1, 3]);
    }
}
