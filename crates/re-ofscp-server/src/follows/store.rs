//! Follows in rhypedb (`Follow` in `schema.rhype`): one row per (owner,
//! channel), keyed `@unique` by `"{owner} {channel}"`, where `channel` is
//! a local channel id or a remote channel's canonical object URI. Neither
//! part can hold a space (a canonical actor, and a local id or an object
//! URI of RFC 3986 characters), so the key is unambiguous.

use std::sync::Arc;

use re_ofscp_types::Actor;
use serde::Deserialize;

use crate::db::{Db, DbError, Ql};

/// A stored follow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredFollow {
    /// A local channel id, or a remote channel's canonical object URI.
    pub channel: String,
    /// RFC 3339 time it was created.
    pub created_at: String,
}

#[derive(Deserialize)]
struct FollowRow {
    channel: String,
    created_at: String,
}

impl FollowRow {
    fn decode(self) -> StoredFollow {
        StoredFollow {
            channel: self.channel,
            created_at: self.created_at,
        }
    }
}

fn key(owner: &Actor, channel: &str) -> String {
    format!("{owner} {channel}")
}

/// What [`FollowStore::create`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Created {
    /// Written.
    Written(StoredFollow),
    /// A follow with this key already exists.
    Exists,
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

    /// Record that `owner` follows `channel`, at `now` (unix seconds).
    pub async fn create(&self, owner: &Actor, channel: &str, now: i64) -> Result<Created, DbError> {
        let q = Ql::new("Follow.create({ key: ")
            .str(&key(owner, channel))
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
            // Taken, or another create of this key won at commit.
            Err(DbError::Conflict(_) | DbError::Contended(_)) => Ok(Created::Exists),
            Err(e) => Err(e),
        }
    }

    /// Remove `owner`'s follow of `channel`, if there is one.
    pub async fn delete(&self, owner: &Actor, channel: &str) -> Result<(), DbError> {
        let q = Ql::new("Follow.filter(.key == ")
            .str(&key(owner, channel))
            .raw(").delete()");
        self.db.write_one_object(&q).await.map(|_| ())
    }
}
