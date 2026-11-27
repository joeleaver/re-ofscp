//! Membership pointers in rhypedb (`GroupPointer` in `schema.rhype`): one
//! row per (owner, group URI), keyed `@unique` by `"{owner} {group}"`.
//! Neither part can hold a space (a canonical actor and an object URI of
//! RFC 3986 characters), so the key is unambiguous.

use std::sync::Arc;

use re_ofscp_types::Actor;
use serde::Deserialize;

use crate::db::{Db, DbError, Ql};

/// A stored pointer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPointer {
    /// The group's canonical object URI.
    pub group: String,
    /// The role hint, if the client recorded one.
    pub role: Option<String>,
    /// RFC 3339 time it last changed.
    pub updated_at: String,
}

#[derive(Deserialize)]
struct PointerRow {
    group: String,
    role: String,
    updated_at: String,
}

impl PointerRow {
    fn decode(self) -> StoredPointer {
        StoredPointer {
            group: self.group,
            // An empty column is "no hint": a recorded hint is never empty.
            role: (!self.role.is_empty()).then_some(self.role),
            updated_at: self.updated_at,
        }
    }
}

fn key(owner: &Actor, group: &str) -> String {
    format!("{owner} {group}")
}

/// What [`PointerStore::create`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Created {
    /// Written.
    Written(StoredPointer),
    /// A pointer with this key already exists.
    Exists,
}

/// Storage for membership pointers.
#[derive(Debug, Clone)]
pub struct PointerStore {
    db: Arc<Db>,
}

impl PointerStore {
    /// Pointers stored in `db`.
    pub fn new(db: Arc<Db>) -> Self {
        Self { db }
    }

    /// `owner`'s pointers, at most `cap`.
    pub async fn list(&self, owner: &Actor, cap: usize) -> Result<Vec<StoredPointer>, DbError> {
        let q = Ql::new("GroupPointer.filter(.owner == ")
            .str(&owner.to_string())
            .raw(").limit(")
            .uint(cap as u64)
            .raw(")");
        Ok(self
            .db
            .fetch::<PointerRow>(&q)
            .await?
            .into_iter()
            .map(|r| r.data.decode())
            .collect())
    }

    /// How many pointers `owner` has, counting at most `cap`.
    pub async fn count(&self, owner: &Actor, cap: usize) -> Result<usize, DbError> {
        self.list(owner, cap).await.map(|l| l.len())
    }

    /// `owner`'s pointer to `group`, if any.
    pub async fn get(&self, owner: &Actor, group: &str) -> Result<Option<StoredPointer>, DbError> {
        let q = Ql::new("GroupPointer.filter(.key == ")
            .str(&key(owner, group))
            .raw(")");
        Ok(self
            .db
            .fetch::<PointerRow>(&q)
            .await?
            .into_iter()
            .next()
            .map(|r| r.data.decode()))
    }

    /// Record a new pointer at `now` (unix seconds).
    pub async fn create(
        &self,
        owner: &Actor,
        group: &str,
        role: Option<&str>,
        now: i64,
    ) -> Result<Created, DbError> {
        let q = Ql::new("GroupPointer.create({ key: ")
            .str(&key(owner, group))
            .raw(", owner: ")
            .str(&owner.to_string())
            .raw(", group: ")
            .str(group)
            .raw(", role: ")
            .str(role.unwrap_or(""))
            .raw(", updated_at: ")
            .unix_seconds(now)
            .raw(" })");
        match self.db.write_one_object_as::<PointerRow>(&q).await {
            Ok(rows) => match rows.into_iter().next() {
                Some(row) => Ok(Created::Written(row.data.decode())),
                None => Err(DbError::Decode("a create returned nothing".to_owned())),
            },
            // Taken, or another create of this key won at commit.
            Err(DbError::Conflict(_) | DbError::Contended(_)) => Ok(Created::Exists),
            Err(e) => Err(e),
        }
    }

    /// Change the role hint of `owner`'s pointer to `group`, only while it
    /// still holds `old` (compare-and-set since rhypedb #59, decision 0012).
    /// `None` if it no longer did, or is gone.
    pub async fn update_role(
        &self,
        owner: &Actor,
        group: &str,
        old: Option<&str>,
        new: Option<&str>,
        now: i64,
    ) -> Result<Option<StoredPointer>, DbError> {
        let q = Ql::new("GroupPointer.filter(.key == ")
            .str(&key(owner, group))
            .raw(" && .role == ")
            .str(old.unwrap_or(""))
            .raw(").update({ role: ")
            .str(new.unwrap_or(""))
            .raw(", updated_at: ")
            .unix_seconds(now)
            .raw(" })");
        Ok(self
            .db
            .write_one_object_as::<PointerRow>(&q)
            .await?
            .into_iter()
            .next()
            .map(|r| r.data.decode()))
    }

    /// Remove `owner`'s pointer to `group`, if there is one. rhypedb's
    /// `delete` returns no rows, so whether one was removed is not known
    /// here: the caller reads first (decision 0018).
    pub async fn delete(&self, owner: &Actor, group: &str) -> Result<(), DbError> {
        let q = Ql::new("GroupPointer.filter(.key == ")
            .str(&key(owner, group))
            .raw(").delete()");
        self.db.write_one_object(&q).await.map(|_| ())
    }
}
