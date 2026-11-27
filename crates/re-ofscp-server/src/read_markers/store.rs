//! Read markers in rhypedb (`ReadMarker` in `schema.rhype`): one row per
//! (owner, scope), keyed `@unique` by `"{owner} {scope}"`. A scope is a
//! channel's local id, which holds no space, nor does a canonical actor,
//! so the key is unambiguous.
//!
//! A marker only moves forward: an update is a compare-and-set on the
//! stored position (`seq`), which rhypedb #59 makes atomic (decision 0012).

use std::collections::BTreeMap;
use std::sync::Arc;

use re_ofscp_types::Actor;
use serde::Deserialize;

use crate::db::lookup::lookup;
use crate::db::{Db, DbError, Ql};

/// A stored marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMarker {
    /// The scope (a channel's local id).
    pub scope_id: String,
    /// The newest message read.
    pub message_id: String,
    /// That message's creation position in the scope's timeline.
    pub seq: i64,
}

#[derive(Deserialize)]
struct MarkerRow {
    scope_id: String,
    message_id: String,
    seq: i64,
}

impl MarkerRow {
    fn decode(self) -> StoredMarker {
        StoredMarker {
            scope_id: self.scope_id,
            message_id: self.message_id,
            seq: self.seq,
        }
    }
}

fn key(owner: &Actor, scope: &str) -> String {
    format!("{owner} {scope}")
}

/// What [`MarkerStore::advance`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Advanced {
    /// The marker moved to the new message.
    Moved(StoredMarker),
    /// The stored marker is already at or past it.
    Behind,
}

/// How often an advance retries when another writer created or moved the
/// same marker between its read and its write.
const ADVANCE_ATTEMPTS: usize = 5;

/// Storage for read markers.
#[derive(Debug, Clone)]
pub struct MarkerStore {
    db: Arc<Db>,
}

impl MarkerStore {
    /// Markers stored in `db`.
    pub fn new(db: Arc<Db>) -> Self {
        Self { db }
    }

    /// `owner`'s markers in `scopes`, by scope.
    pub async fn for_scopes(
        &self,
        owner: &Actor,
        scopes: &[String],
    ) -> Result<BTreeMap<String, StoredMarker>, DbError> {
        let keys: Vec<String> = scopes.iter().map(|s| key(owner, s)).collect();
        let rows: Vec<MarkerRow> =
            lookup(&self.db, "ReadMarker.filter(", ".key == ", &keys).await?;
        Ok(rows
            .into_iter()
            .map(|r| {
                let m = r.decode();
                (m.scope_id.clone(), m)
            })
            .collect())
    }

    /// `owner`'s marker in `scope`, if any.
    pub async fn get(&self, owner: &Actor, scope: &str) -> Result<Option<StoredMarker>, DbError> {
        let q = Ql::new("ReadMarker.filter(.key == ")
            .str(&key(owner, scope))
            .raw(")");
        Ok(self
            .db
            .fetch::<MarkerRow>(&q)
            .await?
            .into_iter()
            .next()
            .map(|r| r.data.decode()))
    }

    /// Move `owner`'s marker in `scope` to `message_id` at position `seq`,
    /// only forward, at `now` (unix seconds).
    pub async fn advance(
        &self,
        owner: &Actor,
        scope: &str,
        message_id: &str,
        seq: i64,
        now: i64,
    ) -> Result<Advanced, DbError> {
        for _ in 0..ADVANCE_ATTEMPTS {
            match self.get(owner, scope).await? {
                Some(m) if m.seq >= seq => return Ok(Advanced::Behind),
                Some(_) => {
                    let q = Ql::new("ReadMarker.filter(.key == ")
                        .str(&key(owner, scope))
                        .raw(" && .seq < ")
                        .int(seq)
                        .raw(").update({ message_id: ")
                        .str(message_id)
                        .raw(", seq: ")
                        .int(seq)
                        .raw(", updated_at: ")
                        .unix_seconds(now)
                        .raw(" })");
                    match self.db.write_one_object_as::<MarkerRow>(&q).await {
                        Ok(rows) => {
                            if let Some(row) = rows.into_iter().next() {
                                return Ok(Advanced::Moved(row.data.decode()));
                            }
                        }
                        // Another write to it won: read again.
                        Err(DbError::Contended(_)) => {}
                        Err(e) => return Err(e),
                    }
                    // Another writer moved it at or past `seq`, or removed
                    // it: read again.
                }
                None => {
                    let q = Ql::new("ReadMarker.create({ key: ")
                        .str(&key(owner, scope))
                        .raw(", owner: ")
                        .str(&owner.to_string())
                        .raw(", scope_id: ")
                        .str(scope)
                        .raw(", message_id: ")
                        .str(message_id)
                        .raw(", seq: ")
                        .int(seq)
                        .raw(", updated_at: ")
                        .unix_seconds(now)
                        .raw(" })");
                    match self.db.write_one_object_as::<MarkerRow>(&q).await {
                        Ok(rows) => match rows.into_iter().next() {
                            Some(row) => return Ok(Advanced::Moved(row.data.decode())),
                            None => {
                                return Err(DbError::Decode(
                                    "a create returned nothing".to_owned(),
                                ));
                            }
                        },
                        // Another writer created it first: compare with theirs.
                        Err(DbError::Conflict(_) | DbError::Contended(_)) => {}
                        Err(e) => return Err(e),
                    }
                }
            }
        }
        Err(DbError::Contended(format!(
            "read marker {scope}: still changing after {ADVANCE_ATTEMPTS} attempts"
        )))
    }

    /// Remove every marker in the deleted channel `scope`. Idempotent.
    pub async fn purge_scope(db: &Db, scope: &str) -> Result<(), DbError> {
        let q = Ql::new("ReadMarker.filter(.scope_id == ")
            .str(scope)
            .raw(").delete()");
        db.execute(&q).await
    }
}
