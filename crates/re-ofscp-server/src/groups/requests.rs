//! Pending join requests in rhypedb (`JoinRequest` in `schema.rhype`,
//! spec §5.7 "Join requests"). A row exists only while its request is
//! pending: approving or denying deletes it, and so does the group's
//! purge. `key` (`@unique`) holds one pending request per (group, actor).

use ofscp_core::LocalId;
use re_ofscp_types::Actor;
use re_ofscp_types::wire::{JoinRequest, JoinRequestState};
use serde::Deserialize;

use super::members::member_key;
use super::store::GroupStore;
use crate::db::doc::new_id;
use crate::db::{DbError, Ql};
use crate::timefmt;

#[derive(Deserialize)]
struct RequestRow {
    request_id: String,
    group_id: String,
    actor: String,
    #[serde(default)]
    message: Option<String>,
    requested_at: String,
}

impl RequestRow {
    fn decode(self) -> Result<StoredRequest, DbError> {
        let bad =
            |what: &str| DbError::Decode(format!("join request {}: bad {what}", self.request_id));
        Ok(StoredRequest {
            actor: Actor::parse_canonical(&self.actor).map_err(|_| bad("actor"))?,
            requested_at: timefmt::unix(&self.requested_at).ok_or_else(|| bad("requested_at"))?,
            id: self.request_id,
            group_id: self.group_id,
            message: self.message,
        })
    }
}

/// A pending join request, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRequest {
    /// Local id (`jrq_…`).
    pub id: String,
    /// The group.
    pub group_id: String,
    /// Who asked (full canonical actor).
    pub actor: Actor,
    /// What they said.
    pub message: Option<String>,
    /// When they asked (unix seconds).
    pub requested_at: i64,
}

impl StoredRequest {
    /// The canonical `JoinRequest` (§5.7): always `pending`, since only
    /// pending requests are kept.
    pub fn to_wire(&self) -> Result<JoinRequest, DbError> {
        let id = |s: &str| {
            LocalId::new(s)
                .map_err(|_| DbError::Decode(format!("join request {}: bad id", self.id)))
        };
        Ok(JoinRequest {
            id: id(&self.id)?,
            group_id: id(&self.group_id)?,
            user: self.actor.clone(),
            state: JoinRequestState::Pending,
            message: self.message.clone(),
            requested_at: timefmt::timestamp(self.requested_at),
        })
    }
}

fn decode_all(rows: Vec<rhypedb_client::Row<RequestRow>>) -> Result<Vec<StoredRequest>, DbError> {
    rows.into_iter().map(|r| r.data.decode()).collect()
}

impl GroupStore {
    /// Record a pending request by `actor` to join `group_id`. `None` if
    /// they already have one pending. The caller has checked the group.
    pub async fn create_request(
        &self,
        group_id: &str,
        actor: &Actor,
        message: Option<&str>,
        now: i64,
    ) -> Result<Option<StoredRequest>, DbError> {
        // One retry covers a (vanishingly unlikely) id collision; a taken
        // key is the actor's pending request.
        for _ in 0..2 {
            let id = new_id("jrq_")?;
            let mut q = Ql::new("JoinRequest.create({ request_id: ")
                .str(&id)
                .raw(", key: ")
                .str(&member_key(group_id, actor))
                .raw(", group_id: ")
                .str(group_id)
                .raw(", actor: ")
                .str(&actor.to_string())
                .raw(", requested_at: ")
                .unix_seconds(now);
            if let Some(m) = message {
                q = q.raw(", message: ").str(m);
            }
            match self.db.execute(&q.raw(" })")).await {
                Ok(()) => {
                    return Ok(Some(StoredRequest {
                        id,
                        group_id: group_id.to_owned(),
                        actor: actor.clone(),
                        message: message.map(str::to_owned),
                        requested_at: now,
                    }));
                }
                Err(DbError::Conflict(_) | DbError::Contended(_)) => {
                    if self.pending_request_of(group_id, actor).await?.is_some() {
                        return Ok(None);
                    }
                }
                Err(e) => return Err(e),
            }
        }
        Err(DbError::Query(
            "could not allocate a unique join request id".to_owned(),
        ))
    }

    /// `actor`'s pending request to join `group_id`, if any.
    pub async fn pending_request_of(
        &self,
        group_id: &str,
        actor: &Actor,
    ) -> Result<Option<StoredRequest>, DbError> {
        let q = Ql::new("JoinRequest.filter(.key == ")
            .str(&member_key(group_id, actor))
            .raw(")");
        Ok(decode_all(self.db.fetch::<RequestRow>(&q).await?)?
            .into_iter()
            .next())
    }

    /// Pending request `request_id` of `group_id`, if any.
    pub async fn request(
        &self,
        group_id: &str,
        request_id: &str,
    ) -> Result<Option<StoredRequest>, DbError> {
        let q = Ql::new("JoinRequest.filter(.request_id == ")
            .str(request_id)
            .raw(")");
        Ok(decode_all(self.db.fetch::<RequestRow>(&q).await?)?
            .into_iter()
            .find(|r| r.group_id == group_id))
    }

    /// The pending requests of `group_id`, at most `cap`, in no order.
    pub async fn requests(
        &self,
        group_id: &str,
        cap: usize,
    ) -> Result<Vec<StoredRequest>, DbError> {
        let q = Ql::new("JoinRequest.filter(.group_id == ")
            .str(group_id)
            .raw(").limit(")
            .uint(cap as u64)
            .raw(")");
        decode_all(self.db.fetch::<RequestRow>(&q).await?)
    }

    /// How many pending requests `group_id` has, counting at most `cap`.
    pub async fn request_count(&self, group_id: &str, cap: usize) -> Result<usize, DbError> {
        let q = Ql::new("JoinRequest.filter(.group_id == ")
            .str(group_id)
            .raw(").limit(")
            .uint(cap as u64)
            .raw(")");
        Ok(self.db.fetch::<serde::de::IgnoredAny>(&q).await?.len())
    }

    /// Delete `actor`'s pending request to join `group_id`, if any.
    pub async fn delete_request_of(&self, group_id: &str, actor: &Actor) -> Result<(), DbError> {
        let q = Ql::new("JoinRequest.filter(.key == ")
            .str(&member_key(group_id, actor))
            .raw(").delete()");
        self.db.write_one_object(&q).await.map(|_| ())
    }

    /// Delete request `request_id` (a no-op if it is gone).
    pub async fn delete_request(&self, request_id: &str) -> Result<(), DbError> {
        let q = Ql::new("JoinRequest.filter(.request_id == ")
            .str(request_id)
            .raw(").delete()");
        self.db.write_one_object(&q).await.map(|_| ())
    }
}
