//! Memberships in rhypedb (`Membership` in `schema.rhype`): every member
//! of a group but its owner, who is the group's `owner` field.
//!
//! A membership is written `pending` and made `active` once its writer has
//! confirmed that the group is still active (see `store.rs`), so a
//! membership never outlives its group. Every read sees active rows only.

use re_ofscp_types::Actor;
use serde::Deserialize;

use super::store::{GroupStore, status};
use crate::db::{DbError, Ql};

#[derive(Deserialize)]
struct RoleRow {
    role: String,
}

/// The membership key: one row per (group, actor).
fn member_key(group_id: &str, actor: &Actor) -> String {
    format!("{group_id} {actor}")
}

impl GroupStore {
    /// `actor`'s role in `group_id`, if they are an active (non-owner)
    /// member.
    pub async fn role_of(&self, group_id: &str, actor: &Actor) -> Result<Option<String>, DbError> {
        let q = Ql::new("Membership.filter(.key == ")
            .str(&member_key(group_id, actor))
            .raw(" && .status == ")
            .str(status::ACTIVE)
            .raw(")");
        Ok(self
            .db
            .fetch::<RoleRow>(&q)
            .await?
            .into_iter()
            .next()
            .map(|r| r.data.role))
    }

    /// Write a `pending` membership of `actor` in `group_id` with `role`;
    /// [`Self::activate_member`] makes it count. `false` if a membership
    /// (pending or active) already exists.
    pub async fn add_member(
        &self,
        group_id: &str,
        actor: &Actor,
        role: &str,
        now: i64,
    ) -> Result<bool, DbError> {
        let q = Ql::new("Membership.create({ key: ")
            .str(&member_key(group_id, actor))
            .raw(", group_id: ")
            .str(group_id)
            .raw(", actor: ")
            .str(&actor.to_string())
            .raw(", role: ")
            .str(role)
            .raw(", status: ")
            .str(status::PENDING)
            .raw(", joined_at: ")
            .unix_seconds(now)
            .raw(" })");
        match self.db.execute(&q).await {
            Ok(()) => Ok(true),
            Err(DbError::Conflict(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Make a pending membership count. `false` if it is gone (its group
    /// was purged, or it expired).
    pub async fn activate_member(&self, group_id: &str, actor: &Actor) -> Result<bool, DbError> {
        let q = Ql::new("Membership.filter(.key == ")
            .str(&member_key(group_id, actor))
            .raw(" && .status == ")
            .str(status::PENDING)
            .raw(").update({ status: ")
            .str(status::ACTIVE)
            .raw(" })");
        Ok(!self.db.write_rows(&q).await?.into_objects().is_empty())
    }

    /// Change an active member's role. `false` if not a member.
    pub async fn set_role(
        &self,
        group_id: &str,
        actor: &Actor,
        role: &str,
    ) -> Result<bool, DbError> {
        let q = Ql::new("Membership.filter(.key == ")
            .str(&member_key(group_id, actor))
            .raw(" && .status == ")
            .str(status::ACTIVE)
            .raw(").update({ role: ")
            .str(role)
            .raw(" })");
        Ok(!self.db.write_rows(&q).await?.into_objects().is_empty())
    }

    /// End `actor`'s membership of `group_id`, pending or active (a no-op
    /// if there is none).
    pub async fn remove_member(&self, group_id: &str, actor: &Actor) -> Result<(), DbError> {
        let q = Ql::new("Membership.filter(.key == ")
            .str(&member_key(group_id, actor))
            .raw(").delete()");
        self.db.execute(&q).await
    }

    /// Remove the pending memberships written before `cutoff` (unix
    /// seconds).
    pub(super) async fn expire_pending_members(&self, cutoff: i64) -> Result<(), DbError> {
        let q = Ql::new("Membership.filter(.status == ")
            .str(status::PENDING)
            .raw(" && .joined_at < ")
            .unix_seconds(cutoff)
            .raw(").delete()");
        self.db.execute(&q).await
    }
}
