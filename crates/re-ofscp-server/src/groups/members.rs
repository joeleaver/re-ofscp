//! Memberships in rhypedb (`Membership` in `schema.rhype`): every member
//! of a group but its owner, who is the group's `owner` field.
//!
//! A membership is written `pending` and made `active` once its writer has
//! confirmed that the group is still active (see `store.rs`), so a
//! membership never outlives its group. Removing one first makes it
//! `leaving` (`member_ops.rs`); a deleting group's memberships are
//! `ended` before its purge (`ending.rs`). Every read sees active rows only.

use re_ofscp_types::Actor;
use serde::Deserialize;

use super::store::{GroupStore, status};
use crate::db::{DbError, Ql};

/// A membership row as rhypedb returns it.
#[derive(Deserialize)]
struct MemberRow {
    group_id: String,
    actor: String,
    role: String,
    status: String,
    joined_at: String,
    #[serde(default)]
    display_name_override: Option<String>,
    #[serde(default)]
    transfer_id: Option<String>,
}

impl MemberRow {
    fn decode(self) -> Result<StoredMember, DbError> {
        let actor = Actor::parse_canonical(&self.actor)
            .map_err(|_| DbError::Decode(format!("membership of {}: bad actor", self.group_id)))?;
        Ok(StoredMember {
            group_id: self.group_id,
            actor,
            role: self.role,
            active: self.status == status::ACTIVE,
            joined_at: self.joined_at,
            display_name: self.display_name_override,
            transfer_id: self.transfer_id,
        })
    }
}

/// A membership, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMember {
    /// The group.
    pub group_id: String,
    /// The member (full canonical actor, security requirement 1).
    pub actor: Actor,
    /// Their role (never `owner`).
    pub role: String,
    /// Active (`true`) or still pending confirmation.
    pub active: bool,
    /// RFC 3339 time the row was written.
    pub joined_at: String,
    /// Their group-scoped nickname (§5.7).
    pub display_name: Option<String>,
    /// The ownership transfer to them that marked this row, if any
    /// (`transfer.rs`).
    pub transfer_id: Option<String>,
}

/// The membership key: one row per (group, actor).
pub(super) fn member_key(group_id: &str, actor: &Actor) -> String {
    format!("{group_id} {actor}")
}

fn decode_all(rows: Vec<rhypedb_client::Row<MemberRow>>) -> Result<Vec<StoredMember>, DbError> {
    rows.into_iter().map(|r| r.data.decode()).collect()
}

/// The first row a write returned, decoded.
fn written(rows: Vec<rhypedb_client::Row<MemberRow>>) -> Result<Option<StoredMember>, DbError> {
    rows.into_iter().next().map(|r| r.data.decode()).transpose()
}

impl GroupStore {
    /// `actor`'s active (non-owner) membership of `group_id`, if any.
    pub async fn member(
        &self,
        group_id: &str,
        actor: &Actor,
    ) -> Result<Option<StoredMember>, DbError> {
        Ok(self.member_row(group_id, actor).await?.filter(|m| m.active))
    }

    /// `actor`'s membership row of `group_id`, pending or active.
    pub async fn member_row(
        &self,
        group_id: &str,
        actor: &Actor,
    ) -> Result<Option<StoredMember>, DbError> {
        let q = Ql::new("Membership.filter(.key == ")
            .str(&member_key(group_id, actor))
            .raw(")");
        Ok(decode_all(self.db.fetch::<MemberRow>(&q).await?)?
            .into_iter()
            .next())
    }

    /// `actor`'s role in `group_id`, if they are an active (non-owner)
    /// member.
    pub async fn role_of(&self, group_id: &str, actor: &Actor) -> Result<Option<String>, DbError> {
        Ok(self.member(group_id, actor).await?.map(|m| m.role))
    }

    /// The active memberships of `group_id`, at most `cap`, in no
    /// particular order.
    pub async fn members(&self, group_id: &str, cap: usize) -> Result<Vec<StoredMember>, DbError> {
        let q = Ql::new("Membership.filter(.group_id == ")
            .str(group_id)
            .raw(" && .status == ")
            .str(status::ACTIVE)
            .raw(").limit(")
            .uint(cap as u64)
            .raw(")");
        decode_all(self.db.fetch::<MemberRow>(&q).await?)
    }

    /// How many membership rows `group_id` has, pending ones included (so
    /// a limit on it errs on the safe side), counting no further than
    /// `cap`. A filter on the one indexed field plus `.limit` counts only
    /// live rows (rhypedb 7b78190, docs/decisions/0014).
    pub async fn member_count(&self, group_id: &str, cap: usize) -> Result<usize, DbError> {
        let q = Ql::new("Membership.filter(.group_id == ")
            .str(group_id)
            .raw(").limit(")
            .uint(cap as u64)
            .raw(")");
        Ok(self.db.fetch::<serde::de::IgnoredAny>(&q).await?.len())
    }

    /// The roles of those of `actors` who are active (non-owner) members
    /// of `group_id`, in as few queries as fit (live fan-out checks every
    /// subscriber of a channel at once).
    pub async fn roles_of(
        &self,
        group_id: &str,
        actors: &[Actor],
    ) -> Result<std::collections::HashMap<Actor, String>, DbError> {
        #[derive(Deserialize)]
        struct KeyedRole {
            actor: String,
            role: String,
            status: String,
        }
        let keys: Vec<String> = actors.iter().map(|a| member_key(group_id, a)).collect();
        let rows: Vec<KeyedRole> =
            crate::db::lookup::lookup(&self.db, "Membership.filter(", ".key == ", &keys).await?;
        Ok(rows
            .into_iter()
            .filter(|r| r.status == status::ACTIVE)
            .filter_map(|r| Some((Actor::parse_canonical(&r.actor).ok()?, r.role)))
            .collect())
    }

    /// Every one of `actor`'s active memberships as `(group_id, role)`,
    /// however many (their groups may be active or being deleted): read
    /// `expected` at a time first, more only when that comes back full
    /// (`read_whole` in `store.rs`).
    pub async fn all_memberships_of(
        &self,
        actor: &Actor,
        expected: usize,
    ) -> Result<Vec<(String, String)>, DbError> {
        super::store::read_whole(expected, |cap| self.memberships_of(actor, cap)).await
    }

    /// `actor`'s active memberships as `(group_id, role)`, at most `cap`
    /// (their groups may be active or being deleted).
    pub async fn memberships_of(
        &self,
        actor: &Actor,
        cap: usize,
    ) -> Result<Vec<(String, String)>, DbError> {
        let q = Ql::new("Membership.filter(.actor == ")
            .str(&actor.to_string())
            .raw(" && .status == ")
            .str(status::ACTIVE)
            .raw(").limit(")
            .uint(cap as u64)
            .raw(")");
        Ok(decode_all(self.db.fetch::<MemberRow>(&q).await?)?
            .into_iter()
            .map(|m| (m.group_id, m.role))
            .collect())
    }

    /// Write a `pending` membership of `actor` in `group_id` with `role`
    /// and nickname `display_name`; [`Self::activate_member`] makes it
    /// count. `false` if a membership (pending or active) already exists.
    pub async fn add_member(
        &self,
        group_id: &str,
        actor: &Actor,
        role: &str,
        display_name: Option<&str>,
        now: i64,
    ) -> Result<bool, DbError> {
        let mut q = Ql::new("Membership.create({ key: ")
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
            .raw(", updated_at: ")
            .unix_seconds(now);
        if let Some(name) = display_name {
            q = q.raw(", display_name_override: ").str(name);
        }
        match self.db.execute(&q.raw(" })")).await {
            Ok(()) => Ok(true),
            // Taken, or another create of this key won at commit.
            Err(DbError::Conflict(_) | DbError::Contended(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Make a pending membership count. `false` if it is gone (its group
    /// was purged, or it expired) or already active.
    pub async fn activate_member(&self, group_id: &str, actor: &Actor) -> Result<bool, DbError> {
        let q = Ql::new("Membership.filter(.key == ")
            .str(&member_key(group_id, actor))
            .raw(" && .status == ")
            .str(status::PENDING)
            .raw(").update({ status: ")
            .str(status::ACTIVE)
            .raw(" })");
        Ok(!self
            .db
            .write_one_object(&q)
            .await?
            .into_objects()
            .is_empty())
    }

    /// Change an active member's role at `now`: the row as written, or
    /// `None` if not a member. Writing the role it already has changes
    /// nothing but `updated_at`; callers skip that case.
    pub async fn set_role(
        &self,
        group_id: &str,
        actor: &Actor,
        role: &str,
        now: i64,
    ) -> Result<Option<StoredMember>, DbError> {
        let q = Ql::new("Membership.filter(.key == ")
            .str(&member_key(group_id, actor))
            .raw(" && .status == ")
            .str(status::ACTIVE)
            .raw(").update({ role: ")
            .str(role)
            .raw(", updated_at: ")
            .unix_seconds(now)
            .raw(" })");
        written(self.db.write_one_object_as::<MemberRow>(&q).await?)
    }

    /// Set (or, with `None`, clear) an active member's nickname: the row
    /// as written, or `None` if not a member.
    pub async fn set_member_display_name(
        &self,
        group_id: &str,
        actor: &Actor,
        display_name: Option<&str>,
    ) -> Result<Option<StoredMember>, DbError> {
        let q = Ql::new("Membership.filter(.key == ")
            .str(&member_key(group_id, actor))
            .raw(" && .status == ")
            .str(status::ACTIVE)
            .raw(").update({ display_name_override: ");
        let q = match display_name {
            Some(name) => q.str(name),
            None => q.raw("null"),
        };
        written(
            self.db
                .write_one_object_as::<MemberRow>(&q.raw(" })"))
                .await?,
        )
    }

    /// End `actor`'s membership of `group_id`, pending or active (a no-op
    /// if there is none). An `ended` row (a deleting group's, `ending.rs`)
    /// is left for the purge, so the sweeper can still name its member.
    pub async fn remove_member(&self, group_id: &str, actor: &Actor) -> Result<(), DbError> {
        let q = Ql::new("Membership.filter(.key == ")
            .str(&member_key(group_id, actor))
            .raw(" && .status != ")
            .str(status::ENDED)
            .raw(").delete()");
        self.db.write_one_object(&q).await.map(|_| ())
    }

    /// Begin removing `actor`'s active membership of `group_id` at `now`:
    /// from this write on it is `leaving`, no longer a membership. Answers
    /// the row as written, so with the transfer mark it carried at that
    /// instant, or `None` if there was no active membership.
    pub(super) async fn retire_member(
        &self,
        group_id: &str,
        actor: &Actor,
        now: i64,
    ) -> Result<Option<StoredMember>, DbError> {
        let q = Ql::new("Membership.filter(.key == ")
            .str(&member_key(group_id, actor))
            .raw(" && .status == ")
            .str(status::ACTIVE)
            .raw(").update({ status: ")
            .str(status::LEAVING)
            .raw(", updated_at: ")
            .unix_seconds(now)
            .raw(" })");
        written(self.db.write_one_object_as::<MemberRow>(&q).await?)
    }

    /// Make the membership [`Self::retire_member`] began removing at
    /// `retired_at` active again (a no-op if it is gone, or is another
    /// removal's).
    pub(super) async fn restore_member(
        &self,
        group_id: &str,
        actor: &Actor,
        retired_at: i64,
    ) -> Result<(), DbError> {
        let q = Self::retired_row(group_id, actor, retired_at)
            .raw(").update({ status: ")
            .str(status::ACTIVE)
            .raw(" })");
        self.db.write_one_object(&q).await.map(|_| ())
    }

    /// Finish removing the membership [`Self::retire_member`] began
    /// removing at `retired_at`. Never deletes a row written since: a
    /// removal stalled past `PENDING_TTL` has had its row swept, and the
    /// actor may have joined again.
    pub(super) async fn delete_retired_member(
        &self,
        group_id: &str,
        actor: &Actor,
        retired_at: i64,
    ) -> Result<(), DbError> {
        let q = Self::retired_row(group_id, actor, retired_at).raw(").delete()");
        self.db.write_one_object(&q).await.map(|_| ())
    }

    /// Delete `actor`'s pending membership of `group_id` (a join still
    /// being recorded), if any. An active or leaving row is untouched.
    pub(super) async fn delete_pending_member(
        &self,
        group_id: &str,
        actor: &Actor,
    ) -> Result<(), DbError> {
        let q = Ql::new("Membership.filter(.key == ")
            .str(&member_key(group_id, actor))
            .raw(" && .status == ")
            .str(status::PENDING)
            .raw(").delete()");
        self.db.write_one_object(&q).await.map(|_| ())
    }

    /// The open filter (no closing parenthesis) for `actor`'s row of
    /// `group_id` as [`Self::retire_member`] left it at `retired_at`.
    fn retired_row(group_id: &str, actor: &Actor, retired_at: i64) -> Ql {
        Ql::new("Membership.filter(.key == ")
            .str(&member_key(group_id, actor))
            .raw(" && .status == ")
            .str(status::LEAVING)
            .raw(" && .updated_at == ")
            .unix_seconds(retired_at)
    }

    /// Mark `actor`'s active membership of `group_id` as the target of
    /// transfer `transfer_id`: the row as written, or `None` if there is no
    /// active membership. A mark an earlier attempt left is replaced.
    pub async fn mark_transfer(
        &self,
        group_id: &str,
        actor: &Actor,
        transfer_id: &str,
    ) -> Result<Option<StoredMember>, DbError> {
        let q = Ql::new("Membership.filter(.key == ")
            .str(&member_key(group_id, actor))
            .raw(" && .status == ")
            .str(status::ACTIVE)
            .raw(").update({ transfer_id: ")
            .str(transfer_id)
            .raw(" })");
        written(self.db.write_one_object_as::<MemberRow>(&q).await?)
    }

    /// `actor`'s membership row of `group_id` if transfer `transfer_id`
    /// marked it, whatever its status.
    pub async fn transferred_member(
        &self,
        group_id: &str,
        actor: &Actor,
        transfer_id: &str,
    ) -> Result<Option<StoredMember>, DbError> {
        let q = Ql::new("Membership.filter(.key == ")
            .str(&member_key(group_id, actor))
            .raw(" && .transfer_id == ")
            .str(transfer_id)
            .raw(")");
        Ok(decode_all(self.db.fetch::<MemberRow>(&q).await?)?
            .into_iter()
            .next())
    }

    /// Remove `actor`'s membership row of `group_id` only if transfer
    /// `transfer_id` marked it: never a row written since, which carries no
    /// mark or another one (docs/decisions/0020).
    pub async fn remove_transferred_member(
        &self,
        group_id: &str,
        actor: &Actor,
        transfer_id: &str,
    ) -> Result<(), DbError> {
        let q = Ql::new("Membership.filter(.key == ")
            .str(&member_key(group_id, actor))
            .raw(" && .transfer_id == ")
            .str(transfer_id)
            .raw(").delete()");
        self.db.write_one_object(&q).await.map(|_| ())
    }

    /// Make `actor`'s active row of `group_id` the one they will hold once
    /// they hand the group on: role `role`, nickname `display_name`, the
    /// `joined_at` they hold as owner (unix seconds, kept through the
    /// transfer: lost-conn/ofscp#35), and no transfer mark (one a past
    /// transfer to them left must not let its late finisher delete this
    /// row). The row as written, or `None` if there is no active row.
    pub(super) async fn reset_former_owner_row(
        &self,
        group_id: &str,
        actor: &Actor,
        role: &str,
        display_name: Option<&str>,
        joined_at: i64,
        now: i64,
    ) -> Result<Option<StoredMember>, DbError> {
        let q = Ql::new("Membership.filter(.key == ")
            .str(&member_key(group_id, actor))
            .raw(" && .status == ")
            .str(status::ACTIVE)
            .raw(").update({ role: ")
            .str(role)
            .raw(", joined_at: ")
            .unix_seconds(joined_at)
            .raw(", updated_at: ")
            .unix_seconds(now)
            .raw(", transfer_id: null, display_name_override: ");
        let q = match display_name {
            Some(name) => q.str(name),
            None => q.raw("null"),
        };
        written(
            self.db
                .write_one_object_as::<MemberRow>(&q.raw(" })"))
                .await?,
        )
    }

    /// Remove the pending memberships written before `cutoff` (unix
    /// seconds), and the leaving ones a remover left since before then.
    pub(super) async fn expire_pending_members(&self, cutoff: i64) -> Result<(), DbError> {
        let pending = Ql::new("Membership.filter(.status == ")
            .str(status::PENDING)
            .raw(" && .joined_at < ")
            .unix_seconds(cutoff)
            .raw(").delete()");
        let leaving = Ql::new("Membership.filter(.status == ")
            .str(status::LEAVING)
            .raw(" && .updated_at < ")
            .unix_seconds(cutoff)
            .raw(").delete()");
        // Try both, so one failing does not leave the other's rows.
        let pending = self.db.execute(&pending).await;
        let leaving = self.db.execute(&leaving).await;
        pending.and(leaving)
    }
}
