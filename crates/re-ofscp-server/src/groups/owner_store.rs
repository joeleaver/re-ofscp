//! The owner's columns of a `Group` row: the owner's nickname, and the
//! ownership transfer (`owner`, `transfer_from`, `transfer_id`;
//! docs/decisions/0020). Every query goes through [`Ql`].

use re_ofscp_types::Actor;

use super::model::{Handover, StoredGroup};
use super::store::{GroupRow, GroupStore, decode_updated, status};
use crate::db::{DbError, Ql};

/// Unfinished transfers the sweeper reads per pass.
const TRANSFER_BATCH: u64 = 100;

/// `q` followed by `value` as a string literal, or `null` for `None`.
fn str_or_null(q: Ql, value: Option<&str>) -> Ql {
    match value {
        Some(v) => q.str(v),
        None => q.raw("null"),
    }
}

impl GroupStore {
    /// Set (or, with `None`, clear) the nickname of `owner` while they own
    /// active group `group_id`: the group as written, or `None` if they no
    /// longer own it. Not an edit of the group: neither its revision nor
    /// `updatedAt` moves. Clearing writes an explicit `null`, which a
    /// `== null` filter matches (an absent field matches none).
    pub async fn set_owner_display_name(
        &self,
        group_id: &str,
        owner: &Actor,
        display_name: Option<&str>,
    ) -> Result<Option<StoredGroup>, DbError> {
        let q = Ql::new("Group.filter(.group_id == ")
            .str(group_id)
            .raw(" && .status == ")
            .str(status::ACTIVE)
            .raw(" && .owner == ")
            .str(&owner.to_string())
            .raw(").update({ owner_display_name: ");
        let rows = self
            .db
            .write_one_object(&str_or_null(q, display_name).raw(" })"))
            .await?;
        decode_updated(rows, GroupRow::decode)
    }

    /// Whether group `group_id` holds its owner's nickname as an explicit
    /// `null`. `false` for a value, and for a field never written (a group
    /// created before the field was written at creation): at rhypedb
    /// 7b78190 an absent field matches neither `== null` nor `!= null`.
    pub async fn owner_display_name_is_null(&self, group_id: &str) -> Result<bool, DbError> {
        let q = Ql::new("Group.filter(.group_id == ")
            .str(group_id)
            .raw(" && .owner_display_name == null)");
        Ok(!self.db.fetch::<serde::de::IgnoredAny>(&q).await?.is_empty())
    }

    /// Hand `group` (as read, owned by `group.owner`) to `to` as its next
    /// revision, recording transfer `transfer_id` as unfinished. The caller
    /// holds that revision's claim (claims.rs). The filter is
    /// compare-and-set on the old revision and the owner, and, with
    /// `guard_nickname`, on the owner's nickname: a nickname the old owner
    /// set since `group` was read then fails the write, and the retry
    /// carries it to their new row. (A field never written matches no
    /// filter, so the caller guards only a nickname that is present.)
    /// `None` when the group changed or is gone.
    pub async fn transfer_owner(
        &self,
        group: &StoredGroup,
        guard_nickname: bool,
        handover: &Handover<'_>,
        now: i64,
    ) -> Result<Option<StoredGroup>, DbError> {
        let Handover {
            to,
            display_name: to_display_name,
            joined_at: to_joined_at,
            transfer_id,
        } = *handover;
        let mut q = Ql::new("Group.filter(.group_id == ")
            .str(&group.id)
            .raw(" && .status == ")
            .str(status::ACTIVE)
            .raw(" && .revision == ")
            .int(group.revision)
            .raw(" && .owner == ")
            .str(&group.owner.to_string());
        if guard_nickname {
            q = str_or_null(
                q.raw(" && .owner_display_name == "),
                group.owner_display_name.as_deref(),
            );
        }
        let q = q
            .raw(").update({ owner: ")
            .str(&to.to_string())
            .raw(", transfer_from: ")
            .str(&group.owner.to_string())
            .raw(", transfer_id: ")
            .str(transfer_id)
            .raw(", owner_joined_at: ")
            .unix_seconds(to_joined_at)
            .raw(", revision: ")
            .int(group.revision.saturating_add(1))
            .raw(", updated_at: ")
            .unix_seconds(now)
            .raw(", owner_display_name: ");
        let q = str_or_null(q, to_display_name).raw(" })");
        decode_updated(self.claimed_write(&q).await?, GroupRow::decode)
    }

    /// Move `group` (as read) to its next revision, changing nothing else,
    /// so that an edit prepared against the read revision cannot write. The
    /// caller holds that revision's claim. `None` when the revision or the
    /// owner moved on, or the group is gone.
    pub(super) async fn fence(&self, group: &StoredGroup) -> Result<Option<StoredGroup>, DbError> {
        let q = Ql::new("Group.filter(.group_id == ")
            .str(&group.id)
            .raw(" && .status == ")
            .str(status::ACTIVE)
            .raw(" && .revision == ")
            .int(group.revision)
            .raw(" && .owner == ")
            .str(&group.owner.to_string())
            .raw(").update({ revision: ")
            .int(group.revision.saturating_add(1))
            .raw(" })");
        decode_updated(self.claimed_write(&q).await?, GroupRow::decode)
    }

    /// While transfer `transfer_id` of `group_id` to `owner` is unfinished,
    /// set the owner's nickname to `display_name`: the one their old row
    /// holds, which they may have changed after the transfer read it. A
    /// no-op once the transfer is finished, so it never overwrites a
    /// nickname set since.
    pub(super) async fn carry_owner_display_name(
        &self,
        group_id: &str,
        owner: &Actor,
        transfer_id: &str,
        display_name: Option<&str>,
    ) -> Result<(), DbError> {
        let q = Ql::new("Group.filter(.group_id == ")
            .str(group_id)
            .raw(" && .owner == ")
            .str(&owner.to_string())
            .raw(" && .transfer_id == ")
            .str(transfer_id)
            .raw(").update({ owner_display_name: ");
        let q = str_or_null(q, display_name).raw(" })");
        self.db.write_one_object(&q).await.map(|_| ())
    }

    /// Mark transfer `transfer_id` of `group_id` finished. A no-op once it
    /// is.
    pub async fn clear_transfer(&self, group_id: &str, transfer_id: &str) -> Result<(), DbError> {
        let q = Ql::new("Group.filter(.group_id == ")
            .str(group_id)
            .raw(" && .transfer_id == ")
            .str(transfer_id)
            .raw(").update({ transfer_from: null, transfer_id: null })");
        self.db.write_one_object(&q).await.map(|_| ())
    }

    /// Active groups with an unfinished transfer, a batch at a time.
    pub async fn unfinished_transfers(&self) -> Result<Vec<StoredGroup>, DbError> {
        let q = Ql::new("Group.filter(.transfer_id != null && .status == ")
            .str(status::ACTIVE)
            .raw(").limit(")
            .uint(TRANSFER_BATCH)
            .raw(")");
        self.db
            .fetch::<GroupRow>(&q)
            .await?
            .into_iter()
            .map(|r| r.data.decode())
            .collect()
    }
}
