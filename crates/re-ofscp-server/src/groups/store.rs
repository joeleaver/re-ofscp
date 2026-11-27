//! Groups and channels in rhypedb (`Group` and `Channel` in
//! `schema.rhype`; memberships are in `members.rs`). Every query goes
//! through [`Ql`].
//!
//! Without transactions, a row that belongs to a group is written
//! `pending` (invisible to every read), and made `active` only once its
//! writer has confirmed that the group is still active. Purging a group
//! removes its rows in either state, and [`GroupStore::expire_pending`]
//! removes pending rows a crashed or failed writer left behind. So no row
//! outlives its group, whatever a writer's timing.

use std::sync::Arc;

use re_ofscp_types::Actor;
use re_ofscp_types::groups::{ChannelType, JoinPolicy, Tier};
use serde::Deserialize;

use super::model::{ChannelFields, GroupFields, PendingTransfer, StoredChannel, StoredGroup};
use crate::db::doc::{json, new_id};
use crate::db::{Db, DbError, Ql};

/// `status` values (`Group`, `Channel`, `Membership`).
pub(super) mod status {
    /// Visible and usable.
    pub const ACTIVE: &str = "active";
    /// A group being deleted: invisible everywhere, children being removed.
    pub const DELETING: &str = "deleting";
    /// A channel or membership written but not yet confirmed: invisible.
    pub const PENDING: &str = "pending";
    /// A membership being removed (`member_ops.rs`): invisible, and no
    /// longer a membership. The sweeper deletes one its remover left.
    pub const LEAVING: &str = "leaving";
}

#[derive(Deserialize)]
pub(super) struct GroupRow {
    group_id: String,
    owner: String,
    name: String,
    tier: String,
    join_policy: String,
    revision: i64,
    doc: String,
    created_at: String,
    updated_at: String,
    #[serde(default)]
    owner_display_name: Option<String>,
    #[serde(default)]
    owner_joined_at: Option<String>,
    #[serde(default)]
    transfer_from: Option<String>,
    #[serde(default)]
    transfer_id: Option<String>,
}

impl GroupRow {
    pub(super) fn decode(self) -> Result<StoredGroup, DbError> {
        let bad = |what: &str| DbError::Decode(format!("group {}: bad {what}", self.group_id));
        Ok(StoredGroup {
            owner: Actor::parse_canonical(&self.owner).map_err(|_| bad("owner"))?,
            tier: Tier::parse(&self.tier).ok_or_else(|| bad("tier"))?,
            join_policy: JoinPolicy::parse(&self.join_policy).ok_or_else(|| bad("join_policy"))?,
            doc: serde_json::from_str(&self.doc).map_err(|_| bad("doc"))?,
            owner_joined_at: match self.owner_joined_at.as_deref() {
                Some(t) => Some(crate::timefmt::unix(t).ok_or_else(|| bad("owner_joined_at"))?),
                None => None,
            },
            // Both are set and cleared together.
            transfer: match (self.transfer_from.as_deref(), self.transfer_id) {
                (Some(from), Some(id)) => Some(PendingTransfer {
                    from: Actor::parse_canonical(from).map_err(|_| bad("transfer_from"))?,
                    id,
                }),
                (None, None) => None,
                _ => return Err(bad("transfer")),
            },
            owner_display_name: self.owner_display_name,
            id: self.group_id,
            name: self.name,
            revision: self.revision,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

#[derive(Deserialize)]
struct ChannelRow {
    channel_id: String,
    group_id: String,
    kind: String,
    tier: String,
    revision: i64,
    doc: String,
    created_at: String,
    updated_at: String,
}

impl ChannelRow {
    fn decode(self) -> Result<StoredChannel, DbError> {
        let bad = |what: &str| DbError::Decode(format!("channel {}: bad {what}", self.channel_id));
        Ok(StoredChannel {
            kind: ChannelType::parse(&self.kind).ok_or_else(|| bad("kind"))?,
            tier: Tier::parse(&self.tier).ok_or_else(|| bad("tier"))?,
            doc: serde_json::from_str(&self.doc).map_err(|_| bad("doc"))?,
            id: self.channel_id,
            group_id: self.group_id,
            revision: self.revision,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

#[derive(Deserialize)]
struct GroupIdRow {
    group_id: String,
}

#[derive(Deserialize)]
struct ChannelIdRow {
    channel_id: String,
}

pub(super) fn decode_updated<R, T>(
    result: rhypedb_client::QueryResult,
    decode: impl Fn(R) -> Result<T, DbError>,
) -> Result<Option<T>, DbError>
where
    R: serde::de::DeserializeOwned,
{
    match result.into_objects().first() {
        None => Ok(None),
        Some(o) => {
            let row = rhypedb_client::Row::<R>::from_object(o)
                .map_err(|e| DbError::Decode(e.to_string()))?;
            decode(row.data).map(Some)
        }
    }
}

impl GroupStore {
    /// The one write a revision claim's holder makes. Run once, never
    /// retried, so that it falls within the claim's lease, assuming the
    /// server applies it promptly (claims.rs). A write that
    /// lost a conflict, or met its object deleted, wrote nothing and
    /// returns no rows, and the edit retries from a fresh read.
    pub(super) async fn claimed_write(
        &self,
        q: &Ql,
    ) -> Result<rhypedb_client::QueryResult, DbError> {
        match self.db.write_rows(q).await {
            Err(DbError::Contended(_) | DbError::Vanished(_)) => {
                Ok(rhypedb_client::QueryResult::Objects(Vec::new()))
            }
            other => other,
        }
    }
}

/// Group ids looked up per statement by [`GroupStore::active_groups`].
const GROUPS_PER_LOOKUP: usize = 50;

fn decode_groups(rows: Vec<rhypedb_client::Row<GroupRow>>) -> Result<Vec<StoredGroup>, DbError> {
    rows.into_iter().map(|r| r.data.decode()).collect()
}

/// Group, channel and membership storage.
#[derive(Debug, Clone)]
pub struct GroupStore {
    pub(super) db: Arc<Db>,
}

impl GroupStore {
    /// A store over `db`.
    pub fn new(db: Arc<Db>) -> Self {
        Self { db }
    }

    /// Create an active group owned by `owner`. One statement: the group
    /// exists, with its owner, or it does not.
    pub async fn create_group(
        &self,
        owner: &Actor,
        fields: &GroupFields,
        now: i64,
    ) -> Result<StoredGroup, DbError> {
        // A random 128-bit id colliding is astronomically unlikely; @unique
        // makes it harmless and one retry covers it.
        for _ in 0..2 {
            let q = Ql::new("Group.create({ group_id: ")
                .str(&new_id("grp_")?)
                .raw(", owner: ")
                .str(&owner.to_string())
                .raw(", name: ")
                .str(&fields.name)
                .raw(", tier: ")
                .str(fields.tier.as_str())
                .raw(", join_policy: ")
                .str(fields.join_policy.as_str())
                .raw(", status: ")
                .str(status::ACTIVE)
                .raw(", revision: 0, doc: ")
                .str(&json(&fields.doc)?)
                .raw(", created_at: ")
                .unix_seconds(now)
                .raw(", updated_at: ")
                .unix_seconds(now)
                // Explicit, so that a transfer can guard on it
                // (`owner_store.rs`).
                .raw(", owner_display_name: null })");
            match self.db.write_one::<GroupRow>(&q).await {
                Ok(row) => return row.data.decode(),
                Err(DbError::Conflict(_)) => continue,
                Err(e) => return Err(e),
            }
        }
        Err(DbError::Query(
            "could not allocate a unique group id".to_owned(),
        ))
    }

    /// The active group `group_id`, if any.
    pub async fn group(&self, group_id: &str) -> Result<Option<StoredGroup>, DbError> {
        let q = Ql::new("Group.filter(.group_id == ")
            .str(group_id)
            .raw(" && .status == ")
            .str(status::ACTIVE)
            .raw(")");
        match self.db.fetch::<GroupRow>(&q).await?.into_iter().next() {
            Some(row) => row.data.decode().map(Some),
            None => Ok(None),
        }
    }

    /// The active groups `owner` owns, at most `cap` of them.
    pub async fn owned_groups(
        &self,
        owner: &Actor,
        cap: usize,
    ) -> Result<Vec<StoredGroup>, DbError> {
        let q = Ql::new("Group.filter(.owner == ")
            .str(&owner.to_string())
            .raw(" && .status == ")
            .str(status::ACTIVE)
            .raw(").limit(")
            .uint(cap as u64)
            .raw(")");
        decode_groups(self.db.fetch::<GroupRow>(&q).await?)
    }

    /// Those of `ids` that are active groups, in no particular order.
    pub async fn active_groups(&self, ids: &[String]) -> Result<Vec<StoredGroup>, DbError> {
        let mut found = Vec::with_capacity(ids.len());
        for chunk in ids.chunks(GROUPS_PER_LOOKUP) {
            let mut q = Ql::new("Group.filter(.status == ")
                .str(status::ACTIVE)
                .raw(" && (");
            for (i, id) in chunk.iter().enumerate() {
                q = q.raw(if i == 0 {
                    ".group_id == "
                } else {
                    " || .group_id == "
                });
                q = q.str(id);
            }
            q = q.raw("))");
            found.extend(decode_groups(self.db.fetch::<GroupRow>(&q).await?)?);
        }
        Ok(found)
    }

    /// How many active groups `owner` owns, counting at most `cap`.
    pub async fn owned_count(&self, owner: &Actor, cap: usize) -> Result<usize, DbError> {
        let q = Ql::new("Group.filter(.owner == ")
            .str(&owner.to_string())
            .raw(" && .status == ")
            .str(status::ACTIVE)
            .raw(").limit(")
            .uint(cap as u64)
            .raw(")");
        Ok(self.db.fetch::<serde::de::IgnoredAny>(&q).await?.len())
    }

    /// Write `fields` to `group` as its next revision. The caller must
    /// hold that revision's claim (claims.rs): the filter on the old
    /// revision is compare-and-set per object (rhypedb #59), so it refuses a
    /// stale read even if a claim was taken over.
    /// `None` when the revision moved on or the group is gone or being
    /// deleted.
    pub async fn update_group(
        &self,
        group: &StoredGroup,
        fields: &GroupFields,
        now: i64,
    ) -> Result<Option<StoredGroup>, DbError> {
        let q = Ql::new("Group.filter(.group_id == ")
            .str(&group.id)
            .raw(" && .status == ")
            .str(status::ACTIVE)
            .raw(" && .revision == ")
            .int(group.revision)
            .raw(").update({ name: ")
            .str(&fields.name)
            .raw(", tier: ")
            .str(fields.tier.as_str())
            .raw(", join_policy: ")
            .str(fields.join_policy.as_str())
            .raw(", revision: ")
            .int(group.revision.saturating_add(1))
            .raw(", doc: ")
            .str(&json(&fields.doc)?)
            .raw(", updated_at: ")
            .unix_seconds(now)
            .raw(" })");
        decode_updated(self.claimed_write(&q).await?, GroupRow::decode)
    }

    /// Begin deleting `group_id`: from now on it is invisible. `false` if
    /// it was not active.
    pub async fn mark_deleting(&self, group_id: &str) -> Result<bool, DbError> {
        let q = Ql::new("Group.filter(.group_id == ")
            .str(group_id)
            .raw(" && .status == ")
            .str(status::ACTIVE)
            .raw(").update({ status: ")
            .str(status::DELETING)
            .raw(" })");
        Ok(!self
            .db
            .write_one_object(&q)
            .await?
            .into_objects()
            .is_empty())
    }

    /// Remove a group being deleted: close its channels' message logs
    /// (the messages sweeper purges them, decision 0017), then remove its channels,
    /// memberships (pending, active or leaving) and join requests, then the group
    /// row. Each step is idempotent, so an interrupted purge is simply run
    /// again.
    pub async fn purge_group(&self, group_id: &str) -> Result<(), DbError> {
        crate::messages::log::close_group(&self.db, group_id).await?;
        let channels = Ql::new("Channel.filter(.group_id == ")
            .str(group_id)
            .raw(").delete()");
        self.db.execute(&channels).await?;
        let members = Ql::new("Membership.filter(.group_id == ")
            .str(group_id)
            .raw(").delete()");
        self.db.execute(&members).await?;
        let requests = Ql::new("JoinRequest.filter(.group_id == ")
            .str(group_id)
            .raw(").delete()");
        self.db.execute(&requests).await?;
        let group = Ql::new("Group.filter(.group_id == ")
            .str(group_id)
            .raw(" && .status == ")
            .str(status::DELETING)
            .raw(").delete()");
        self.db.execute(&group).await
    }

    /// Up to `limit` groups whose deletion has begun.
    pub async fn deleting(&self, limit: usize) -> Result<Vec<String>, DbError> {
        let q = Ql::new("Group.filter(.status == ")
            .str(status::DELETING)
            .raw(").limit(")
            .uint(limit as u64)
            .raw(")");
        Ok(self
            .db
            .fetch::<GroupIdRow>(&q)
            .await?
            .into_iter()
            .map(|r| r.data.group_id)
            .collect())
    }

    /// Write a `pending` channel in `group_id`; [`Self::activate_channel`]
    /// makes it visible. The caller has checked the group.
    pub async fn create_channel(
        &self,
        group_id: &str,
        kind: ChannelType,
        fields: &ChannelFields,
        now: i64,
    ) -> Result<StoredChannel, DbError> {
        for _ in 0..2 {
            let q = Ql::new("Channel.create({ channel_id: ")
                .str(&new_id("chn_")?)
                .raw(", group_id: ")
                .str(group_id)
                .raw(", kind: ")
                .str(kind.as_str())
                .raw(", tier: ")
                .str(fields.tier.as_str())
                .raw(", status: ")
                .str(status::PENDING)
                .raw(", revision: 0, doc: ")
                .str(&json(&fields.doc)?)
                .raw(", created_at: ")
                .unix_seconds(now)
                .raw(", updated_at: ")
                .unix_seconds(now)
                .raw(" })");
            match self.db.write_one::<ChannelRow>(&q).await {
                Ok(row) => return row.data.decode(),
                Err(DbError::Conflict(_)) => continue,
                Err(e) => return Err(e),
            }
        }
        Err(DbError::Query(
            "could not allocate a unique channel id".to_owned(),
        ))
    }

    /// Make a pending channel visible. `false` if it is gone (its group
    /// was purged, or it expired).
    pub async fn activate_channel(
        &self,
        group_id: &str,
        channel_id: &str,
    ) -> Result<bool, DbError> {
        let q = Ql::new("Channel.filter(.channel_id == ")
            .str(channel_id)
            .raw(" && .group_id == ")
            .str(group_id)
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

    /// Remove the pending channels and memberships written before `cutoff`
    /// (unix seconds): their writers failed or died before confirming them.
    pub async fn expire_pending(&self, cutoff: i64) -> Result<(), DbError> {
        let channels = Ql::new("Channel.filter(.status == ")
            .str(status::PENDING)
            .raw(" && .created_at < ")
            .unix_seconds(cutoff)
            .raw(").delete()");
        // Try both, so one failing does not leave the other's rows.
        let channels = self.db.execute(&channels).await;
        let members = self.expire_pending_members(cutoff).await;
        channels.and(members)
    }

    /// Up to `limit` active channels of `group_id`, oldest first.
    pub async fn channels(
        &self,
        group_id: &str,
        limit: usize,
    ) -> Result<Vec<StoredChannel>, DbError> {
        let q = Ql::new("Channel.filter(.group_id == ")
            .str(group_id)
            .raw(" && .status == ")
            .str(status::ACTIVE)
            .raw(").limit(")
            .uint(limit as u64)
            .raw(")");
        let mut channels = self
            .db
            .fetch::<ChannelRow>(&q)
            .await?
            .into_iter()
            .map(|r| r.data.decode())
            .collect::<Result<Vec<_>, _>>()?;
        channels.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
        Ok(channels)
    }

    /// How many channels `group_id` has, pending and deleting ones
    /// included (so the limit is conservative), counting no further than
    /// `cap`: the answer is `min(count, cap)`.
    ///
    /// A filter on the one indexed field plus `.limit` is pushed down to an
    /// index scan. Since rhypedb 7b78190 (#61) that scan counts only live
    /// rows toward its limit, so deleted channels cannot make the count
    /// come back short (docs/decisions/0014).
    pub async fn channel_count(&self, group_id: &str, cap: usize) -> Result<usize, DbError> {
        let q = Ql::new("Channel.filter(.group_id == ")
            .str(group_id)
            .raw(").limit(")
            .uint(cap as u64)
            .raw(")");
        Ok(self.db.fetch::<serde::de::IgnoredAny>(&q).await?.len())
    }

    /// Active channel `channel_id` of `group_id`, if any.
    pub async fn channel(
        &self,
        group_id: &str,
        channel_id: &str,
    ) -> Result<Option<StoredChannel>, DbError> {
        let q = Ql::new("Channel.filter(.channel_id == ")
            .str(channel_id)
            .raw(" && .group_id == ")
            .str(group_id)
            .raw(" && .status == ")
            .str(status::ACTIVE)
            .raw(")");
        match self.db.fetch::<ChannelRow>(&q).await?.into_iter().next() {
            Some(row) => row.data.decode().map(Some),
            None => Ok(None),
        }
    }

    /// The ids of every channel row of `group_id`, whatever its status:
    /// whose live readers must re-check access when the group changes.
    ///
    /// Read whole, with no `.limit`, for the reason given at
    /// [`Self::channel_count`]: a limited scan could come back short and
    /// leave a channel's readers unchecked. The group's channel limit
    /// bounds the read.
    pub async fn channel_ids(&self, group_id: &str) -> Result<Vec<String>, DbError> {
        let q = Ql::new("Channel.filter(.group_id == ")
            .str(group_id)
            .raw(")");
        Ok(self
            .db
            .fetch::<ChannelIdRow>(&q)
            .await?
            .into_iter()
            .map(|r| r.data.channel_id)
            .collect())
    }

    /// The group of active channel `channel_id`, if there is one. Channel
    /// ids are unique across groups (`@unique`).
    pub async fn channel_group(&self, channel_id: &str) -> Result<Option<String>, DbError> {
        let q = Ql::new("Channel.filter(.channel_id == ")
            .str(channel_id)
            .raw(" && .status == ")
            .str(status::ACTIVE)
            .raw(")");
        let rows = self.db.fetch::<GroupIdRow>(&q).await?;
        Ok(rows.into_iter().next().map(|r| r.data.group_id))
    }

    /// Write `fields` to `channel` as its next revision, under that
    /// revision's claim, as for [`Self::update_group`]. `None` when the
    /// revision moved on or the channel is gone.
    pub async fn update_channel(
        &self,
        channel: &StoredChannel,
        fields: &ChannelFields,
        now: i64,
    ) -> Result<Option<StoredChannel>, DbError> {
        let q = Ql::new("Channel.filter(.channel_id == ")
            .str(&channel.id)
            .raw(" && .group_id == ")
            .str(&channel.group_id)
            .raw(" && .status == ")
            .str(status::ACTIVE)
            .raw(" && .revision == ")
            .int(channel.revision)
            .raw(").update({ tier: ")
            .str(fields.tier.as_str())
            .raw(", revision: ")
            .int(channel.revision.saturating_add(1))
            .raw(", doc: ")
            .str(&json(&fields.doc)?)
            .raw(", updated_at: ")
            .unix_seconds(now)
            .raw(" })");
        decode_updated(self.claimed_write(&q).await?, ChannelRow::decode)
    }

    /// Delete channel `channel_id` of `group_id`, pending or active (a
    /// no-op if it is gone). Its message log is closed first, so no write
    /// lands after the channel is gone, and the messages sweeper purges
    /// its messages (decision 0017).
    pub async fn delete_channel(&self, group_id: &str, channel_id: &str) -> Result<(), DbError> {
        crate::messages::log::close_channel(&self.db, group_id, channel_id).await?;
        let q = Ql::new("Channel.filter(.channel_id == ")
            .str(channel_id)
            .raw(" && .group_id == ")
            .str(group_id)
            .raw(").delete()");
        self.db.write_one_object(&q).await.map(|_| ())
    }
}
