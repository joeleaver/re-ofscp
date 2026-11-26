//! Groups, channels and memberships in rhypedb (`Group`, `Channel`,
//! `Membership` in `schema.rhype`). Every query goes through [`Ql`].

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use re_ofscp_types::Actor;
use re_ofscp_types::groups::{ChannelType, JoinPolicy, Tier};
use serde::Deserialize;

use super::model::{ChannelFields, GroupFields, StoredChannel, StoredGroup};
use crate::db::{Db, DbError, Ql};

/// `Group.status` values.
mod status {
    /// Visible and usable.
    pub const ACTIVE: &str = "active";
    /// Being deleted: invisible everywhere, children being removed.
    pub const DELETING: &str = "deleting";
}

#[derive(Deserialize)]
struct GroupRow {
    group_id: String,
    owner: String,
    name: String,
    tier: String,
    join_policy: String,
    revision: i64,
    doc: String,
    created_at: String,
    updated_at: String,
}

impl GroupRow {
    fn decode(self) -> Result<StoredGroup, DbError> {
        let bad = |what: &str| DbError::Decode(format!("group {}: bad {what}", self.group_id));
        Ok(StoredGroup {
            owner: Actor::parse_canonical(&self.owner).map_err(|_| bad("owner"))?,
            tier: Tier::parse(&self.tier).ok_or_else(|| bad("tier"))?,
            join_policy: JoinPolicy::parse(&self.join_policy).ok_or_else(|| bad("join_policy"))?,
            doc: serde_json::from_str(&self.doc).map_err(|_| bad("doc"))?,
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
struct RoleRow {
    role: String,
}

#[derive(Deserialize)]
struct GroupIdRow {
    group_id: String,
}

/// A fresh local id: `prefix` + 128 random bits, base64url (§2.2).
fn new_id(prefix: &'static str) -> Result<String, DbError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| DbError::Query(format!("random source: {e}")))?;
    Ok(format!("{prefix}{}", B64URL.encode(bytes)))
}

fn json<T: serde::Serialize>(value: &T) -> Result<String, DbError> {
    serde_json::to_string(value).map_err(|e| DbError::Query(format!("encoding a document: {e}")))
}

fn decode_updated<R, T>(
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

/// The membership key: one row per (group, actor).
fn member_key(group_id: &str, actor: &Actor) -> String {
    format!("{group_id} {actor}")
}

/// Group, channel and membership storage.
#[derive(Debug, Clone)]
pub struct GroupStore {
    db: Arc<Db>,
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
                .raw(" })");
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

    /// How many groups `owner` owns, counting at most `cap`.
    pub async fn owned_count(&self, owner: &Actor, cap: usize) -> Result<usize, DbError> {
        let q = Ql::new("Group.filter(.owner == ")
            .str(&owner.to_string())
            .raw(").limit(")
            .uint(cap as u64)
            .raw(")");
        Ok(self.db.fetch::<serde::de::IgnoredAny>(&q).await?.len())
    }

    /// Write `fields` to `group` if nobody changed it since it was read
    /// (its revision is unchanged). `None` when the revision moved on or
    /// the group is gone or being deleted.
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
        decode_updated(self.db.write_rows(&q).await?, GroupRow::decode)
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
        Ok(!self.db.write_rows(&q).await?.into_objects().is_empty())
    }

    /// Remove a group being deleted: its channels, its memberships, then
    /// the group row. Each step is idempotent, so an interrupted purge is
    /// simply run again.
    pub async fn purge_group(&self, group_id: &str) -> Result<(), DbError> {
        let channels = Ql::new("Channel.filter(.group_id == ")
            .str(group_id)
            .raw(").delete()");
        self.db.execute(&channels).await?;
        let members = Ql::new("Membership.filter(.group_id == ")
            .str(group_id)
            .raw(").delete()");
        self.db.execute(&members).await?;
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

    /// Create a channel in `group_id`. The caller has checked the group.
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

    /// Up to `limit` channels of `group_id`, oldest first.
    pub async fn channels(
        &self,
        group_id: &str,
        limit: usize,
    ) -> Result<Vec<StoredChannel>, DbError> {
        let q = Ql::new("Channel.filter(.group_id == ")
            .str(group_id)
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

    /// How many channels `group_id` has, counting at most `cap`.
    pub async fn channel_count(&self, group_id: &str, cap: usize) -> Result<usize, DbError> {
        let q = Ql::new("Channel.filter(.group_id == ")
            .str(group_id)
            .raw(").limit(")
            .uint(cap as u64)
            .raw(")");
        Ok(self.db.fetch::<serde::de::IgnoredAny>(&q).await?.len())
    }

    /// Channel `channel_id` of `group_id`, if any.
    pub async fn channel(
        &self,
        group_id: &str,
        channel_id: &str,
    ) -> Result<Option<StoredChannel>, DbError> {
        let q = Ql::new("Channel.filter(.channel_id == ")
            .str(channel_id)
            .raw(" && .group_id == ")
            .str(group_id)
            .raw(")");
        match self.db.fetch::<ChannelRow>(&q).await?.into_iter().next() {
            Some(row) => row.data.decode().map(Some),
            None => Ok(None),
        }
    }

    /// Write `fields` to `channel` if its revision is unchanged. `None`
    /// when the revision moved on or the channel is gone.
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
        decode_updated(self.db.write_rows(&q).await?, ChannelRow::decode)
    }

    /// Delete channel `channel_id` of `group_id` (a no-op if it is gone).
    pub async fn delete_channel(&self, group_id: &str, channel_id: &str) -> Result<(), DbError> {
        let q = Ql::new("Channel.filter(.channel_id == ")
            .str(channel_id)
            .raw(" && .group_id == ")
            .str(group_id)
            .raw(").delete()");
        self.db.execute(&q).await
    }

    /// `actor`'s role in `group_id`, if they are a (non-owner) member.
    pub async fn role_of(&self, group_id: &str, actor: &Actor) -> Result<Option<String>, DbError> {
        let q = Ql::new("Membership.filter(.key == ")
            .str(&member_key(group_id, actor))
            .raw(")");
        Ok(self
            .db
            .fetch::<RoleRow>(&q)
            .await?
            .into_iter()
            .next()
            .map(|r| r.data.role))
    }

    /// Record `actor` as a member of `group_id` with `role`. `false` if
    /// they already are one. Used by membership (§5.7) and invites (§5.6).
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
            .raw(", joined_at: ")
            .unix_seconds(now)
            .raw(" })");
        match self.db.execute(&q).await {
            Ok(()) => Ok(true),
            Err(DbError::Conflict(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Change `actor`'s role in `group_id`. `false` if not a member.
    pub async fn set_role(
        &self,
        group_id: &str,
        actor: &Actor,
        role: &str,
    ) -> Result<bool, DbError> {
        let q = Ql::new("Membership.filter(.key == ")
            .str(&member_key(group_id, actor))
            .raw(").update({ role: ")
            .str(role)
            .raw(" })");
        Ok(!self.db.write_rows(&q).await?.into_objects().is_empty())
    }

    /// End `actor`'s membership of `group_id` (a no-op if there is none).
    pub async fn remove_member(&self, group_id: &str, actor: &Actor) -> Result<(), DbError> {
        let q = Ql::new("Membership.filter(.key == ")
            .str(&member_key(group_id, actor))
            .raw(").delete()");
        self.db.execute(&q).await
    }
}
