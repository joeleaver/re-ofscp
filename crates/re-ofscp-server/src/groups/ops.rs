//! Group and channel operations (§5.5), independent of HTTP. Every read
//! goes through [`Groups::read_group`] or [`Groups::read_channel`], which
//! apply the [`access`](super::access) rule; later surfaces (history,
//! subscriptions, notifications, discovery samples) use the same two.

use re_ofscp_types::Actor;
use re_ofscp_types::groups::{
    Channel, ChannelCreateRequest, ChannelUpdateRequest, Group, GroupCreateRequest,
    GroupUpdateRequest,
};

use super::access::{self, Standing, actions};
use super::model::{self, StoredChannel, StoredGroup};
use super::validate::Invalid;
use super::{AccessChange, Caller, Groups, MAX_CHANNELS_PER_GROUP, MAX_GROUPS_PER_OWNER};
use crate::db::DbError;

/// How often a conditional update is retried against a fresh read before
/// the request is answered `409`.
const UPDATE_ATTEMPTS: usize = 5;

/// Most channel rows one listing reads. A group holds at most
/// [`MAX_CHANNELS_PER_GROUP`] channels once concurrent creates settle, but
/// creates over the limit exist briefly before they are taken back; the
/// margin keeps those from crowding real channels out of a listing.
const LIST_FETCH_LIMIT: usize = 2 * MAX_CHANNELS_PER_GROUP;

/// Why an operation failed. Each maps to one problem (§7.3).
#[derive(Debug, thiserror::Error)]
pub enum GroupError {
    /// `404`: no such group or channel.
    #[error("{0}")]
    NotFound(&'static str),
    /// `403`: the caller may not do this.
    #[error("{0}")]
    Forbidden(&'static str),
    /// `400`: the request is invalid.
    #[error(transparent)]
    Invalid(#[from] Invalid),
    /// `409`: the object kept changing underneath the update.
    #[error("{0}")]
    Conflict(&'static str),
    /// The database failed.
    #[error(transparent)]
    Db(#[from] DbError),
}

/// A group the caller may read, with their standing.
#[derive(Debug, Clone)]
pub struct ReadableGroup {
    /// The group.
    pub group: StoredGroup,
    /// The caller's standing.
    pub standing: Standing,
}

const NO_GROUP: &str = "no such group";
const NO_CHANNEL: &str = "no such channel";
const GROUP_HIDDEN: &str = "this group is visible to its members only";
const GROUP_LIMIT: &str = "you already own the most groups this provider allows";
const CHANNEL_LIMIT: &str = "this group has the most channels this provider allows";
const NOT_MANAGER: &str = "you may not manage this group";

impl Groups {
    /// The group, if it exists (`404`) and the caller may read it (`403`,
    /// §5.5).
    pub async fn read_group(
        &self,
        caller: &Caller,
        group_id: &str,
    ) -> Result<ReadableGroup, GroupError> {
        let group = self
            .store
            .group(group_id)
            .await?
            .ok_or(GroupError::NotFound(NO_GROUP))?;
        let standing = self.standing(caller, &group).await?;
        if !access::can_read_group(&standing, &group.policy()) {
            return Err(GroupError::Forbidden(GROUP_HIDDEN));
        }
        Ok(ReadableGroup { group, standing })
    }

    /// The channel, if it exists and the caller has effective read access
    /// to it (§11.3). A channel the caller cannot read, for any §11.3
    /// reason (its group's tier included), is answered exactly as one that
    /// does not exist: `404` (lost-conn/ofscp#26). Otherwise a `403` would
    /// tell an outsider which channel ids are real. Only group-level routes
    /// answer an unreadable group `403`.
    pub async fn read_channel(
        &self,
        caller: &Caller,
        group_id: &str,
        channel_id: &str,
    ) -> Result<(ReadableGroup, StoredChannel), GroupError> {
        let g = match self.read_group(caller, group_id).await {
            Err(GroupError::Forbidden(_)) => return Err(GroupError::NotFound(NO_CHANNEL)),
            other => other?,
        };
        let channel = self
            .store
            .channel(group_id, channel_id)
            .await?
            .filter(|c| access::can_read_channel(&g.standing, &g.group.policy(), &c.policy()))
            .ok_or(GroupError::NotFound(NO_CHANNEL))?;
        Ok((g, channel))
    }

    /// The channel, for a caller who must `manage` its group: first read
    /// access as [`Self::read_channel`] (`404` for a channel the caller
    /// cannot read, even a `manage` holder whom `view` leaves out), then
    /// `403` without `manage` (§5.5, lost-conn/ofscp#26).
    async fn managed_channel(
        &self,
        actor: &Actor,
        group_id: &str,
        channel_id: &str,
    ) -> Result<StoredChannel, GroupError> {
        let caller = Caller::Actor(actor.clone());
        let (g, channel) = self.read_channel(&caller, group_id, channel_id).await?;
        if !access::may(&g.standing, &g.group.policy(), actions::MANAGE) {
            return Err(GroupError::Forbidden(NOT_MANAGER));
        }
        Ok(channel)
    }

    /// The group, for a caller who must hold `action` on it. A caller who
    /// cannot read the group gets the same `403` as one who can but lacks
    /// the action.
    async fn group_for(
        &self,
        actor: &Actor,
        group_id: &str,
        action: &str,
    ) -> Result<StoredGroup, GroupError> {
        let group = self
            .store
            .group(group_id)
            .await?
            .ok_or(GroupError::NotFound(NO_GROUP))?;
        let standing = self.standing(&Caller::Actor(actor.clone()), &group).await?;
        if !access::may(&standing, &group.policy(), action) {
            return Err(GroupError::Forbidden(NOT_MANAGER));
        }
        Ok(group)
    }

    /// `POST /api/groups`: `owner` (a local actor; the route checks) creates
    /// a group and becomes its owner.
    pub async fn create_group(
        &self,
        owner: &Actor,
        req: GroupCreateRequest,
        now: i64,
    ) -> Result<Group, GroupError> {
        let fields = model::new_group(req)?;
        let cap = MAX_GROUPS_PER_OWNER;
        if self.store.owned_count(owner, cap + 1).await? >= cap {
            return Err(GroupError::Forbidden(GROUP_LIMIT));
        }
        let group = self.store.create_group(owner, &fields, now).await?;
        // Checked again after the write, as for channels: a create that
        // finds its owner over the limit takes its group back.
        if self.store.owned_count(owner, cap + 1).await? > cap {
            if self.store.mark_deleting(&group.id).await? {
                self.store.purge_group(&group.id).await?;
            }
            return Err(GroupError::Forbidden(GROUP_LIMIT));
        }
        Ok(group.to_wire())
    }

    /// `GET /api/groups/{groupId}`.
    pub async fn get_group(&self, caller: &Caller, group_id: &str) -> Result<Group, GroupError> {
        Ok(self.read_group(caller, group_id).await?.group.to_wire())
    }

    /// `PATCH /api/groups/{groupId}`: needs `manage`.
    pub async fn update_group(
        &self,
        actor: &Actor,
        group_id: &str,
        patch: &GroupUpdateRequest,
        now: i64,
    ) -> Result<Group, GroupError> {
        for _ in 0..UPDATE_ATTEMPTS {
            // Re-read and re-authorize on every attempt: a concurrent change
            // may have revoked the caller's `manage`.
            let group = self.group_for(actor, group_id, actions::MANAGE).await?;
            let Some(fields) = model::patch_group(&group, patch)? else {
                return Ok(group.to_wire());
            };
            if let Some(updated) = self.store.update_group(&group, &fields, now).await? {
                self.changed(AccessChange::Group {
                    group_id: group_id.to_owned(),
                });
                return Ok(updated.to_wire());
            }
        }
        Err(GroupError::Conflict("the group kept changing; retry"))
    }

    /// `DELETE /api/groups/{groupId}`: owner only. The group disappears
    /// at once; its channels and memberships are purged after, and the
    /// sweeper finishes the purge if this one is interrupted.
    pub async fn delete_group(&self, actor: &Actor, group_id: &str) -> Result<(), GroupError> {
        let group = self
            .store
            .group(group_id)
            .await?
            .ok_or(GroupError::NotFound(NO_GROUP))?;
        if group.owner != *actor {
            return Err(GroupError::Forbidden("only the owner may delete a group"));
        }
        if !self.store.mark_deleting(group_id).await? {
            return Err(GroupError::NotFound(NO_GROUP));
        }
        self.changed(AccessChange::Group {
            group_id: group_id.to_owned(),
        });
        if let Err(e) = self.store.purge_group(group_id).await {
            tracing::warn!(error = %e, group_id, "purging a deleted group failed; the sweeper will finish it");
        }
        Ok(())
    }

    /// `GET /api/groups/{groupId}/channels`: only the channels the caller
    /// may read (§11.3); the others are omitted, not marked.
    pub async fn list_channels(
        &self,
        caller: &Caller,
        group_id: &str,
    ) -> Result<Vec<Channel>, GroupError> {
        let g = self.read_group(caller, group_id).await?;
        let policy = g.group.policy();
        Ok(self
            .store
            .channels(group_id, LIST_FETCH_LIMIT)
            .await?
            .iter()
            .filter(|c| access::can_read_channel(&g.standing, &policy, &c.policy()))
            .map(StoredChannel::to_wire)
            .collect())
    }

    /// `POST /api/groups/{groupId}/channels`: needs `manage`.
    pub async fn create_channel(
        &self,
        actor: &Actor,
        group_id: &str,
        req: ChannelCreateRequest,
        now: i64,
    ) -> Result<Channel, GroupError> {
        let (kind, fields) = model::new_channel(req)?;
        self.group_for(actor, group_id, actions::MANAGE).await?;
        if self.channel_count(group_id).await? >= MAX_CHANNELS_PER_GROUP {
            return Err(GroupError::Forbidden(CHANNEL_LIMIT));
        }
        let channel = self
            .store
            .create_channel(group_id, kind, &fields, now)
            .await?;
        // Checked again after the write, so the limit holds without a
        // transaction: of concurrent creates, any that sees the group over
        // the limit (its own channel included) takes its channel back, and
        // whichever checks last sees every channel written before it.
        if self.channel_count(group_id).await? > MAX_CHANNELS_PER_GROUP {
            self.store.delete_channel(group_id, &channel.id).await?;
            return Err(GroupError::Forbidden(CHANNEL_LIMIT));
        }
        // The group may have been deleted while this channel was being
        // written; then the channel must not outlive it.
        if self.store.group(group_id).await?.is_none() {
            self.store.delete_channel(group_id, &channel.id).await?;
            return Err(GroupError::NotFound(NO_GROUP));
        }
        Ok(channel.to_wire())
    }

    /// `GET /api/groups/{groupId}/channels/{channelId}`.
    pub async fn get_channel(
        &self,
        caller: &Caller,
        group_id: &str,
        channel_id: &str,
    ) -> Result<Channel, GroupError> {
        Ok(self
            .read_channel(caller, group_id, channel_id)
            .await?
            .1
            .to_wire())
    }

    /// `PATCH /api/groups/{groupId}/channels/{channelId}`: needs `manage`.
    pub async fn update_channel(
        &self,
        actor: &Actor,
        group_id: &str,
        channel_id: &str,
        patch: &ChannelUpdateRequest,
        now: i64,
    ) -> Result<Channel, GroupError> {
        for _ in 0..UPDATE_ATTEMPTS {
            // Re-read and re-authorize on every attempt, as for groups.
            let channel = self.managed_channel(actor, group_id, channel_id).await?;
            let Some(fields) = model::patch_channel(&channel, patch)? else {
                return Ok(channel.to_wire());
            };
            if let Some(updated) = self.store.update_channel(&channel, &fields, now).await? {
                self.channel_changed(group_id, channel_id);
                return Ok(updated.to_wire());
            }
        }
        Err(GroupError::Conflict("the channel kept changing; retry"))
    }

    /// `DELETE /api/groups/{groupId}/channels/{channelId}`: needs `manage`.
    pub async fn delete_channel(
        &self,
        actor: &Actor,
        group_id: &str,
        channel_id: &str,
    ) -> Result<(), GroupError> {
        self.managed_channel(actor, group_id, channel_id).await?;
        self.store.delete_channel(group_id, channel_id).await?;
        self.channel_changed(group_id, channel_id);
        Ok(())
    }

    /// How many channels `group_id` has, counting at most one past the
    /// limit.
    async fn channel_count(&self, group_id: &str) -> Result<usize, GroupError> {
        Ok(self
            .store
            .channel_count(group_id, MAX_CHANNELS_PER_GROUP + 1)
            .await?)
    }

    fn channel_changed(&self, group_id: &str, channel_id: &str) {
        self.changed(AccessChange::Channel {
            group_id: group_id.to_owned(),
            channel_id: channel_id.to_owned(),
        });
    }
}
