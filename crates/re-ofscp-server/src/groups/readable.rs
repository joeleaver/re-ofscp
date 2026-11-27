//! Which channels a user can read right now (effective read access, §11.3;
//! security requirement 5), for the surfaces that start from the user
//! rather than from one channel: follows (§7.6), read markers (§7.7) and,
//! later, notifications (§10.1).
//!
//! Every answer is computed from the stored group, channel and membership
//! as they are at the call, never cached, so a change in tier, `view` or
//! membership takes effect on the next request.

use std::collections::{BTreeMap, BTreeSet};

use re_ofscp_types::Actor;

use super::listing::ListingError;
use super::model::StoredChannel;
use super::{Caller, Groups, access};
use crate::db::DbError;

/// What [`Groups::readable_among`] found.
#[derive(Debug, Default)]
pub struct Readable {
    /// The channels the actor can read now, by channel id.
    pub channels: BTreeMap<String, StoredChannel>,
    /// The ids that name no active channel of an active group.
    pub gone: Vec<String>,
}

/// Most channel rows read per group: every active channel fits, with room
/// for rows a concurrent create or delete leaves behind.
const CHANNELS_READ: usize = 2 * super::MAX_CHANNELS_PER_GROUP;

impl Groups {
    /// Active channel `channel_id`, if it exists and `actor` can read it
    /// now. A channel that is missing, in a group being deleted, or
    /// unreadable for any §11.3 reason is `None` alike: callers answer all
    /// three the same way.
    pub async fn readable_channel(
        &self,
        actor: &Actor,
        channel_id: &str,
    ) -> Result<Option<StoredChannel>, DbError> {
        self.channel_for(actor, channel_id, false).await
    }

    /// As [`Self::readable_channel`], but only in a group `actor` owns or
    /// is an active member of: the scopes of read markers (§7.7).
    pub async fn readable_member_channel(
        &self,
        actor: &Actor,
        channel_id: &str,
    ) -> Result<Option<StoredChannel>, DbError> {
        self.channel_for(actor, channel_id, true).await
    }

    async fn channel_for(
        &self,
        actor: &Actor,
        channel_id: &str,
        member_only: bool,
    ) -> Result<Option<StoredChannel>, DbError> {
        // The same checks, in the same order, as `Groups::read_channel`.
        let Some(group_id) = self.store.channel_group(channel_id).await? else {
            return Ok(None);
        };
        let Some(group) = self.store.group(&group_id).await? else {
            return Ok(None);
        };
        let standing = self.standing(&Caller::Actor(actor.clone()), &group).await?;
        let policy = group.policy();
        if (member_only && !standing.is_member()) || !access::can_read_group(&standing, &policy) {
            return Ok(None);
        }
        Ok(self
            .store
            .channel(&group_id, channel_id)
            .await?
            .filter(|c| access::can_read_channel(&standing, &policy, &c.policy())))
    }

    /// Whether active channel `channel_id` exists at all, readable or not.
    pub async fn channel_exists(&self, channel_id: &str) -> Result<bool, DbError> {
        let Some(group_id) = self.store.channel_group(channel_id).await? else {
            return Ok(false);
        };
        Ok(self.store.group(&group_id).await?.is_some())
    }

    /// Every channel `actor` can read now in the groups hosted here that
    /// they own or are an active member of, by group then channel age.
    /// Fails rather than leave a group out (see
    /// [`Groups::hosted_entries`]).
    pub async fn readable_member_channels(
        &self,
        actor: &Actor,
    ) -> Result<Vec<StoredChannel>, ListingError> {
        let caller = Caller::Actor(actor.clone());
        let mut out = Vec::new();
        for entry in self.hosted_entries(actor).await? {
            let Some(group) = self.store.group(&entry.group_id).await? else {
                continue;
            };
            let standing = self.standing(&caller, &group).await?;
            // The membership was read a moment ago; re-check it against the
            // standing read now, so a removal in between leaves the group out.
            if !standing.is_member() {
                continue;
            }
            let policy = group.policy();
            if !access::can_read_group(&standing, &policy) {
                continue;
            }
            out.extend(
                self.store
                    .channels(&group.id, CHANNELS_READ)
                    .await?
                    .into_iter()
                    .filter(|c| access::can_read_channel(&standing, &policy, &c.policy())),
            );
        }
        Ok(out)
    }

    /// Sort `ids` into the channels `actor` can read now and the ids that
    /// name no active channel. An id in neither exists but is unreadable.
    /// Reads each channel and each group once, however many ids share it.
    pub async fn readable_among(&self, actor: &Actor, ids: &[String]) -> Result<Readable, DbError> {
        let wanted: BTreeSet<&String> = ids.iter().collect();
        let unique: Vec<String> = wanted.iter().map(|s| (*s).clone()).collect();
        let found = self.store.active_channels(&unique).await?;
        let caller = Caller::Actor(actor.clone());
        let mut out = Readable::default();
        let mut present = BTreeSet::new();
        // Each group's policy and the caller's standing in it, if active.
        let mut groups = BTreeMap::new();
        for channel in found {
            if !groups.contains_key(&channel.group_id) {
                let entry = match self.store.group(&channel.group_id).await? {
                    Some(g) => {
                        let standing = self.standing(&caller, &g).await?;
                        Some((g.policy(), standing))
                    }
                    None => None,
                };
                groups.insert(channel.group_id.clone(), entry);
            }
            let Some(Some((policy, standing))) = groups.get(&channel.group_id) else {
                // Its group is being deleted: the channel is going too.
                continue;
            };
            present.insert(channel.id.clone());
            if access::can_read_group(standing, policy)
                && access::can_read_channel(standing, policy, &channel.policy())
            {
                out.channels.insert(channel.id.clone(), channel);
            }
        }
        out.gone = unique
            .into_iter()
            .filter(|id| !present.contains(id))
            .collect();
        Ok(out)
    }
}
