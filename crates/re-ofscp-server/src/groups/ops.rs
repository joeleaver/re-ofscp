//! Group and channel operations (§5.5), independent of HTTP. Every read
//! goes through [`Groups::read_group`] or [`Groups::read_channel`], which
//! apply the [`access`] rule; later surfaces (history,
//! subscriptions, notifications, discovery samples) use the same two.

use std::time::{Duration, Instant};

use re_ofscp_types::Actor;
use re_ofscp_types::groups::{
    Channel, ChannelCreateRequest, ChannelUpdateRequest, Group, GroupCreateRequest,
    GroupUpdateRequest,
};

use super::access::{self, Standing, actions, roles};
use super::claims;
use super::model::{self, StoredChannel, StoredGroup};
use super::validate::Invalid;
use super::{
    AccessChange, Caller, Groups, MAX_CHANNELS_PER_GROUP, MAX_GROUPS_PER_OWNER, PENDING_TTL,
};
use crate::db::DbError;

/// How often an edit is retried against a fresh read before the request
/// is answered `409`. Each retry follows another edit's success, so a
/// `409` means the object really did keep changing.
const UPDATE_ATTEMPTS: usize = 5;

/// How long after writing a pending row its writer may still activate it.
/// The sweeper deletes pending rows older than [`PENDING_TTL`], and its
/// delete is not conditional at the moment of writing (claims.rs), so an
/// expiry that saw the row pending could delete it just after activation.
/// Activating only well inside the TTL leaves that impossible but for the
/// server stalling one statement for minutes. The data layer's 10 s
/// timeout only stops the client waiting and does not rule that out
/// (docs/decisions/0014). A writer slower than this takes its row back.
const ACTIVATE_WITHIN: Duration = PENDING_TTL.saturating_sub(Duration::from_secs(300));
const _: () = assert!(
    PENDING_TTL.as_secs() >= 2 * 300,
    "PENDING_TTL must be at least 600 s, leaving ACTIVATE_WITHIN at least 300 s"
);

/// The pause after losing a revision claim, times the attempt number: the
/// claim's holder is writing, and an immediate re-read would likely see
/// the revision it is replacing.
const CLAIM_BACKOFF: Duration = Duration::from_millis(20);

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
const SLOW_WRITE: &str = "the write took too long to confirm; retry";

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

    /// The group id of active channel `channel_id`, for callers that know
    /// only the channel (the §7.1 `subscribe` command names channels
    /// alone). `None` unless both the channel and its group are active (a
    /// group being deleted keeps its channel rows active until purged).
    /// This answers no access question: follow it with
    /// [`Self::read_channel`], which hides a channel the caller cannot read
    /// exactly as a missing one.
    pub async fn channel_group(&self, channel_id: &str) -> Result<Option<String>, GroupError> {
        let Some(group_id) = self.store.channel_group(channel_id).await? else {
            return Ok(None);
        };
        Ok(self.store.group(&group_id).await?.map(|_| group_id))
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
            // A missing group and an unreadable one answer exactly as a
            // missing channel: the same `404` body in every case.
            Err(GroupError::Forbidden(_) | GroupError::NotFound(_)) => {
                return Err(GroupError::NotFound(NO_CHANNEL));
            }
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
        for attempt in 1..=UPDATE_ATTEMPTS {
            // Re-read and re-authorize on every attempt: a concurrent change
            // may have revoked the caller's `manage`.
            let group = self.group_for(actor, group_id, actions::MANAGE).await?;
            let Some(fields) = model::patch_group(&group, patch)? else {
                return Ok(group.to_wire());
            };
            // Only the holder of the claim on the next revision writes it
            // (claims.rs: a filtered update alone is not compare-and-set).
            let next = claims::group_key(&group.id, group.revision.saturating_add(1));
            // The lease runs from the clock at claiming, not from the
            // request's `now`, which earlier attempts may have aged; the
            // one write below follows at once.
            if !self.store.claim(&next, self.now()).await? {
                lost_claim(attempt).await;
                continue;
            }
            let written = self.store.update_group(&group, &fields, now).await;
            // A failed write may have committed (see `announce_unless`).
            announce_unless(
                &written,
                |w| w.is_none(),
                || {
                    self.changed(AccessChange::Group {
                        group_id: group_id.to_owned(),
                    });
                },
            );
            if let Some(updated) = written? {
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
        // A failed mark may have committed (the group is then hidden): tell
        // live readers now, as every revoking write does. On success the
        // channels and the group are announced below, in that order.
        let marked = self.store.mark_deleting(group_id).await;
        announce_unless(
            &marked,
            |_| true,
            || {
                self.changed(AccessChange::Group {
                    group_id: group_id.to_owned(),
                });
            },
        );
        if !marked? {
            return Err(GroupError::NotFound(NO_GROUP));
        }
        // Live readers (WebSocket subscriptions) find a group's channels
        // through its channel rows, which the purge removes: name every
        // channel now, while the rows are still there. They are read after
        // `mark_deleting`, so none that was readable is missed (none
        // becomes readable afterwards). If they cannot be read, the purge
        // is left to the sweeper, so whoever receives the `Group` change
        // can still find them.
        let channels = self.store.channel_ids(group_id).await;
        if let Ok(ids) = &channels {
            for channel_id in ids {
                self.channel_changed(group_id, channel_id);
            }
        }
        self.changed(AccessChange::Group {
            group_id: group_id.to_owned(),
        });
        match channels {
            Ok(_) => {
                if let Err(e) = self.store.purge_group(group_id).await {
                    tracing::warn!(error = %e, group_id, "purging a deleted group failed; the sweeper will finish it");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, group_id, "listing a deleted group's channels failed; the sweeper will purge it");
            }
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
        // The row's age, as the sweeper reckons it, runs from `now`, read
        // just before this call.
        let started = Instant::now();
        self.group_for(actor, group_id, actions::MANAGE).await?;
        let (kind, fields) = model::new_channel(req)?;
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
        self.confirm_channel(group_id, &channel.id, started).await?;
        Ok(channel.to_wire())
    }

    /// Make a channel just written `pending` visible, once its group is
    /// known to be still active. A purge of the group that runs at any
    /// moment of this removes the channel, pending or active, so the
    /// channel never outlives its group (see `store.rs`). A create that
    /// began more than [`ACTIVATE_WITHIN`] ago takes its row back instead,
    /// so the sweeper's expiry never meets an activated row.
    async fn confirm_channel(
        &self,
        group_id: &str,
        channel_id: &str,
        started: Instant,
    ) -> Result<(), GroupError> {
        if self.store.group(group_id).await?.is_none() {
            self.store.delete_channel(group_id, channel_id).await?;
            return Err(GroupError::NotFound(NO_GROUP));
        }
        if started.elapsed() > ACTIVATE_WITHIN {
            self.store.delete_channel(group_id, channel_id).await?;
            return Err(GroupError::Conflict(SLOW_WRITE));
        }
        if self.store.activate_channel(group_id, channel_id).await? {
            return Ok(());
        }
        // The pending row is gone: the group was purged meanwhile, or the
        // sweeper expired it (an exceptionally slow create).
        if self.store.group(group_id).await?.is_none() {
            return Err(GroupError::NotFound(NO_GROUP));
        }
        Err(GroupError::Conflict(
            "the channel could not be created; retry",
        ))
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
        for attempt in 1..=UPDATE_ATTEMPTS {
            // Re-read and re-authorize on every attempt, as for groups.
            let channel = self.managed_channel(actor, group_id, channel_id).await?;
            let Some(fields) = model::patch_channel(&channel, patch)? else {
                return Ok(channel.to_wire());
            };
            let next = claims::channel_key(&channel.id, channel.revision.saturating_add(1));
            // The lease runs from the clock at claiming, not from the
            // request's `now`, which earlier attempts may have aged; the
            // one write below follows at once.
            if !self.store.claim(&next, self.now()).await? {
                lost_claim(attempt).await;
                continue;
            }
            let written = self.store.update_channel(&channel, &fields, now).await;
            announce_unless(
                &written,
                |w| w.is_none(),
                || {
                    self.channel_changed(group_id, channel_id);
                },
            );
            if let Some(updated) = written? {
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
        let deleted = self.store.delete_channel(group_id, channel_id).await;
        announce_unless(
            &deleted,
            |_| false,
            || {
                self.channel_changed(group_id, channel_id);
            },
        );
        Ok(deleted?)
    }

    /// How many channels `group_id` has (read whole; see
    /// `GroupStore::channel_count`).
    async fn channel_count(&self, group_id: &str) -> Result<usize, GroupError> {
        Ok(self.store.channel_count(group_id).await?)
    }

    fn channel_changed(&self, group_id: &str, channel_id: &str) {
        self.changed(AccessChange::Channel {
            group_id: group_id.to_owned(),
            channel_id: channel_id.to_owned(),
        });
    }

    /// Record `actor` as a member of `group_id` with `role` (the §5.7
    /// seam). `Ok(false)` if they already belong to the group (the owner
    /// included). The role `owner` is refused: ownership is the group's
    /// `owner` field, never a membership. Announces the change.
    pub async fn add_member(
        &self,
        group_id: &str,
        actor: &Actor,
        role: &str,
        now: i64,
    ) -> Result<bool, GroupError> {
        // As for channels: the row's age runs from `now`.
        let started = Instant::now();
        member_role(role)?;
        let group = self
            .store
            .group(group_id)
            .await?
            .ok_or(GroupError::NotFound(NO_GROUP))?;
        if group.owner == *actor {
            return Ok(false);
        }
        if !self.store.add_member(group_id, actor, role, now).await? {
            // A row exists. An active one is a membership; a pending one is
            // another add in flight, or a dead writer's row awaiting expiry.
            // That is not a membership, so it must not be reported as one.
            return match self.store.role_of(group_id, actor).await? {
                Some(_) => Ok(false),
                None => Err(GroupError::Conflict(
                    "the membership is being recorded; retry",
                )),
            };
        }
        // Confirm as for channels: a membership never outlives its group.
        if self.store.group(group_id).await?.is_none() {
            self.store.remove_member(group_id, actor).await?;
            return Err(GroupError::NotFound(NO_GROUP));
        }
        if started.elapsed() > ACTIVATE_WITHIN {
            self.store.remove_member(group_id, actor).await?;
            return Err(GroupError::Conflict(SLOW_WRITE));
        }
        if !self.store.activate_member(group_id, actor).await? {
            if self.store.group(group_id).await?.is_none() {
                return Err(GroupError::NotFound(NO_GROUP));
            }
            return Err(GroupError::Conflict(
                "the membership could not be recorded; retry",
            ));
        }
        self.member_changed(group_id, actor);
        Ok(true)
    }

    /// Change a member's role (the §5.7 seam). `Ok(false)` if not a
    /// member. The role `owner` is refused, as for [`Self::add_member`].
    /// Announces the change.
    pub async fn set_role(
        &self,
        group_id: &str,
        actor: &Actor,
        role: &str,
    ) -> Result<bool, GroupError> {
        member_role(role)?;
        let set = self.store.set_role(group_id, actor, role).await;
        announce_unless(&set, |set| !set, || self.member_changed(group_id, actor));
        Ok(set?)
    }

    /// End a membership (the §5.7 seam). Announces the change.
    pub async fn remove_member(&self, group_id: &str, actor: &Actor) -> Result<(), GroupError> {
        let removed = self.store.remove_member(group_id, actor).await;
        announce_unless(&removed, |_| false, || self.member_changed(group_id, actor));
        Ok(removed?)
    }
}

/// Run `announce` after a write that may have changed access: always, unless
/// it succeeded and `unchanged` says it wrote nothing. A write that failed
/// is announced too: it may have committed before the failure reached us
/// (the connection dropped after the commit), and live readers must not
/// keep access it revoked until the next periodic re-check. A spurious
/// announcement costs only a re-check.
fn announce_unless<T, E>(
    written: &Result<T, E>,
    unchanged: impl FnOnce(&T) -> bool,
    announce: impl FnOnce(),
) {
    if !matches!(written, Ok(w) if unchanged(w)) {
        announce();
    }
}

/// A role a membership may hold: anything but `owner` (which would make
/// `Standing::Member("owner")`, holding whatever a map grants `owner`).
fn member_role(role: &str) -> Result<(), GroupError> {
    if role == roles::OWNER {
        return Err(GroupError::Invalid(Invalid(
            "`owner` is the group's owner field, not a membership role".to_owned(),
        )));
    }
    Ok(())
}

/// Wait before retrying an edit whose revision claim another edit holds.
async fn lost_claim(attempt: usize) {
    let factor = u32::try_from(attempt).unwrap_or(u32::MAX);
    tokio::time::sleep(CLAIM_BACKOFF.saturating_mul(factor)).await;
}

#[cfg(test)]
#[path = "ops_tests.rs"]
mod tests;
