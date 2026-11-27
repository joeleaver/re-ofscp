//! Membership seams and reads (§5.7): adding, re-roling and removing a
//! member, the members as `Member` objects, the caller's own
//! `Group.membership` (§5.5), and settling an unfinished ownership
//! transfer before any membership change. The endpoints' operations build
//! on these (`member_edits.rs`, `joining.rs`, `transfer.rs`, `roster.rs`).
//!
//! The owner is `Group.owner`, never a membership row (decision 0014). A
//! row an interrupted transfer leaves for the owner is ignored by every
//! read here (docs/decisions/0020).

use std::collections::HashSet;
use std::time::Instant;

use re_ofscp_types::Actor;
use re_ofscp_types::wire::{Member, Membership};

use super::access::{Standing, roles};
use super::members::StoredMember;
use super::model::StoredGroup;
use super::ops::{ACTIVATE_WITHIN, GroupError, NO_GROUP, SLOW_WRITE, announce_unless, member_role};
use super::{Groups, MAX_MEMBERS_PER_GROUP, MAX_MEMBERSHIPS_PER_ACTOR};
use crate::db::DbError;
use crate::timefmt;

pub(super) const NO_MEMBER: &str = "no such member";
const GROUP_FULL: &str = "this group has the most members this provider allows";
const MEMBER_OF_TOO_MANY: &str = "you are a member of the most groups this provider allows";

/// How many times a membership change re-reads a group whose transfer it
/// had to finish first.
const SETTLE_ATTEMPTS: usize = 3;

/// A membership change, and whether it changed what `member.updated`
/// carries (§5.7: a role or a nickname).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Updated {
    /// The member as they are now.
    pub member: Member,
    /// Whether their role or nickname changed.
    pub changed: bool,
}

/// The owner's `joinedAt`: the group's creation time for its creator, and
/// for an owner handed the group, the `joinedAt` of their membership. A
/// transfer changes no one's `joinedAt` (default 1 of
/// docs/decisions/0020; lost-conn/ofscp#35).
pub(super) fn owner_joined_at(group: &StoredGroup) -> Result<i64, DbError> {
    if let Some(at) = group.owner_joined_at {
        return Ok(at);
    }
    timefmt::unix(&group.created_at)
        .ok_or_else(|| DbError::Decode(format!("group {}: bad created_at", group.id)))
}

/// The owner as a `Member` (§5.7): role `owner`, nickname from the group.
pub(super) fn owner_member(group: &StoredGroup) -> Result<Member, DbError> {
    Ok(Member {
        user: group.owner.clone(),
        role: roles::OWNER.to_owned(),
        display_name_override: group.owner_display_name.clone(),
        joined_at: timefmt::timestamp(owner_joined_at(group)?),
    })
}

/// When a membership row was written (unix seconds).
pub(super) fn joined_unix(m: &StoredMember) -> Result<i64, DbError> {
    timefmt::unix(&m.joined_at)
        .ok_or_else(|| DbError::Decode(format!("membership of {}: bad joined_at", m.group_id)))
}

/// A membership row as a `Member` (§5.7).
pub(super) fn row_member(m: &StoredMember) -> Result<Member, DbError> {
    Ok(Member {
        user: m.actor.clone(),
        role: m.role.clone(),
        display_name_override: m.display_name.clone(),
        joined_at: timefmt::timestamp(joined_unix(m)?),
    })
}

impl Groups {
    /// Active group `group_id` (`404` otherwise), with any unfinished
    /// ownership transfer finished first, so a membership change never
    /// races the transfer's own row writes (docs/decisions/0020).
    pub(super) async fn settled_group(&self, group_id: &str) -> Result<StoredGroup, GroupError> {
        for _ in 0..SETTLE_ATTEMPTS {
            let group = self
                .store
                .group(group_id)
                .await?
                .ok_or(GroupError::NotFound(NO_GROUP))?;
            if group.transfer.is_none() {
                return Ok(group);
            }
            self.finish_transfer(&group).await?;
        }
        Err(GroupError::Conflict(
            "the group's ownership kept changing; retry",
        ))
    }

    /// `actor` as a member of `group` (the owner included), if they are
    /// one.
    pub(super) async fn member_of(
        &self,
        group: &StoredGroup,
        actor: &Actor,
    ) -> Result<Option<Member>, GroupError> {
        if group.owner == *actor {
            return Ok(Some(owner_member(group)?));
        }
        match self.store.member(&group.id, actor).await? {
            Some(m) => Ok(Some(row_member(&m)?)),
            None => Ok(None),
        }
    }

    /// The caller's own `Group.membership` (§5.5), for a standing already
    /// worked out: `None` for an outsider.
    pub(super) async fn membership(
        &self,
        group: &StoredGroup,
        actor: &Actor,
        standing: &Standing,
    ) -> Result<Option<Membership>, GroupError> {
        if !standing.is_member() {
            return Ok(None);
        }
        Ok(self.member_of(group, actor).await?.map(|m| Membership {
            role: m.role,
            joined_at: m.joined_at,
            display_name_override: m.display_name_override,
        }))
    }

    /// Record `actor` as a member of `group_id` with `role` (the §5.7
    /// seam). `Ok(false)` if they already belong to the group (the owner
    /// included). The role `owner` is refused: ownership is the group's
    /// `owner` field, never a membership. A group holding
    /// [`MAX_MEMBERS_PER_GROUP`] members refuses more, and an actor already
    /// in [`MAX_MEMBERSHIPS_PER_ACTOR`] groups may join no more (both
    /// `403`). Announces the change once the row may be active, on every
    /// exit from then on, errors included ([`Self::settle_join`]).
    pub async fn add_member(
        &self,
        group_id: &str,
        actor: &Actor,
        role: &str,
        now: i64,
    ) -> Result<bool, GroupError> {
        member_role(role)?;
        let group = self
            .store
            .group(group_id)
            .await?
            .ok_or(GroupError::NotFound(NO_GROUP))?;
        if group.owner == *actor {
            return Ok(false);
        }
        if self.member_count(&group).await? >= MAX_MEMBERS_PER_GROUP {
            // A member is a member, full or not.
            return match self.store.member(group_id, actor).await? {
                Some(_) => Ok(false),
                None => Err(GroupError::Forbidden(GROUP_FULL)),
            };
        }
        if self.store.member(group_id, actor).await?.is_some() {
            return Ok(false);
        }
        if self.membership_count(actor).await? >= MAX_MEMBERSHIPS_PER_ACTOR {
            return Err(GroupError::Forbidden(MEMBER_OF_TOO_MANY));
        }
        if !self
            .write_pending_member(group_id, actor, role, None, MAX_MEMBERS_PER_GROUP, now)
            .await?
        {
            return Ok(false);
        }
        let activated = match self.store.activate_member(group_id, actor).await {
            Ok(true) => Ok(()),
            // Known to have activated nothing: there is nothing to announce.
            Ok(false) => return Err(self.not_activated(group_id).await),
            // May have committed: settled (and announced) as if it had.
            Err(e) => Err(e.into()),
        };
        self.settle_join(group_id, actor, activated).await
    }

    /// The rest of [`Self::add_member`] once its row may be active: the
    /// activation succeeded, or failed in a way that may have committed.
    /// Every exit from here announces the change, so group lists and live
    /// subscriptions never miss a membership that may exist (decision
    /// 0018). A join that cannot be confirmed (the activation or the
    /// recount failed) or that took the actor past
    /// [`MAX_MEMBERSHIPS_PER_ACTOR`] is taken back, which announces again.
    pub(super) async fn settle_join(
        &self,
        group_id: &str,
        actor: &Actor,
        activated: Result<(), GroupError>,
    ) -> Result<bool, GroupError> {
        self.member_changed(group_id, actor);
        // Counted again once active, as for owned groups: of concurrent
        // joins past the limit, each finds the excess and takes itself back.
        let confirmed = match activated {
            Ok(()) => match self.membership_count(actor).await {
                Ok(n) if n > MAX_MEMBERSHIPS_PER_ACTOR => {
                    Err(GroupError::Forbidden(MEMBER_OF_TOO_MANY))
                }
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            },
            Err(e) => Err(e),
        };
        if let Err(e) = confirmed {
            // A take-back that fails leaves the join's state unknown: its
            // error is the answer then.
            self.remove_member(group_id, actor).await?;
            return Err(e);
        }
        // A member has nothing left to ask for.
        self.store.delete_request_of(group_id, actor).await?;
        Ok(true)
    }

    /// How many groups `actor` is a member of, counted up to one past
    /// [`MAX_MEMBERSHIPS_PER_ACTOR`]. A row left for them in a group they
    /// own is not a membership and does not count; every owned group is
    /// read (`all_owned_groups`), so no such row can pass for one.
    pub(super) async fn membership_count(&self, actor: &Actor) -> Result<usize, GroupError> {
        let owned: HashSet<String> = self
            .store
            .all_owned_groups(actor)
            .await?
            .into_iter()
            .map(|g| g.id)
            .collect();
        // Enough rows that strays in owned groups cannot hide real ones.
        let cap = MAX_MEMBERSHIPS_PER_ACTOR + 1 + owned.len();
        Ok(self
            .store
            .memberships_of(actor, cap)
            .await?
            .into_iter()
            .filter(|(group_id, _)| !owned.contains(group_id))
            .take(MAX_MEMBERSHIPS_PER_ACTOR + 1)
            .count())
    }

    /// Write and confirm a membership row, as for channels: pending, then
    /// active once the group is known to be still active, so it never
    /// outlives its group. `Ok(false)` if an active one exists; `409` for a
    /// pending one (another add in flight, or a dead writer's row awaiting
    /// expiry, which is not a membership). Does not announce. Counts the
    /// rows again after writing, and takes this one back if that finds more
    /// than `limit` (normally [`MAX_MEMBERS_PER_GROUP`]).
    pub(super) async fn write_member(
        &self,
        group_id: &str,
        actor: &Actor,
        role: &str,
        display_name: Option<&str>,
        limit: usize,
        now: i64,
    ) -> Result<bool, GroupError> {
        if !self
            .write_pending_member(group_id, actor, role, display_name, limit, now)
            .await?
        {
            return Ok(false);
        }
        if !self.store.activate_member(group_id, actor).await? {
            return Err(self.not_activated(group_id).await);
        }
        Ok(true)
    }

    /// [`Self::write_member`] up to its activation: `Ok(true)` once a
    /// pending row is written and confirmed, ready to be made active.
    /// Nothing it leaves is active, so it never needs announcing.
    async fn write_pending_member(
        &self,
        group_id: &str,
        actor: &Actor,
        role: &str,
        display_name: Option<&str>,
        limit: usize,
        now: i64,
    ) -> Result<bool, GroupError> {
        // As for channels: the row's age runs from `now`.
        let started = Instant::now();
        if !self
            .store
            .add_member(group_id, actor, role, display_name, now)
            .await?
        {
            return match self.store.member(group_id, actor).await? {
                Some(_) => Ok(false),
                None => Err(GroupError::Conflict(
                    "the membership is being recorded; retry",
                )),
            };
        }
        let Some(group) = self.store.group(group_id).await? else {
            self.store.remove_member(group_id, actor).await?;
            return Err(GroupError::NotFound(NO_GROUP));
        };
        if self.member_count(&group).await? > limit {
            self.store.remove_member(group_id, actor).await?;
            return Err(GroupError::Forbidden(GROUP_FULL));
        }
        if started.elapsed() > ACTIVATE_WITHIN {
            self.store.remove_member(group_id, actor).await?;
            return Err(GroupError::Conflict(SLOW_WRITE));
        }
        Ok(true)
    }

    /// The answer when activating a pending membership of `group_id` found
    /// no pending row (it expired, or the group was purged).
    async fn not_activated(&self, group_id: &str) -> GroupError {
        match self.store.group(group_id).await {
            Ok(None) => GroupError::NotFound(NO_GROUP),
            Ok(Some(_)) => GroupError::Conflict("the membership could not be recorded; retry"),
            Err(e) => e.into(),
        }
    }

    /// How many members `group` has besides its owner, pending rows
    /// included (so a limit errs on the safe side), counted up to one past
    /// [`MAX_MEMBERS_PER_GROUP`]. A row left for the owner (by a transfer
    /// to or from them, docs/decisions/0020) is not a membership and does
    /// not count.
    pub(super) async fn member_count(&self, group: &StoredGroup) -> Result<usize, GroupError> {
        let rows = self
            .store
            .member_count(&group.id, MAX_MEMBERS_PER_GROUP + 2)
            .await?;
        let stray = self.store.member_row(&group.id, &group.owner).await?;
        Ok(rows.saturating_sub(usize::from(stray.is_some())))
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
        Ok(self.write_role(group_id, actor, role).await?.is_some())
    }

    /// [`Self::set_role`], answering the row as written.
    pub(super) async fn write_role(
        &self,
        group_id: &str,
        actor: &Actor,
        role: &str,
    ) -> Result<Option<StoredMember>, GroupError> {
        member_role(role)?;
        let set = self.store.set_role(group_id, actor, role, self.now()).await;
        announce_unless(&set, Option::is_none, || {
            self.member_changed(group_id, actor);
        });
        Ok(set?)
    }
}
