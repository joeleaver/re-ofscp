//! Group invites (spec §5.6; docs/decisions/0019): creating, listing and
//! revoking them (group `manage`), and redeeming one as an existing
//! account, local or remote (§2.2: identity is the full actor).
//!
//! An invite admits whatever the group's `joinPolicy` and tier: that is
//! what it is for (§5.2), and private groups admit no other way (§11,
//! security requirement 6). Redemption joins through [`Groups::add_member`],
//! so every limit, access change and announcement of a join applies.

use std::collections::HashMap;

use re_ofscp_types::Actor;
use re_ofscp_types::wire::{
    Invite, InviteCreateRequest, InviteCreateResponse, InviteRedeemResponse, Paged,
};

use super::access::{self, Standing, actions, roles};
use super::invite_model;
use super::invite_store::StoredInvite;
use super::model::StoredGroup;
use super::ops::{GroupError, NO_GROUP, NOT_MANAGER};
use super::paging::{self, PageQuery, SortKey};
use super::validate::Invalid;
use super::{Caller, Groups};
use crate::db::DbError;
use ofscp_core::LocalId;

/// Most invites one group may hold, expired ones awaiting the sweeper
/// included (provider policy). Bounds the list, which is read whole.
pub const MAX_INVITES_PER_GROUP: usize = 50;

/// Expired invites the sweeper deletes per pass.
const EXPIRED_BATCH: usize = 500;

const NO_INVITE: &str = "no such invite";
const EXHAUSTED: &str = "this invite has been used as many times as it allows";
const TOO_MANY_INVITES: &str = "this group has the most invites this provider allows";
const OUTRANKED_ROLE: &str = "you may not invite people to a role with permissions you lack";
const STALE_INVITE: &str =
    "this invite no longer grants anything: its role, or its creator's authority, is gone";
const NOT_A_ROLE: &str = "`owner` cannot be granted by an invite; ownership is transferred";

/// What a redemption did (§5.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redeemed {
    /// The answer: the group, the invite's channel and the caller's role.
    pub response: InviteRedeemResponse,
    /// Whether the caller joined now (`false`: they already belonged).
    pub joined: bool,
}

impl Groups {
    /// The group, if `actor` may manage it, with their standing.
    async fn managing(
        &self,
        actor: &Actor,
        group_id: &str,
    ) -> Result<(StoredGroup, Standing), GroupError> {
        let group = self.settled_group(group_id).await?;
        let standing = self.standing(&Caller::Actor(actor.clone()), &group).await?;
        if !access::may(&standing, &group.policy(), actions::MANAGE) {
            return Err(GroupError::Forbidden(NOT_MANAGER));
        }
        Ok((group, standing))
    }

    /// `POST /api/groups/{groupId}/invites`: `manage`, then the terms. The
    /// role must exist and not be `owner` (`400`), and the subset rule
    /// binds it (§5.7: `403` unless `perms(role) ⊆ perms(caller)`). A
    /// `channelId` must name an active channel of the group (`400`).
    pub async fn create_invite(
        &self,
        actor: &Actor,
        group_id: &str,
        req: &InviteCreateRequest,
    ) -> Result<InviteCreateResponse, GroupError> {
        let (group, standing) = self.managing(actor, group_id).await?;
        let now = self.now();
        let terms = invite_model::terms(req, now)?;
        let policy = group.policy();
        if terms.role == roles::OWNER {
            return Err(Invalid(NOT_A_ROLE.to_owned()).into());
        }
        if !policy.knows_role(&terms.role) {
            return Err(Invalid(format!("the group has no role `{}`", terms.role)).into());
        }
        if !access::may_act_on(&standing, &terms.role, &policy) {
            return Err(GroupError::Forbidden(OUTRANKED_ROLE));
        }
        if let Some(c) = &terms.channel_id
            && self.store.channel(&group.id, c).await?.is_none()
        {
            return Err(Invalid(format!("the group has no channel `{c}`")).into());
        }
        if self.invite_count(&group.id).await? >= MAX_INVITES_PER_GROUP {
            return Err(GroupError::Forbidden(TOO_MANY_INVITES));
        }
        let token = invite_model::new_token()?;
        let hash = invite_model::token_hash(&token)
            .ok_or_else(|| DbError::Query("a fresh invite token did not hash".to_owned()))?;
        let invite = self
            .store
            .create_invite(&group.id, actor, &terms, &hash, now)
            .await?;
        // Counted again once written: of concurrent creates past the
        // limit, each finds the excess and takes itself back. And an
        // invite written after the group's purge began would never be
        // purged.
        if self.invite_count(&group.id).await? > MAX_INVITES_PER_GROUP {
            self.store.delete_invite(&invite.id).await?;
            return Err(GroupError::Forbidden(TOO_MANY_INVITES));
        }
        if self.store.group(&group.id).await?.is_none() {
            self.store.delete_invite(&invite.id).await?;
            return Err(GroupError::NotFound(NO_GROUP));
        }
        Ok(invite.to_created(token)?)
    }

    async fn invite_count(&self, group_id: &str) -> Result<usize, GroupError> {
        Ok(self
            .store
            .invites(group_id, MAX_INVITES_PER_GROUP + 1)
            .await?
            .len())
    }

    /// `GET /api/groups/{groupId}/invites`: `manage`. The unexpired
    /// invites, without their tokens, paged per §7.2 by `(createdAt, id)`,
    /// newest first by default.
    pub async fn list_invites(
        &self,
        actor: &Actor,
        group_id: &str,
        query: &PageQuery,
    ) -> Result<Paged<Invite>, GroupError> {
        let (group, _) = self.managing(actor, group_id).await?;
        let now = self.now();
        let invites = self.store.invites(&group.id, MAX_INVITES_PER_GROUP).await?;
        let cap = MAX_INVITES_PER_GROUP * invite_model::MAX_INVITE_USES as usize;
        let mut slots: HashMap<String, Vec<u32>> = HashMap::new();
        for (invite, n) in self.store.group_slots(&group.id, cap).await? {
            slots.entry(invite).or_default().push(n);
        }
        let items = invites
            .iter()
            .filter(|i| !i.expired(now))
            .map(|i| {
                let uses = match i.max_uses {
                    Some(max) => used_slots(slots.get(&i.id), max),
                    None => i.counter,
                };
                let key = SortKey {
                    at: i.created_at,
                    id: i.id.clone(),
                };
                Ok((key, i.to_wire(uses)?))
            })
            .collect::<Result<Vec<_>, GroupError>>()?;
        Ok(paging::page(
            &format!("invites {}", group.id),
            items,
            query,
        )?)
    }

    /// `DELETE /api/groups/{groupId}/invites/{inviteId}`: `manage`. `404`
    /// for an invite the group does not have (expired ones included, until
    /// the sweeper deletes them).
    pub async fn revoke_invite(
        &self,
        actor: &Actor,
        group_id: &str,
        invite_id: &str,
    ) -> Result<(), GroupError> {
        let (group, _) = self.managing(actor, group_id).await?;
        let invite = self
            .store
            .invite(&group.id, invite_id)
            .await?
            .ok_or(GroupError::NotFound(NO_INVITE))?;
        Ok(self.store.delete_invite(&invite.id).await?)
    }

    /// `POST /api/invites/{token}/redeem` (§5.6) as `actor`. The invite is
    /// checked first, whoever the caller is (lost-conn/ofscp#35):
    ///
    /// - An unknown, revoked or expired token, or one whose group is gone,
    ///   is `404`.
    /// - A limited invite with every slot taken is `409`, members and the
    ///   owner included.
    /// - Someone who already belongs (the owner included) is answered with
    ///   their current role. No use is taken and nothing changes.
    /// - An invite whose role no longer exists, or whose creator no longer
    ///   holds `manage` and a superset of the role's permissions, is `403`
    ///   (decision 0019).
    /// - Otherwise the caller joins with the invite's role, `409` if the
    ///   last slot went to a concurrent redemption.
    pub async fn redeem_invite(&self, actor: &Actor, token: &str) -> Result<Redeemed, GroupError> {
        let hash = invite_model::token_hash(token).ok_or(GroupError::NotFound(NO_INVITE))?;
        let invite = self
            .store
            .invite_by_token(&hash)
            .await?
            .filter(|i| !i.expired(self.now()))
            .ok_or(GroupError::NotFound(NO_INVITE))?;
        let group = match self.settled_group(&invite.group_id).await {
            Err(GroupError::NotFound(_)) => return Err(GroupError::NotFound(NO_INVITE)),
            other => other?,
        };
        if let Some(max) = invite.max_uses
            && self.store.slots_taken(&invite).await?.len() >= max as usize
        {
            return Err(GroupError::Conflict(EXHAUSTED));
        }
        if let Some(m) = self.member_of(&group, actor).await? {
            return self.redeemed(&invite, m.role, false).await;
        }
        self.still_grants(&invite, &group).await?;
        let slot = match invite.max_uses {
            None => None,
            Some(_) => Some(
                self.store
                    .take_slot(&invite, actor, self.now())
                    .await?
                    .ok_or(GroupError::Conflict(EXHAUSTED))?,
            ),
        };
        let joined = self.join_by_invite(&invite, actor).await;
        let joined = match (joined, slot) {
            (Ok(true), _) => true,
            (outcome, Some(n)) => {
                // Not joined by this use: give the slot back. A failure
                // here leaves the slot taken, which only ever admits fewer.
                if let Err(e) = self.store.give_back_slot(&invite.id, n).await {
                    tracing::warn!(invite = %invite.id, error = %e, "giving back an invite slot failed");
                }
                outcome?
            }
            (outcome, None) => outcome?,
        };
        if joined && invite.max_uses.is_none() {
            match self.store.bump_uses(&invite.id).await {
                Ok(true) => {}
                Ok(false) => {
                    tracing::warn!(invite = %invite.id, "an invite's use count kept moving")
                }
                Err(e) => {
                    tracing::warn!(invite = %invite.id, error = %e, "counting an invite's use failed");
                }
            }
        }
        // Re-read the group: an ownership change meanwhile.
        let now = self.settled_group(&group.id).await?;
        let member = self
            .member_of(&now, actor)
            .await?
            .ok_or(GroupError::Conflict(
                "the membership changed meanwhile; retry",
            ))?;
        self.redeemed(&invite, member.role, joined).await
    }

    /// Join `invite`'s group with its role, once its slot (if any) is
    /// held. `Ok(false)`: the caller already belonged (a concurrent
    /// redemption or join). An invite revoked meanwhile is `404`: a slot
    /// taken after the revocation's deletes must not admit anyone.
    async fn join_by_invite(
        &self,
        invite: &StoredInvite,
        actor: &Actor,
    ) -> Result<bool, GroupError> {
        if self
            .store
            .invite(&invite.group_id, &invite.id)
            .await?
            .is_none()
        {
            return Err(GroupError::NotFound(NO_INVITE));
        }
        self.add_member(&invite.group_id, actor, &invite.role, self.now())
            .await
    }

    /// `403` unless `invite` still grants its role: the role exists, and
    /// its creator still holds `manage` and every permission the role
    /// carries (the subset rule, as at creation). Someone demoted or
    /// removed leaves no invite behind that outranks them.
    async fn still_grants(
        &self,
        invite: &StoredInvite,
        group: &StoredGroup,
    ) -> Result<(), GroupError> {
        let policy = group.policy();
        let creator = self
            .standing(&Caller::Actor(invite.created_by.clone()), group)
            .await?;
        let grants = invite.role != roles::OWNER
            && policy.knows_role(&invite.role)
            && access::may(&creator, &policy, actions::MANAGE)
            && access::may_act_on(&creator, &invite.role, &policy);
        if grants {
            Ok(())
        } else {
            Err(GroupError::Forbidden(STALE_INVITE))
        }
    }

    /// The redemption's answer (§5.6): the group, the caller's `role`, and
    /// the invite's channel while it still exists. An invite whose channel
    /// has since been deleted still joins the group, and the answer omits
    /// `channelId` (lost-conn/ofscp#40).
    async fn redeemed(
        &self,
        invite: &StoredInvite,
        role: String,
        joined: bool,
    ) -> Result<Redeemed, GroupError> {
        let bad = |_| DbError::Decode(format!("invite {}: bad id", invite.id));
        let channel_id = match &invite.channel_id {
            Some(c) if self.store.channel(&invite.group_id, c).await?.is_some() => {
                Some(LocalId::new(c).map_err(bad)?)
            }
            _ => None,
        };
        Ok(Redeemed {
            response: InviteRedeemResponse {
                group_id: LocalId::new(&invite.group_id).map_err(bad)?,
                channel_id,
                role,
            },
            joined,
        })
    }

    /// Delete invites that expired by `now` (a sweeper step): up to a
    /// batch per pass.
    pub(super) async fn purge_expired_invites(&self, now: i64) -> Result<usize, DbError> {
        let ids = self.store.expired_invites(now, EXPIRED_BATCH).await?;
        for id in &ids {
            self.store.delete_invite(id).await?;
        }
        Ok(ids.len())
    }
}

/// How many of a limited invite's `max` slots are taken.
fn used_slots(taken: Option<&Vec<u32>>, max: u32) -> u32 {
    let mut taken: Vec<u32> = taken
        .map(|t| t.iter().copied().filter(|n| *n < max).collect())
        .unwrap_or_default();
    taken.sort_unstable();
    taken.dedup();
    u32::try_from(taken.len()).unwrap_or(max)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_slots_within_the_limit_count() {
        assert_eq!(used_slots(None, 3), 0);
        assert_eq!(used_slots(Some(&vec![0, 2, 2, 7]), 3), 2);
    }
}
