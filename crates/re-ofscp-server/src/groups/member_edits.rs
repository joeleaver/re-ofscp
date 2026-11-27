//! The member-changing endpoints of §5.7: leave, kick, role change and
//! nickname. Each re-reads the group (finishing any unfinished ownership
//! transfer first), authorizes against the caller's standing *now*, then
//! applies the subset rule ([`access::may_act_on`]) where §5.7 asks for it.
//! Authorization comes before body validation (decision 0014).

use re_ofscp_types::Actor;

use super::access::{self, Standing, actions, roles};
use super::member_ops::{NO_MEMBER, Updated, owner_member, row_member};
use super::model::StoredGroup;
use super::ops::{GroupError, NOT_MANAGER};
use super::validate::Invalid;
use super::{Caller, Groups};

/// Longest nickname, in characters, after trimming (§5.7).
pub const MAX_DISPLAY_NAME: usize = 64;

const NOT_A_MEMBER: &str = "you are not a member of this group";
const NOT_MODERATOR: &str = "you may not remove members of this group";
const OUTRANKED: &str = "that member holds a permission you do not";
const OUTRANKED_ROLE: &str = "that role holds a permission you do not";
const OWNER_STAYS: &str = "the owner cannot be removed";
const OWNER_LEAVES: &str = "the owner must transfer ownership before leaving";
const OWNER_DEMOTED: &str = "the owner's role changes only by transferring ownership";
const NO_NICKNAMES: &str = "you may not set other members' nicknames";

/// A nickname as stored (§5.7): trimmed, and `None` when nothing is left.
/// Longer than [`MAX_DISPLAY_NAME`] characters is `400`.
pub fn display_name(raw: Option<&str>) -> Result<Option<String>, Invalid> {
    let Some(trimmed) = raw.map(str::trim).filter(|t| !t.is_empty()) else {
        return Ok(None);
    };
    if trimmed.chars().count() > MAX_DISPLAY_NAME {
        return Err(Invalid(format!(
            "`displayNameOverride` is longer than {MAX_DISPLAY_NAME} characters"
        )));
    }
    Ok(Some(trimmed.to_owned()))
}

impl Groups {
    /// The group, settled, and where `actor` stands in it now.
    async fn acting(
        &self,
        actor: &Actor,
        group_id: &str,
    ) -> Result<(StoredGroup, Standing), GroupError> {
        let group = self.settled_group(group_id).await?;
        let standing = self.standing(&Caller::Actor(actor.clone()), &group).await?;
        Ok((group, standing))
    }

    /// `POST /api/groups/{groupId}/leave`: end the caller's own
    /// membership. The owner must transfer first (`409`); a caller who is
    /// not a member gets `404` (default 4 of docs/decisions/0020).
    pub async fn leave(&self, actor: &Actor, group_id: &str) -> Result<(), GroupError> {
        let group = self.settled_group(group_id).await?;
        if group.owner == *actor {
            return Err(GroupError::Conflict(OWNER_LEAVES));
        }
        if self.store.member(group_id, actor).await?.is_none() {
            return Err(GroupError::NotFound(NO_MEMBER));
        }
        self.remove_member(group_id, actor).await
    }

    /// `DELETE /api/groups/{groupId}/members/{userRef}`: needs `moderate`
    /// and the subset rule against the target's role. The owner is never
    /// removed.
    pub async fn kick(
        &self,
        actor: &Actor,
        group_id: &str,
        target: &Actor,
    ) -> Result<(), GroupError> {
        let (group, standing) = self.acting(actor, group_id).await?;
        let policy = group.policy();
        if !access::may(&standing, &policy, actions::MODERATE) {
            return Err(GroupError::Forbidden(NOT_MODERATOR));
        }
        if group.owner == *target {
            return Err(GroupError::Forbidden(OWNER_STAYS));
        }
        let member = self
            .store
            .member(group_id, target)
            .await?
            .ok_or(GroupError::NotFound(NO_MEMBER))?;
        if !access::may_act_on(&standing, &member.role, &policy) {
            return Err(GroupError::Forbidden(OUTRANKED));
        }
        self.remove_member(group_id, target).await
    }

    /// `PATCH /api/groups/{groupId}/members/{userRef}`: needs `manage`, and
    /// the subset rule against both the current and the requested role.
    /// `role` is the request body's, or why it is malformed: it is looked
    /// at only once the caller holds `manage` (authorization before body
    /// validation, decision 0014). The role must exist in the group
    /// (`400`). `owner` is an owner-only ownership transfer
    /// (`transfer.rs`). Answers each member whose role changed: the
    /// target, and for a transfer also the former owner.
    pub async fn change_role(
        &self,
        actor: &Actor,
        group_id: &str,
        target: &Actor,
        role: Result<&str, Invalid>,
    ) -> Result<Vec<Updated>, GroupError> {
        let (group, standing) = self.acting(actor, group_id).await?;
        let policy = group.policy();
        if !access::may(&standing, &policy, actions::MANAGE) {
            return Err(GroupError::Forbidden(NOT_MANAGER));
        }
        let role = role?;
        if !policy.knows_role(role) {
            return Err(GroupError::Invalid(Invalid(format!(
                "the group has no role `{role}`"
            ))));
        }
        if role == roles::OWNER {
            return self
                .transfer_ownership(actor, &standing, &group, target)
                .await;
        }
        if group.owner == *target {
            // Only the owner may act on the owner, and even the owner
            // changes their own role only by handing ownership on.
            return Err(if standing == Standing::Owner {
                GroupError::Conflict(OWNER_DEMOTED)
            } else {
                GroupError::Forbidden(OUTRANKED)
            });
        }
        let member = self
            .store
            .member(group_id, target)
            .await?
            .ok_or(GroupError::NotFound(NO_MEMBER))?;
        if !access::may_act_on(&standing, &member.role, &policy) {
            return Err(GroupError::Forbidden(OUTRANKED));
        }
        if !access::may_act_on(&standing, role, &policy) {
            return Err(GroupError::Forbidden(OUTRANKED_ROLE));
        }
        if member.role == role {
            return Ok(vec![Updated {
                member: row_member(&member)?,
                changed: false,
            }]);
        }
        let written = self
            .write_role(group_id, target, role)
            .await?
            .ok_or(GroupError::NotFound(NO_MEMBER))?;
        Ok(vec![Updated {
            member: row_member(&written)?,
            changed: true,
        }])
    }

    /// `PATCH /api/groups/{groupId}/members/{userRef}/display-name`: any
    /// member sets their own; another's needs `members.set-nickname` and
    /// the subset rule against their role. `raw` is the request's value
    /// (`None` for `null`), or why the body is malformed, which is answered
    /// only once the caller is authorized; it is trimmed, and empty clears.
    pub async fn set_display_name(
        &self,
        actor: &Actor,
        group_id: &str,
        target: &Actor,
        raw: Result<Option<&str>, Invalid>,
    ) -> Result<Updated, GroupError> {
        let (group, standing) = self.acting(actor, group_id).await?;
        let policy = group.policy();
        if !standing.is_member() {
            return Err(GroupError::Forbidden(NOT_A_MEMBER));
        }
        let own = actor == target;
        if !own && !access::may(&standing, &policy, actions::SET_NICKNAME) {
            return Err(GroupError::Forbidden(NO_NICKNAMES));
        }
        if group.owner == *target {
            if !own && !access::may_act_on(&standing, roles::OWNER, &policy) {
                return Err(GroupError::Forbidden(OUTRANKED));
            }
            let name = display_name(raw?)?;
            return self.write_owner_display_name(&group, name).await;
        }
        let member = self
            .store
            .member(group_id, target)
            .await?
            .ok_or(GroupError::NotFound(NO_MEMBER))?;
        if !own && !access::may_act_on(&standing, &member.role, &policy) {
            return Err(GroupError::Forbidden(OUTRANKED));
        }
        let name = display_name(raw?)?;
        if member.display_name == name {
            return Ok(Updated {
                member: row_member(&member)?,
                changed: false,
            });
        }
        let written = self
            .store
            .set_member_display_name(group_id, target, name.as_deref())
            .await?
            .ok_or(GroupError::NotFound(NO_MEMBER))?;
        // An ownership transfer to the target may have committed meanwhile:
        // the nickname then belongs on the group. Finish the transfer first
        // (it carries this row's nickname over), so that no finisher still
        // running can overwrite the write below.
        if self
            .store
            .group(group_id)
            .await?
            .is_some_and(|g| g.owner == *target)
        {
            let now = self.settled_group(group_id).await?;
            if now.owner == *target {
                return self.write_owner_display_name(&now, name).await;
            }
        }
        Ok(Updated {
            member: row_member(&written)?,
            changed: true,
        })
    }

    /// Set the nickname of `group`'s owner, which lives on the group, and
    /// on the row a transfer from them may be preparing (ignored while they
    /// own the group). A transfer whose commit this write races fails its
    /// guard on the nickname and retries (`owner_store.rs`). If they handed
    /// the group on before this write, it belongs on the membership row the
    /// transfer gave them instead.
    async fn write_owner_display_name(
        &self,
        group: &StoredGroup,
        name: Option<String>,
    ) -> Result<Updated, GroupError> {
        if group.owner_display_name == name {
            return Ok(Updated {
                member: owner_member(group)?,
                changed: false,
            });
        }
        let owner = &group.owner;
        self.store
            .set_owner_display_name(&group.id, owner, name.as_deref())
            .await?;
        // Re-read, finishing any transfer, so the former owner's row (if
        // they are one now) is final.
        let now = self.settled_group(&group.id).await?;
        if now.owner == *owner {
            self.store
                .set_member_display_name(&group.id, owner, name.as_deref())
                .await?;
            return Ok(Updated {
                member: owner_member(&now)?,
                changed: true,
            });
        }
        let row = self
            .store
            .set_member_display_name(&group.id, owner, name.as_deref())
            .await?
            .ok_or(GroupError::NotFound(NO_MEMBER))?;
        Ok(Updated {
            member: row_member(&row)?,
            changed: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nicknames_are_trimmed_and_blank_clears() {
        assert_eq!(display_name(None), Ok(None));
        assert_eq!(display_name(Some("")), Ok(None));
        assert_eq!(display_name(Some(" \t\n ")), Ok(None));
        assert_eq!(
            display_name(Some("  Ada (mod) ")),
            Ok(Some("Ada (mod)".to_owned()))
        );
    }

    #[test]
    fn nicknames_are_at_most_64_characters_after_trimming() {
        let at_limit = "é".repeat(MAX_DISPLAY_NAME);
        assert_eq!(
            display_name(Some(&format!("  {at_limit}  "))),
            Ok(Some(at_limit.clone()))
        );
        assert!(display_name(Some(&format!("{at_limit}x"))).is_err());
    }
}
