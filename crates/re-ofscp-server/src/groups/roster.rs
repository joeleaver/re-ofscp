//! `GET /api/groups/{groupId}/members` (§5.7): the member list, paged per
//! §7.2.
//!
//! As lost-conn/ofscp#35 settles (docs/decisions/0020): the owner is
//! listed as `{user, role: "owner", joinedAt}`, the creator's being the
//! group's `createdAt` and a transfer changing no one's (default 1); the
//! order is provider-defined but stable, here
//! `(joinedAt, user)`, newest first unless `direction=forward`; and only
//! members may read the list, whatever the tier, each seeing every member
//! (default 2).

use re_ofscp_types::Actor;
use re_ofscp_types::wire::{Member, Paged};

use super::member_ops::{joined_unix, owner_joined_at, owner_member, row_member};
use super::members::StoredMember;
use super::model::StoredGroup;
use super::ops::GroupError;
use super::paging::{self, PageQuery, SortKey};
use super::{Caller, Groups, MAX_MEMBERS_PER_GROUP};

const MEMBERS_ONLY: &str = "only members may list this group's members";

/// The owner's place in the member list.
fn owner_key(group: &StoredGroup) -> Result<SortKey, GroupError> {
    Ok(SortKey {
        at: owner_joined_at(group)?,
        id: group.owner.to_string(),
    })
}

/// A membership row's place in the member list.
fn row_key(m: &StoredMember) -> Result<SortKey, GroupError> {
    Ok(SortKey {
        at: joined_unix(m)?,
        id: m.actor.to_string(),
    })
}

/// Whether a signed non-member may list the members of a group. Never, for
/// now (default 2 of docs/decisions/0020): §5.7 lets a provider expose
/// the list of a public group, and this is the seam that would.
fn outsiders_may_list(_group: &StoredGroup) -> bool {
    false
}

impl Groups {
    /// One page of the members of `group_id` (the owner included), for
    /// `actor`.
    pub async fn list_members(
        &self,
        actor: &Actor,
        group_id: &str,
        query: &PageQuery,
    ) -> Result<Paged<Member>, GroupError> {
        let group = self.settled_group(group_id).await?;
        let standing = self.standing(&Caller::Actor(actor.clone()), &group).await?;
        if !standing.is_member() && !outsiders_may_list(&group) {
            return Err(GroupError::Forbidden(MEMBERS_ONLY));
        }
        let rows = self
            .store
            .members(&group.id, MAX_MEMBERS_PER_GROUP + 2)
            .await?;
        let mut items = Vec::with_capacity(rows.len() + 1);
        items.push((owner_key(&group)?, owner_member(&group)?));
        // A row left for the owner by a transfer is not a membership.
        for m in rows.iter().filter(|m| m.actor != group.owner) {
            items.push((row_key(m)?, row_member(m)?));
        }
        Ok(paging::page(
            &format!("members {}", group.id),
            items,
            query,
        )?)
    }
}
