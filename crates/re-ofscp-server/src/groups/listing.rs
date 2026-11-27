//! The caller's own entries in their group list (spec §5.7, *My groups*;
//! docs/decisions/0018): every group hosted here that they own or are an
//! active member of, with their current role and when the entry last
//! changed. Pointers to remote groups live in `crate::my_groups`.
//!
//! `updatedAt` reads `Membership.updated_at` (written on a role change) and
//! `Group.owner_since` (written on an ownership transfer). Both columns are
//! optional: where one is absent the entry dates from `joined_at` or the
//! group's `created_at`.

use std::collections::BTreeMap;

use re_ofscp_types::Actor;
use serde::Deserialize;

use super::store::{GroupStore, status};
use super::{Groups, MAX_GROUPS_PER_OWNER};
use crate::db::{DbError, Ql};

/// Most memberships one actor may hold (provider policy). `GET
/// /api/me/groups` lists every one, so the joins that create memberships
/// enforce it; a list that finds more fails rather than leave some out.
pub const MAX_MEMBERSHIPS_PER_ACTOR: usize = 1_000;

/// Members of a deleting group read per page while announcing its end.
const MEMBERS_PAGE: usize = 500;

/// One entry of the caller's hosted group list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedEntry {
    /// The group's local id.
    pub group_id: String,
    /// `owner`, or the membership's role.
    pub role: String,
    /// RFC 3339 time the entry last changed.
    pub updated_at: String,
}

/// Why the hosted list could not be read.
#[derive(Debug, thiserror::Error)]
pub enum ListingError {
    /// The database failed.
    #[error(transparent)]
    Db(#[from] DbError),
    /// The actor holds more memberships than [`MAX_MEMBERSHIPS_PER_ACTOR`].
    #[error("{0} holds more memberships than this provider allows")]
    TooMany(Actor),
}

#[derive(Deserialize)]
struct MembershipRow {
    group_id: String,
    role: String,
    joined_at: String,
    #[serde(default)]
    updated_at: Option<String>,
}

impl MembershipRow {
    fn changed_at(self) -> (String, String, String) {
        let at = self.updated_at.unwrap_or(self.joined_at);
        (self.group_id, self.role, at)
    }
}

#[derive(Deserialize)]
struct OwnerRow {
    group_id: String,
    owner: String,
    status: String,
    created_at: String,
    #[serde(default)]
    owner_since: Option<String>,
}

impl OwnerRow {
    fn owner_entry(self) -> HostedEntry {
        HostedEntry {
            updated_at: self.owner_since.unwrap_or(self.created_at),
            group_id: self.group_id,
            role: super::access::roles::OWNER.to_owned(),
        }
    }
}

#[derive(Deserialize)]
struct ActorRow {
    actor: String,
}

/// A group row, whatever its status: who owns it and whether it is live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupOwner {
    /// The owner.
    pub owner: Actor,
    /// Whether the group is active (not being deleted).
    pub active: bool,
}

impl GroupStore {
    /// The active groups `owner` owns, as owner entries.
    async fn owner_entries(&self, owner: &Actor) -> Result<Vec<HostedEntry>, DbError> {
        let q = Ql::new("Group.filter(.owner == ")
            .str(&owner.to_string())
            .raw(" && .status == ")
            .str(status::ACTIVE)
            .raw(").limit(")
            .uint(MAX_GROUPS_PER_OWNER as u64 + 1)
            .raw(")");
        Ok(self
            .db
            .fetch::<OwnerRow>(&q)
            .await?
            .into_iter()
            .map(|r| r.data.owner_entry())
            .collect())
    }

    /// `actor`'s active memberships, at most `cap`.
    async fn membership_rows(
        &self,
        actor: &Actor,
        cap: usize,
    ) -> Result<Vec<(String, String, String)>, DbError> {
        let q = Ql::new("Membership.filter(.actor == ")
            .str(&actor.to_string())
            .raw(" && .status == ")
            .str(status::ACTIVE)
            .raw(").limit(")
            .uint(cap as u64)
            .raw(")");
        Ok(self
            .db
            .fetch::<MembershipRow>(&q)
            .await?
            .into_iter()
            .map(|r| r.data.changed_at())
            .collect())
    }

    /// `actor`'s active membership of `group_id`: role and change time.
    async fn membership_row(
        &self,
        group_id: &str,
        actor: &Actor,
    ) -> Result<Option<(String, String)>, DbError> {
        let q = Ql::new("Membership.filter(.group_id == ")
            .str(group_id)
            .raw(" && .actor == ")
            .str(&actor.to_string())
            .raw(" && .status == ")
            .str(status::ACTIVE)
            .raw(")");
        Ok(self
            .db
            .fetch::<MembershipRow>(&q)
            .await?
            .into_iter()
            .next()
            .map(|r| {
                let (_, role, at) = r.data.changed_at();
                (role, at)
            }))
    }

    /// The row of group `group_id` in any status, if it still exists.
    pub async fn group_owner(&self, group_id: &str) -> Result<Option<GroupOwner>, DbError> {
        let q = Ql::new("Group.filter(.group_id == ").str(group_id).raw(")");
        let Some(row) = self.db.fetch::<OwnerRow>(&q).await?.into_iter().next() else {
            return Ok(None);
        };
        let owner = Actor::parse_canonical(&row.data.owner)
            .map_err(|_| DbError::Decode(format!("group {group_id}: bad owner")))?;
        Ok(Some(GroupOwner {
            owner,
            active: row.data.status == status::ACTIVE,
        }))
    }

    /// Every actor with an active membership of `group_id`, read in pages.
    /// Meant for a group being deleted, whose membership no longer changes.
    pub async fn member_actors(&self, group_id: &str) -> Result<Vec<Actor>, DbError> {
        let mut actors = Vec::new();
        let mut offset = 0usize;
        loop {
            let q = Ql::new("Membership.filter(.group_id == ")
                .str(group_id)
                .raw(" && .status == ")
                .str(status::ACTIVE)
                .raw(").offset(")
                .uint(offset as u64)
                .raw(").limit(")
                .uint(MEMBERS_PAGE as u64)
                .raw(")");
            let page = self.db.fetch::<ActorRow>(&q).await?;
            let full = page.len() == MEMBERS_PAGE;
            offset += page.len();
            for row in page {
                let actor = Actor::parse_canonical(&row.data.actor)
                    .map_err(|_| DbError::Decode(format!("group {group_id}: bad member")))?;
                actors.push(actor);
            }
            if !full {
                return Ok(actors);
            }
        }
    }
}

impl Groups {
    /// Every active group hosted here that `actor` owns or is an active
    /// member of, by group id. Fails with [`ListingError::TooMany`] rather
    /// than leave a membership out.
    pub async fn hosted_entries(&self, actor: &Actor) -> Result<Vec<HostedEntry>, ListingError> {
        let mut entries: BTreeMap<String, HostedEntry> = BTreeMap::new();
        for e in self.store.owner_entries(actor).await? {
            entries.insert(e.group_id.clone(), e);
        }
        let rows = self
            .store
            .membership_rows(actor, MAX_MEMBERSHIPS_PER_ACTOR + 1)
            .await?;
        if rows.len() > MAX_MEMBERSHIPS_PER_ACTOR {
            return Err(ListingError::TooMany(actor.clone()));
        }
        let ids: Vec<String> = rows.iter().map(|(id, _, _)| id.clone()).collect();
        let mut by_id: BTreeMap<String, (String, String)> = rows
            .into_iter()
            .map(|(id, role, at)| (id, (role, at)))
            .collect();
        for group in self.store.active_groups(&ids).await? {
            // The owner is never also a member; a stray row is ignored.
            if group.owner == *actor {
                continue;
            }
            if let Some((role, updated_at)) = by_id.remove(&group.id) {
                entries.insert(
                    group.id.clone(),
                    HostedEntry {
                        group_id: group.id,
                        role,
                        updated_at,
                    },
                );
            }
        }
        Ok(entries.into_values().collect())
    }

    /// `actor`'s entry for the hosted group `group_id` as it is now: `None`
    /// when the group is gone or being deleted, or they do not belong to it.
    pub async fn hosted_entry(
        &self,
        actor: &Actor,
        group_id: &str,
    ) -> Result<Option<HostedEntry>, DbError> {
        let q = Ql::new("Group.filter(.group_id == ")
            .str(group_id)
            .raw(" && .status == ")
            .str(status::ACTIVE)
            .raw(")");
        let Some(group) = self
            .store
            .db
            .fetch::<OwnerRow>(&q)
            .await?
            .into_iter()
            .next()
        else {
            return Ok(None);
        };
        if group.data.owner == actor.to_string() {
            return Ok(Some(group.data.owner_entry()));
        }
        Ok(self
            .store
            .membership_row(group_id, actor)
            .await?
            .map(|(role, updated_at)| HostedEntry {
                group_id: group_id.to_owned(),
                role,
                updated_at,
            }))
    }
}
