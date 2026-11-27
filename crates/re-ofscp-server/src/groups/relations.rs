//! Group memberships for the visibility policy (§6.1 `sharedGroups`, §6.5
//! membership listing): [`GroupMemberships`] answered from this
//! provider's groups.
//!
//! A user belongs to a group as its owner or as an active member. Only
//! active groups count, and a group appears in a listing only when the
//! viewer may read it (§5.5): a private group stays unknown to outsiders.

use std::collections::{BTreeMap, HashSet};

use re_ofscp_types::Actor;

use super::access::{self, Standing};
use super::model::StoredGroup;
use super::{Caller, Groups, MAX_MEMBERSHIPS_PER_ACTOR};
use crate::db::DbError;
use crate::privacy::seams::RelFuture;
use crate::privacy::{GroupMemberships, RelError, Viewer};

/// One user's groups, with where the user stands in each.
struct Belonging {
    /// Active groups, by id.
    groups: BTreeMap<String, (StoredGroup, Standing)>,
}

impl Belonging {
    fn ids(&self) -> HashSet<&str> {
        self.groups.keys().map(String::as_str).collect()
    }
}

impl Groups {
    /// Every active group `actor` owns or is an active member of. Neither
    /// read is capped: the limits are checked around writes, and concurrent
    /// writes (two ownership transfers, say) can briefly exceed them, so a
    /// capped read could silently drop a group and, with it, a shared one.
    async fn belonging(&self, actor: &Actor) -> Result<Belonging, DbError> {
        let mut groups = BTreeMap::new();
        for g in self.store.all_owned_groups(actor).await? {
            groups.insert(g.id.clone(), (g, Standing::Owner));
        }
        // Every membership the limit allows, plus a stray row (left by an
        // ownership transfer, docs/decisions/0020; ignored below) in each
        // owned group, in one read; more only if there are more.
        let expected = MAX_MEMBERSHIPS_PER_ACTOR + groups.len() + 1;
        let memberships = self.store.all_memberships_of(actor, expected).await?;
        let mut roles: BTreeMap<String, String> = memberships.into_iter().collect();
        let ids: Vec<String> = roles.keys().cloned().collect();
        for g in self.store.active_groups(&ids).await? {
            // The owner is never also a member; a stray row is ignored.
            if let Some(role) = roles.remove(&g.id)
                && g.owner != *actor
            {
                groups.insert(g.id.clone(), (g, Standing::Member(role)));
            }
        }
        Ok(Belonging { groups })
    }

    /// Whether `a` and `b` both belong to some active group hosted here.
    pub async fn share_a_group(&self, a: &Actor, b: &Actor) -> Result<bool, DbError> {
        let of_a = self.belonging(a).await?;
        if of_a.groups.is_empty() {
            return Ok(false);
        }
        let of_b = self.belonging(b).await?;
        Ok(!of_a.ids().is_disjoint(&of_b.ids()))
    }

    /// The object URIs (§2.2) of the groups `subject` belongs to that
    /// `viewer` may read (§5.5), sorted by group id.
    pub async fn groups_visible_to(
        &self,
        subject: &Actor,
        viewer: &Viewer,
    ) -> Result<Vec<String>, DbError> {
        let of_subject = self.belonging(subject).await?;
        let caller = match viewer {
            Viewer::Actor(a) => Caller::Actor(a.clone()),
            Viewer::Anonymous | Viewer::Provider(_) => Caller::Anonymous,
        };
        let of_viewer = match &caller {
            Caller::Actor(a) if a == subject => None,
            Caller::Actor(a) => Some(self.belonging(a).await?),
            Caller::Anonymous => Some(Belonging {
                groups: BTreeMap::new(),
            }),
        };
        Ok(of_subject
            .groups
            .iter()
            .filter(|(id, (group, own))| {
                let standing = match &of_viewer {
                    // The subject looking at their own list.
                    None => own.clone(),
                    Some(v) => v
                        .groups
                        .get(*id)
                        .map_or(Standing::Outsider, |(_, s)| s.clone()),
                };
                access::can_read_group(&standing, &group.policy())
            })
            .map(|(id, _)| format!("https://{}/api/groups/{id}", self.home()))
            .collect())
    }
}

fn rel(e: DbError) -> RelError {
    RelError(e.to_string())
}

impl GroupMemberships for Groups {
    fn share_a_group<'a>(&'a self, a: &'a Actor, b: &'a Actor) -> RelFuture<'a, bool> {
        Box::pin(async move { Groups::share_a_group(self, a, b).await.map_err(rel) })
    }

    fn groups_visible_to<'a>(
        &'a self,
        subject: &'a Actor,
        viewer: &'a Viewer,
    ) -> RelFuture<'a, Vec<String>> {
        Box::pin(async move {
            Groups::groups_visible_to(self, subject, viewer)
                .await
                .map_err(rel)
        })
    }
}
