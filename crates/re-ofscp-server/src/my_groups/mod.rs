//! The user's group list at their home provider (spec §5.7, *My groups*;
//! docs/decisions/0018): the groups hosted here that they own or belong
//! to, plus membership pointers their clients record for remote groups.
//!
//! - [`request`]: reading `{groupRef}` and the role-hint body (`400`s).
//! - [`store`]: the `GroupPointer` rows.
//! - [`events`]: `groups.updated` for hosted membership changes.
//! - [`routes`]: `GET /api/me/groups`, `PUT`/`DELETE
//!   /api/me/groups/{groupRef}`.
//!
//! A pointer is a reference only. The provider never stores one for a group
//! it hosts (its own memberships are the authority) and never contacts the
//! group's provider to check one.

pub mod events;
pub mod request;
pub mod routes;
pub mod store;

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use re_ofscp_types::wire::GroupPointer;
use re_ofscp_types::{Actor, Authority};
use tokio::sync::{Mutex, MutexGuard};

use crate::db::DbError;
use crate::federation::{Decision, FederationPolicy};
use crate::groups::Groups;
use crate::groups::listing::{HostedEntry, ListingError};
use crate::timefmt;
use crate::ws::Hub;
use ofscp_core::ObjectUri;
use request::{GroupRef, group_uri};
use store::{Created, PointerStore, StoredPointer};

/// Most pointers one user may record (provider policy). A `PUT` of a new
/// pointer beyond it is refused with `409`.
pub const MAX_POINTERS_PER_ACTOR: usize = 1_000;
/// How often a `PUT` re-reads and retries when another process changed the
/// pointer under it, before answering `409`.
const PUT_ATTEMPTS: usize = 5;
/// Lock stripes serializing one user's pointer writes and their events.
const LOCK_STRIPES: usize = 64;

/// Why a group-list operation failed.
#[derive(Debug, thiserror::Error)]
pub enum MyGroupsError {
    /// Federation with the group's provider is not permitted (`403`).
    #[error("federation with {0} is not permitted")]
    Denied(Authority),
    /// The federation policy is not loaded yet (`503`).
    #[error("the federation policy is not loaded yet")]
    PolicyUnknown,
    /// A hosted group the caller does not belong to (`404`).
    #[error("you are not a member of this group")]
    NotMember,
    /// `DELETE` of a hosted group the caller belongs to (`409`).
    #[error("leave the group with POST /api/groups/{0}/leave")]
    Hosted(String),
    /// The caller already has [`MAX_POINTERS_PER_ACTOR`] pointers (`409`).
    #[error("you have recorded the most group pointers this provider allows")]
    Limit,
    /// The pointer kept changing under the write (`409`).
    #[error("the pointer kept changing; retry")]
    Contended,
    /// The hosted list could not be read in full (`500`).
    #[error(transparent)]
    Listing(#[from] ListingError),
    /// The caller holds more pointers than [`MAX_POINTERS_PER_ACTOR`]
    /// (`500`): `PUT` refuses the write that would do it, so the list is
    /// refused rather than shown with some left out.
    #[error("{0} holds more group pointers than this provider allows")]
    TooManyPointers(Actor),
    /// The database failed (`500`).
    #[error(transparent)]
    Db(#[from] DbError),
}

/// The group-list operations.
pub struct MyGroups {
    store: PointerStore,
    groups: Arc<Groups>,
    hub: Arc<Hub>,
    policy: Arc<FederationPolicy>,
    locks: Vec<Mutex<()>>,
}

impl std::fmt::Debug for MyGroups {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MyGroups").finish_non_exhaustive()
    }
}

/// The wire entry for a hosted group of `home`.
pub fn hosted_pointer(home: &Authority, e: &HostedEntry) -> Result<GroupPointer, DbError> {
    pointer(
        &group_uri(home, &e.group_id),
        Some(e.role.clone()),
        &e.updated_at,
    )
}

fn stored_pointer(p: &StoredPointer) -> Result<GroupPointer, DbError> {
    pointer(&p.group, p.role.clone(), &p.updated_at)
}

fn pointer(group: &str, role: Option<String>, updated_at: &str) -> Result<GroupPointer, DbError> {
    Ok(GroupPointer {
        group: ObjectUri::parse(group)
            .map_err(|_| DbError::Decode(format!("bad group URI {group:?}")))?,
        role,
        updated_at: timefmt::parse_timestamp(updated_at)
            .ok_or_else(|| DbError::Decode(format!("bad timestamp {updated_at:?}")))?,
    })
}

impl MyGroups {
    /// Group lists over `db`'s pointers and `groups`' memberships, telling
    /// `hub`'s connections of changes, refusing providers `policy` denies.
    pub fn new(
        store: PointerStore,
        groups: Arc<Groups>,
        hub: Arc<Hub>,
        policy: Arc<FederationPolicy>,
    ) -> Self {
        Self {
            store,
            groups,
            hub,
            policy,
            locks: (0..LOCK_STRIPES).map(|_| Mutex::new(())).collect(),
        }
    }

    fn home(&self) -> &Authority {
        self.groups.home()
    }

    /// Serialize `owner`'s pointer writes, so the events their devices
    /// receive come in the order the writes landed.
    async fn lock(&self, owner: &Actor) -> MutexGuard<'_, ()> {
        let mut h = DefaultHasher::new();
        owner.hash(&mut h);
        let stripe = (h.finish() % LOCK_STRIPES as u64) as usize;
        // `locks` has LOCK_STRIPES entries and `stripe` is below that.
        self.locks[stripe].lock().await
    }

    /// `GET /api/me/groups`: every hosted group `actor` belongs to, then
    /// every pointer, each sorted by URI.
    pub async fn list(&self, actor: &Actor) -> Result<Vec<GroupPointer>, MyGroupsError> {
        let mut out = Vec::new();
        for e in self.groups.hosted_entries(actor).await? {
            out.push(hosted_pointer(self.home(), &e)?);
        }
        let mut stored = self.store.list(actor, MAX_POINTERS_PER_ACTOR + 1).await?;
        if stored.len() > MAX_POINTERS_PER_ACTOR {
            return Err(MyGroupsError::TooManyPointers(actor.clone()));
        }
        stored.sort_by(|a, b| a.group.cmp(&b.group));
        for p in &stored {
            out.push(stored_pointer(p)?);
        }
        Ok(out)
    }

    /// `PUT /api/me/groups/{groupRef}` with role hint `role` at `now`.
    pub async fn put(
        &self,
        actor: &Actor,
        group: &GroupRef,
        role: Option<&str>,
        now: i64,
    ) -> Result<GroupPointer, MyGroupsError> {
        // A hosted group involves no other provider, so no federation
        // policy: it is answered even before the policy has loaded.
        if group.authority == *self.home() {
            return match self.groups.hosted_entry(actor, &group.group_id).await? {
                Some(e) => Ok(hosted_pointer(self.home(), &e)?),
                None => Err(MyGroupsError::NotMember),
            };
        }
        match self.policy.decide(&group.authority) {
            Decision::Permitted => {}
            Decision::Denied => return Err(MyGroupsError::Denied(group.authority.clone())),
            Decision::Unknown => return Err(MyGroupsError::PolicyUnknown),
        }
        let uri = group.uri();
        let _held = self.lock(actor).await;
        for _ in 0..PUT_ATTEMPTS {
            match self.store.get(actor, &uri).await? {
                Some(p) if p.role.as_deref() == role => return Ok(stored_pointer(&p)?),
                Some(p) => {
                    let updated = self
                        .store
                        .update_role(actor, &uri, p.role.as_deref(), role, now)
                        .await?;
                    if let Some(p) = updated {
                        let entry = stored_pointer(&p)?;
                        events::send(&self.hub, actor, vec![entry.clone()], Vec::new());
                        return Ok(entry);
                    }
                }
                None => {
                    if let Some(entry) = self.create(actor, &uri, role, now).await? {
                        return Ok(entry);
                    }
                }
            }
        }
        Err(MyGroupsError::Contended)
    }

    /// Record a new pointer within the limit. `None` if one appeared
    /// meanwhile (the caller reads it again).
    async fn create(
        &self,
        actor: &Actor,
        uri: &str,
        role: Option<&str>,
        now: i64,
    ) -> Result<Option<GroupPointer>, MyGroupsError> {
        let cap = MAX_POINTERS_PER_ACTOR;
        if self.store.count(actor, cap + 1).await? >= cap {
            return Err(MyGroupsError::Limit);
        }
        let p = match self.store.create(actor, uri, role, now).await? {
            Created::Written(p) => p,
            Created::Exists => return Ok(None),
        };
        // Another process may have created one at the same time: checked
        // again after the write, and taken back when over (as for groups).
        if self.store.count(actor, cap + 1).await? > cap {
            self.store.delete(actor, uri).await?;
            return Err(MyGroupsError::Limit);
        }
        let entry = stored_pointer(&p)?;
        events::send(&self.hub, actor, vec![entry.clone()], Vec::new());
        Ok(Some(entry))
    }

    /// `DELETE /api/me/groups/{groupRef}`.
    pub async fn delete(&self, actor: &Actor, group: &GroupRef) -> Result<(), MyGroupsError> {
        if group.authority == *self.home() {
            return match self.groups.hosted_entry(actor, &group.group_id).await? {
                Some(_) => Err(MyGroupsError::Hosted(group.group_id.clone())),
                None => Ok(()),
            };
        }
        let uri = group.uri();
        let _held = self.lock(actor).await;
        if self.store.get(actor, &uri).await?.is_none() {
            return Ok(());
        }
        self.store.delete(actor, &uri).await?;
        match ObjectUri::parse(&uri) {
            Ok(removed) => events::send(&self.hub, actor, Vec::new(), vec![removed]),
            Err(e) => tracing::error!(error = %e, uri, "a canonical group URI did not parse"),
        }
        Ok(())
    }
}
