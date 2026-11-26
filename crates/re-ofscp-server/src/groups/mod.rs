//! Groups and channels (spec §5.2, §5.2.1, §5.5, §11; docs/decisions/0008).
//!
//! - [`access`]: the one effective-read-access and permission rule.
//! - [`model`]: stored shapes and request → state.
//! - [`store`]: rhypedb queries.
//! - [`ops`]: the operations the endpoints (and later surfaces) call.
//! - [`routes`]: the §5.5 HTTP endpoints and `GET /api/tiers`.
//!
//! Membership is minimal here: the owner is the group's `owner` field and
//! every other member is a `Membership` row ([`store::GroupStore::add_member`]
//! and friends), which full membership (§5.7), invites (§5.6) and guests
//! (§4.8) build on.

pub mod access;
pub mod model;
pub mod ops;
pub mod routes;
pub mod store;
pub mod validate;

use std::sync::Arc;
use std::time::Duration;

use re_ofscp_types::{Actor, Authority};
use tokio::sync::broadcast;

use crate::db::{Db, DbError};
use access::Standing;
use model::StoredGroup;
use store::GroupStore;

/// Most groups one actor may own (provider policy, §5.5 "MAY restrict").
pub const MAX_GROUPS_PER_OWNER: usize = 100;
/// Most channels in one group; bounds the channel list response.
pub const MAX_CHANNELS_PER_GROUP: usize = 200;
/// How often the sweeper finishes interrupted group deletions.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(300);
/// Groups the sweeper purges per pass.
const SWEEP_BATCH: usize = 100;
/// Buffered [`AccessChange`]s per receiver before it lags.
const CHANGE_BUFFER: usize = 1024;

/// Something that may change who can read what. Live readers (WebSocket
/// subscriptions, §7.1) re-evaluate their access with [`access`] on each
/// change that names their group, and end with `access_revoked` when it
/// is lost. A receiver that lags must re-check everything it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessChange {
    /// The group's tier, permissions or roles changed, or it was deleted.
    Group {
        /// The group.
        group_id: String,
    },
    /// The channel's tier or permissions changed, or it was deleted.
    Channel {
        /// The group.
        group_id: String,
        /// The channel.
        channel_id: String,
    },
    /// The actor's membership of the group began, ended or changed role.
    Member {
        /// The group.
        group_id: String,
        /// The member.
        actor: Actor,
    },
}

/// Who is calling, as far as group access is concerned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Caller {
    /// An unsigned request, or one signed by a provider (§8.1): never a
    /// member of anything.
    Anonymous,
    /// A user-signed request, local or remote (§2.2: identity is the full
    /// `handle@domain`).
    Actor(Actor),
}

/// Groups, channels and minimal membership.
pub struct Groups {
    /// Storage.
    pub store: GroupStore,
    home: Authority,
    changes: broadcast::Sender<AccessChange>,
}

impl std::fmt::Debug for Groups {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Groups").field("home", &self.home).finish()
    }
}

impl Groups {
    /// Groups hosted by `home`, stored in `db`.
    pub fn new(home: Authority, db: Arc<Db>) -> Self {
        Self {
            store: GroupStore::new(db),
            home,
            changes: broadcast::channel(CHANGE_BUFFER).0,
        }
    }

    /// This provider's authority.
    pub fn home(&self) -> &Authority {
        &self.home
    }

    /// Receive every [`AccessChange`] from now on.
    pub fn subscribe_changes(&self) -> broadcast::Receiver<AccessChange> {
        self.changes.subscribe()
    }

    fn changed(&self, change: AccessChange) {
        // No receivers is normal (nothing live yet).
        let _ = self.changes.send(change);
    }

    /// Where `caller` stands with `group` right now.
    pub async fn standing(
        &self,
        caller: &Caller,
        group: &StoredGroup,
    ) -> Result<Standing, DbError> {
        let Caller::Actor(actor) = caller else {
            return Ok(Standing::Outsider);
        };
        if *actor == group.owner {
            return Ok(Standing::Owner);
        }
        Ok(match self.store.role_of(&group.id, actor).await? {
            Some(role) => Standing::Member(role),
            None => Standing::Outsider,
        })
    }

    /// Record `actor` as a member with `role` (§5.7 seam). `false` if they
    /// already are one.
    pub async fn add_member(
        &self,
        group_id: &str,
        actor: &Actor,
        role: &str,
        now: i64,
    ) -> Result<bool, DbError> {
        let added = self.store.add_member(group_id, actor, role, now).await?;
        if added {
            self.member_changed(group_id, actor);
        }
        Ok(added)
    }

    /// Change a member's role (§5.7 seam). `false` if not a member.
    pub async fn set_role(
        &self,
        group_id: &str,
        actor: &Actor,
        role: &str,
    ) -> Result<bool, DbError> {
        let set = self.store.set_role(group_id, actor, role).await?;
        if set {
            self.member_changed(group_id, actor);
        }
        Ok(set)
    }

    /// End a membership (§5.7 seam).
    pub async fn remove_member(&self, group_id: &str, actor: &Actor) -> Result<(), DbError> {
        self.store.remove_member(group_id, actor).await?;
        self.member_changed(group_id, actor);
        Ok(())
    }

    fn member_changed(&self, group_id: &str, actor: &Actor) {
        self.changed(AccessChange::Member {
            group_id: group_id.to_owned(),
            actor: actor.clone(),
        });
    }

    /// Finish every group deletion that was interrupted (a crash or a
    /// database fault between marking a group and purging it).
    pub async fn sweep_deleting(&self) -> Result<usize, DbError> {
        let mut purged = 0;
        loop {
            let batch = self.store.deleting(SWEEP_BATCH).await?;
            if batch.is_empty() {
                return Ok(purged);
            }
            let full = batch.len() == SWEEP_BATCH;
            for id in batch {
                self.store.purge_group(&id).await?;
                purged += 1;
            }
            if !full {
                return Ok(purged);
            }
        }
    }

    /// Run [`Groups::sweep_deleting`] now and every [`SWEEP_INTERVAL`],
    /// until the task is dropped.
    pub async fn sweep_forever(self: Arc<Self>) {
        let mut tick = tokio::time::interval(SWEEP_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            match self.sweep_deleting().await {
                Ok(0) => {}
                Ok(n) => tracing::info!(groups = n, "finished interrupted group deletions"),
                Err(e) => tracing::warn!(error = %e, "sweeping deleted groups failed"),
            }
        }
    }
}
