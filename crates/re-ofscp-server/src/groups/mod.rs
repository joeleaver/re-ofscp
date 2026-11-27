//! Groups and channels (spec §5.2, §5.2.1, §5.5, §11; docs/decisions/0014).
//!
//! - [`access`]: the one effective-read-access and permission rule.
//! - [`model`]: stored shapes and request → state.
//! - [`store`]: rhypedb queries for groups and channels; `members.rs` for
//!   memberships.
//! - [`ops`]: the operations the endpoints (and later surfaces) call.
//! - [`routes`]: the §5.5 HTTP endpoints and `GET /api/tiers`.
//! - [`listing`]: a user's hosted group-list entries (§5.7 *My groups*,
//!   served by `crate::my_groups`).
//! - [`invite_routes`]: the §5.6 invite endpoints; [`invites`] holds their
//!   operations, [`invite_model`] tokens and terms, `invite_store.rs` the
//!   rows and use slots (docs/decisions/0019).
//! - [`member_routes`]: the §5.7 membership endpoints: joining and join
//!   requests ([`joining`]), the member list (`roster.rs`, paged by
//!   [`paging`]), leave, kick, role and nickname changes ([`member_edits`])
//!   and ownership transfer (`transfer.rs`; docs/decisions/0020).
//! - `ending.rs`: ending a deleted group's memberships, announcing each to
//!   the [`MembershipListener`]s, before the purge.
//!
//! The owner is the group's `owner` field and every other member is a
//! `Membership` row ([`Groups::add_member`], [`Groups::set_role`],
//! [`Groups::remove_member`]), which invites (§5.6) and guests (§4.8)
//! also build on.

pub mod access;
mod claims;
mod ending;
pub mod invite_model;
pub mod invite_routes;
mod invite_store;
pub mod invites;
pub mod joining;
pub mod listing;
pub mod member_edits;
mod member_ops;
pub mod member_routes;
mod members;
pub mod model;
pub mod ops;
mod owner_store;
pub mod paging;
mod relations;
mod removal;
pub mod requests;
mod roster;
pub mod routes;
pub mod store;
mod transfer;
pub mod validate;

pub use member_ops::Updated;

use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use re_ofscp_types::{Actor, Authority};
use tokio::sync::broadcast;

use crate::db::{Db, DbError};
use crate::signing::Clock;
use access::Standing;
use model::StoredGroup;
use store::GroupStore;

/// Most groups one actor may own (provider policy, §5.5 "MAY restrict").
pub const MAX_GROUPS_PER_OWNER: usize = 100;
/// Most channels in one group; bounds the channel list response.
pub const MAX_CHANNELS_PER_GROUP: usize = 200;
/// Most members of one group, the owner aside (provider policy). Bounds
/// the member list, which is read whole to be ordered (docs/decisions/0020).
pub const MAX_MEMBERS_PER_GROUP: usize = 10_000;
/// Most groups one actor may be a member of, owned groups aside (provider
/// policy). `GET /api/me/groups` lists every hosted membership, so joining
/// past this is refused rather than leaving groups out of that list.
pub const MAX_MEMBERSHIPS_PER_ACTOR: usize = 1_000;
/// Most pending join requests of one group (provider policy).
pub const MAX_PENDING_REQUESTS_PER_GROUP: usize = 1_000;
/// How often the sweeper finishes interrupted group deletions.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(300);
/// How long a pending channel or membership may stay unconfirmed before
/// the sweeper removes it. Far longer than any create takes; a writer that
/// is slower still finds its row gone and fails cleanly.
pub const PENDING_TTL: Duration = Duration::from_secs(600);
/// Groups the sweeper purges per batch.
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

/// Told of every membership change, synchronously and in full, from the
/// write that made it (registered with [`Groups::on_membership`]).
///
/// Unlike the bounded [`AccessChange`] broadcast, nothing here can lag: a
/// group's deletion names every one of its members, in pages, which could
/// be far more than a broadcast buffers. A listener must not block or do
/// I/O (it runs inside the write); it records the change and returns.
pub trait MembershipListener: Send + Sync {
    /// `actor`'s membership of `group_id` began, ended or changed role, or
    /// the group was deleted. The change has committed (or may have: a
    /// failed write is announced too, decision 0014), so a fresh read
    /// shows its effect.
    fn membership_changed(&self, group_id: &str, actor: &Actor);
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
///
/// A clone is the same service, not a copy: it shares the store, the
/// [`AccessChange`] broadcast and the [`MembershipListener`]s. It lets a
/// write finish in a task of its own, which outlives a dropped request
/// (`member_ops.rs`).
#[derive(Clone)]
pub struct Groups {
    /// Storage.
    pub store: GroupStore,
    home: Authority,
    clock: Arc<dyn Clock>,
    changes: broadcast::Sender<AccessChange>,
    listeners: Arc<RwLock<Vec<Arc<dyn MembershipListener>>>>,
}

impl std::fmt::Debug for Groups {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Groups").field("home", &self.home).finish()
    }
}

impl Groups {
    /// Groups hosted by `home`, stored in `db`, telling the time by
    /// `clock` (revision claims and the sweeper).
    pub fn new(home: Authority, db: Arc<Db>, clock: Arc<dyn Clock>) -> Self {
        Self {
            store: GroupStore::new(db),
            home,
            clock,
            changes: broadcast::channel(CHANGE_BUFFER).0,
            listeners: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// This provider's authority.
    pub fn home(&self) -> &Authority {
        &self.home
    }

    /// Now, in unix seconds.
    fn now(&self) -> i64 {
        self.clock.now().unix_timestamp()
    }

    /// Receive every [`AccessChange`] from now on.
    pub fn subscribe_changes(&self) -> broadcast::Receiver<AccessChange> {
        self.changes.subscribe()
    }

    /// Tell `listener` of every membership change from now on.
    pub fn on_membership(&self, listener: Arc<dyn MembershipListener>) {
        self.listeners
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .push(listener);
    }

    /// Tell the [`MembershipListener`]s, and them only, that `actor`'s
    /// membership of `group_id` changed.
    fn tell_listeners(&self, group_id: &str, actor: &Actor) {
        let listeners = self
            .listeners
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        for l in listeners.iter() {
            l.membership_changed(group_id, actor);
        }
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

    /// Announce a change to `actor`'s membership of `group_id`: to live
    /// readers (the broadcast) and to the membership listeners.
    fn member_changed(&self, group_id: &str, actor: &Actor) {
        self.changed(AccessChange::Member {
            group_id: group_id.to_owned(),
            actor: actor.clone(),
        });
        self.tell_listeners(group_id, actor);
    }

    /// One sweeper pass at `now` (unix seconds): finish the group
    /// deletions a crash or a database fault interrupted (announcing their
    /// memberships' end first, `finish_deletion` in `ending.rs`), expire the
    /// pending channels and memberships whose writers never confirmed them
    /// (older than [`PENDING_TTL`]), finish interrupted ownership transfers
    /// (`transfer.rs`), and delete expired revision claims and invites. A
    /// step or a group's purge that fails is logged and left for the next
    /// pass; the rest of the pass goes on.
    pub async fn sweep(&self, now: i64) -> Result<usize, DbError> {
        // Expiry failing must not hold up the purges (nor the reverse).
        let cutoff = now.saturating_sub(PENDING_TTL.as_secs() as i64);
        if let Err(e) = self.store.expire_pending(cutoff).await {
            tracing::warn!(error = %e, "expiring pending group rows failed");
        }
        if let Err(e) = self.finish_transfers().await {
            tracing::warn!(error = %e, "finishing interrupted ownership transfers failed");
        }
        if let Err(e) = self.store.purge_claims(now).await {
            tracing::warn!(error = %e, "purging expired revision claims failed");
        }
        if let Err(e) = self.purge_expired_invites(now).await {
            tracing::warn!(error = %e, "purging expired invites failed");
        }
        let mut purged = 0;
        loop {
            let batch = self.store.deleting(SWEEP_BATCH).await?;
            let full = batch.len() == SWEEP_BATCH;
            let mut failed = false;
            for id in batch {
                match self.finish_deletion(&id).await {
                    Ok(()) => purged += 1,
                    Err(e) => {
                        tracing::warn!(group = %id, error = %e, "purging a deleted group failed");
                        failed = true;
                    }
                }
            }
            // A failed purge leaves its group in the next batch: stop
            // rather than retry it at once.
            if !full || failed {
                return Ok(purged);
            }
        }
    }

    /// Run [`Groups::sweep`] now and every [`SWEEP_INTERVAL`] until the
    /// task is dropped.
    pub async fn sweep_forever(self: Arc<Self>) {
        let mut tick = tokio::time::interval(SWEEP_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            match self.sweep(self.now()).await {
                Ok(0) => {}
                Ok(n) => tracing::info!(groups = n, "finished interrupted group deletions"),
                Err(e) => tracing::warn!(error = %e, "sweeping deleted groups failed"),
            }
        }
    }
}
