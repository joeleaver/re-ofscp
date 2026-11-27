//! Follows (spec §7.6; docs/decisions/0022): the channels a local user
//! follows, as pointers. The provider stores which channels, never a
//! compiled feed; the client composes the home feed by reading each
//! channel from its home provider.
//!
//! - [`request`]: reading channel references and the `POST` body (`400`s).
//! - [`store`]: the `Follow` rows.
//! - [`routes`]: `GET`/`POST /api/me/follows`, `DELETE
//!   /api/me/follows/{channelRef}`.
//!
//! Effective read access (§11.3, security requirement 5) applies to local
//! channels: a follow needs it, and the list shows a local follow only
//! while the user still has it. Nothing here contacts another provider.

pub mod request;
pub mod routes;
pub mod store;

use std::sync::Arc;

use ofscp_core::wire::Follow;
use ofscp_core::{Authority, ObjectRef};
use re_ofscp_types::Actor;

use crate::db::DbError;
use crate::federation::{Decision, FederationPolicy};
use crate::groups::Groups;
use crate::groups::model::StoredChannel;
use crate::timefmt;
use request::ChannelRef;
use store::{Created, FollowStore, StoredFollow};

/// Most follows one user may hold (provider policy): the number of their
/// follow slots (`store.rs`). Following a new channel beyond it is refused
/// with `409`.
pub const MAX_FOLLOWS_PER_ACTOR: usize = 1_000;
/// How often a follow reads again when another request created the same
/// follow or took the slot it picked, before answering `409`.
const CREATE_ATTEMPTS: usize = 8;

/// Why a follow operation failed.
#[derive(Debug, thiserror::Error)]
pub enum FollowError {
    /// Federation with the channel's provider is not permitted (`403`).
    #[error("federation with {0} is not permitted")]
    Denied(Authority),
    /// The federation policy is not loaded yet (`503`).
    #[error("the federation policy is not loaded yet")]
    PolicyUnknown,
    /// No such local channel, or one the caller cannot read (`404`, §11.3).
    #[error("no such channel")]
    NotFound,
    /// The caller already follows [`MAX_FOLLOWS_PER_ACTOR`] channels (`409`).
    #[error("you follow the most channels this provider allows")]
    Limit,
    /// The follow kept changing under the write (`409`).
    #[error("the follow kept changing; retry")]
    Contended,
    /// The caller holds more follows than [`MAX_FOLLOWS_PER_ACTOR`]
    /// (`500`): following refuses the write that would do it, so the list
    /// is refused rather than shown with some left out.
    #[error("{0} holds more follows than this provider allows")]
    TooMany(Actor),
    /// The database failed (`500`).
    #[error(transparent)]
    Db(#[from] DbError),
}

/// Follows.
#[derive(Debug)]
pub struct Follows {
    store: FollowStore,
    groups: Arc<Groups>,
    policy: Arc<FederationPolicy>,
}

impl Follows {
    /// Follows kept in `store`, checking local channels against `groups`
    /// and remote providers against `policy`.
    pub fn new(store: FollowStore, groups: Arc<Groups>, policy: Arc<FederationPolicy>) -> Self {
        Self {
            store,
            groups,
            policy,
        }
    }

    /// `GET /api/me/follows`: `actor`'s follows, oldest first. A local
    /// follow appears only while `actor` can read its channel; one whose
    /// channel is gone is pruned (§7.6 "the stale pointer MAY be pruned").
    /// Remote follows are always listed: the federation policy governs
    /// talking to a provider, not remembering it.
    pub async fn list(&self, actor: &Actor) -> Result<Vec<Follow>, FollowError> {
        let rows = self.store.list(actor, MAX_FOLLOWS_PER_ACTOR + 1).await?;
        if rows.len() > MAX_FOLLOWS_PER_ACTOR {
            return Err(FollowError::TooMany(actor.clone()));
        }
        let local: Vec<String> = rows
            .iter()
            .filter(|f| is_local(&f.channel))
            .map(|f| f.channel.clone())
            .collect();
        let readable = self.groups.readable_among(actor, &local).await?;
        for gone in &readable.gone {
            self.store.delete(actor, gone).await?;
        }
        let mut shown: Vec<&StoredFollow> = rows
            .iter()
            .filter(|f| !is_local(&f.channel) || readable.channels.contains_key(&f.channel))
            .collect();
        shown.sort_by(|a, b| {
            let at = |f: &StoredFollow| timefmt::unix(&f.created_at).unwrap_or(i64::MAX);
            at(a).cmp(&at(b)).then_with(|| a.channel.cmp(&b.channel))
        });
        shown
            .into_iter()
            .map(|f| to_wire(f, readable.channels.get(&f.channel)))
            .collect()
    }

    /// `POST /api/me/follows`: `actor` follows `channel` at `now` (unix
    /// seconds). Returns the follow and whether it is new (`201`) or
    /// already existed (`200`).
    pub async fn follow(
        &self,
        actor: &Actor,
        channel: &ChannelRef,
        now: i64,
    ) -> Result<(Follow, bool), FollowError> {
        let local = match channel {
            ChannelRef::Local {
                channel_id,
                group_id,
            } => {
                let found = self
                    .groups
                    .readable_channel(actor, channel_id)
                    .await?
                    .ok_or(FollowError::NotFound)?;
                // A channel URI naming another group names no channel.
                if group_id.as_ref().is_some_and(|g| *g != found.group_id) {
                    return Err(FollowError::NotFound);
                }
                Some(found)
            }
            ChannelRef::Remote { authority, .. } => {
                match self.policy.decide(authority) {
                    Decision::Permitted => {}
                    Decision::Denied => return Err(FollowError::Denied(authority.clone())),
                    Decision::Unknown => return Err(FollowError::PolicyUnknown),
                }
                None
            }
        };
        let stored = channel.stored();
        for _ in 0..CREATE_ATTEMPTS {
            if let Some(existing) = self.store.get(actor, &stored).await? {
                return Ok((to_wire(&existing, local.as_ref())?, false));
            }
            let slot = self.free_slot(actor).await?;
            match self.store.create(actor, &stored, slot, now).await? {
                Created::Written(row) => return Ok((to_wire(&row, local.as_ref())?, true)),
                // Another request created this follow, or took the slot:
                // read again.
                Created::Taken => {}
            }
        }
        Err(FollowError::Contended)
    }

    /// `DELETE /api/me/follows/{channelRef}`: stop following. Works
    /// whatever the channel's state and the federation policy, so a user
    /// can always clean up.
    pub async fn unfollow(&self, actor: &Actor, channel: &ChannelRef) -> Result<(), FollowError> {
        Ok(self.store.delete(actor, &channel.stored()).await?)
    }

    /// A slot `actor` holds no follow in, picked at random among the free
    /// ones so that concurrent creates seldom pick the same one. With every
    /// slot taken, first prune their local follows of channels that are
    /// gone or that they can no longer read: the list does not show those,
    /// so they could not remove them themselves (§7.6 allows pruning a
    /// stale pointer). With none to prune, the limit is reached (`409`).
    async fn free_slot(&self, actor: &Actor) -> Result<usize, FollowError> {
        let mut rows = self.store.list(actor, MAX_FOLLOWS_PER_ACTOR + 1).await?;
        if store::free_slots(&rows, MAX_FOLLOWS_PER_ACTOR).is_empty() {
            self.prune_stale(actor, &rows).await?;
            rows = self.store.list(actor, MAX_FOLLOWS_PER_ACTOR + 1).await?;
        }
        let free = store::free_slots(&rows, MAX_FOLLOWS_PER_ACTOR);
        if free.is_empty() {
            // Another request took the slots pruning freed.
            return Err(FollowError::Limit);
        }
        let mut pick = [0u8; 8];
        getrandom::fill(&mut pick).map_err(|e| DbError::Query(format!("random source: {e}")))?;
        // Below `free.len()`, so the cast cannot truncate.
        let at = (u64::from_le_bytes(pick) % free.len() as u64) as usize;
        free.get(at).copied().ok_or(FollowError::Limit)
    }

    /// Remove `actor`'s local follows (among `rows`) of channels that are
    /// gone or that they can no longer read; `409` if there are none.
    async fn prune_stale(&self, actor: &Actor, rows: &[StoredFollow]) -> Result<(), FollowError> {
        let local: Vec<String> = rows
            .iter()
            .filter(|f| is_local(&f.channel))
            .map(|f| f.channel.clone())
            .collect();
        let readable = self.groups.readable_among(actor, &local).await?;
        let mut pruned = 0;
        for id in local
            .iter()
            .filter(|id| !readable.channels.contains_key(*id))
        {
            self.store.delete(actor, id).await?;
            pruned += 1;
        }
        if pruned == 0 {
            return Err(FollowError::Limit);
        }
        Ok(())
    }
}

/// Whether a stored channel is a local id (a remote one is a URI).
fn is_local(channel: &str) -> bool {
    !channel.starts_with("https://")
}

/// The wire form of `row` (§7.6 `groupId`): a local follow carries its
/// channel's group id (`channel`, which the caller looked up), a remote one
/// its group's object URI on the channel's authority, which the channel
/// URI names.
fn to_wire(row: &StoredFollow, channel: Option<&StoredChannel>) -> Result<Follow, FollowError> {
    let bad = |what: &str| DbError::Decode(format!("follow of {}: bad {what}", row.channel));
    let group = match channel {
        Some(c) => c.group_id.as_str(),
        None => request::group_uri_of(&row.channel).ok_or_else(|| bad("channel URI"))?,
    };
    let group_id = Some(ObjectRef::parse(group).map_err(|_| bad("group"))?);
    Ok(Follow {
        channel: ObjectRef::parse(&row.channel).map_err(|_| bad("channel"))?,
        group_id,
        created_at: timefmt::parse_timestamp(&row.created_at).ok_or_else(|| bad("created_at"))?,
        metadata: Vec::new(),
    })
}
