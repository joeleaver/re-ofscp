//! Read markers and unread counts (spec §7.7; docs/decisions/0022): for
//! each local user, the newest message they have read in each channel
//! they can read in the groups they belong to, and the exact number of
//! messages after it that they did not write (lost-conn/ofscp#41).
//!
//! - [`request`]: reading the `PATCH` body (`400`s).
//! - [`store`]: the `ReadMarker` rows.
//! - [`unread`]: the unread count from a marker and the channel's counts
//!   (`messages::ordinals`).
//! - [`routes`]: `GET`/`PATCH /api/me/read-markers`.
//!
//! A scope the user cannot read now is an unknown scope (§7.7, security
//! requirement 5): never listed, never stored, never reported, and a
//! marker for one is ignored with `200`, so nothing tells an outsider that
//! a channel or a message exists. A channel being deleted (its log closed,
//! its row perhaps not yet removed) is no longer readable either: it is
//! left out of every answer and of `read.updated`. Direct-message scopes join this when
//! direct messages (§7.4) are implemented.

pub mod request;
pub mod routes;
pub mod store;
pub mod unread;

use std::collections::BTreeMap;
use std::sync::Arc;

use ofscp_core::LocalId;
use ofscp_core::wire::ReadMarker;
use ofscp_core::ws::ReadUpdated;
use re_ofscp_types::Actor;

use crate::db::DbError;
use crate::groups::Groups;
use crate::groups::listing::ListingError;
use crate::groups::model::StoredChannel;
use crate::messages::Messages;
use crate::messages::ordinals::{ChannelTotals, CountError, Totals};
use crate::ws::Hub;
use request::MarkerUpdate;
use store::{Advanced, MarkerStore, StoredMarker};

/// The `read.updated` event type (§7.7).
pub const READ_UPDATED: &str = "read.updated";

/// Why a read-marker operation failed.
#[derive(Debug, thiserror::Error)]
pub enum MarkerError {
    /// The user's groups could not be listed in full (`500`).
    #[error(transparent)]
    Listing(#[from] ListingError),
    /// The database failed (`500`; `503` for a transient conflict).
    #[error(transparent)]
    Db(#[from] DbError),
    /// A channel predates message ordinals and is being numbered (`503`
    /// with `Retry-After`, `messages/numbering.rs`).
    #[error("channel {0} is being numbered")]
    Numbering(String),
}

impl From<CountError> for MarkerError {
    fn from(e: CountError) -> Self {
        match e {
            CountError::Db(e) => Self::Db(e),
            CountError::Numbering(c) => Self::Numbering(c),
        }
    }
}

/// Read markers.
pub struct ReadMarkers {
    store: MarkerStore,
    groups: Arc<Groups>,
    messages: Arc<Messages>,
    hub: Arc<Hub>,
}

impl std::fmt::Debug for ReadMarkers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadMarkers").finish_non_exhaustive()
    }
}

impl ReadMarkers {
    /// Markers kept in `store`, over `groups`' channels and `messages`'
    /// counts, announcing changes through `hub`.
    pub fn new(
        store: MarkerStore,
        groups: Arc<Groups>,
        messages: Arc<Messages>,
        hub: Arc<Hub>,
    ) -> Self {
        Self {
            store,
            groups,
            messages,
            hub,
        }
    }

    /// `GET /api/me/read-markers`: an entry for every channel `actor` can
    /// read now in the groups they belong to. Bounded whatever the
    /// channels hold: batched lookups of the markers, logs and tallies.
    pub async fn scopes(&self, actor: &Actor) -> Result<Vec<ReadMarker>, MarkerError> {
        let channels = self.groups.readable_member_channels(actor).await?;
        let ids: Vec<String> = channels.iter().map(|c| c.id.clone()).collect();
        self.entries(actor, &channels, &ids).await
    }

    /// `PATCH /api/me/read-markers` at `now` (unix seconds): move each
    /// marker forward, ignoring any for an unknown or unreadable scope, a
    /// message the scope does not hold, or one behind the stored marker.
    /// Returns the scopes that advanced, and tells `actor`'s connections.
    pub async fn update(
        &self,
        actor: &Actor,
        updates: &[MarkerUpdate],
        now: i64,
    ) -> Result<Vec<ReadMarker>, MarkerError> {
        let reader = actor.to_string();
        // The usable channel of each scope named, looked up once.
        let mut usable: BTreeMap<&str, Option<StoredChannel>> = BTreeMap::new();
        let mut moved: Vec<StoredChannel> = Vec::new();
        for u in updates {
            if !usable.contains_key(u.scope_id.as_str()) {
                let channel = match LocalId::new(&u.scope_id) {
                    Ok(_) => {
                        self.groups
                            .readable_member_channel(actor, &u.scope_id)
                            .await?
                    }
                    Err(_) => None,
                };
                usable.insert(u.scope_id.as_str(), channel);
            }
            let Some(Some(channel)) = usable.get(u.scope_id.as_str()) else {
                continue;
            };
            let Some(at) = self
                .messages
                .mark_point(&channel.id, u.last_read_message_id.as_str(), &reader)
                .await?
            else {
                continue;
            };
            let advanced = self.store.advance(actor, &channel.id, &at, now).await?;
            if matches!(advanced, Advanced::Moved(_)) && !moved.iter().any(|c| c.id == channel.id) {
                moved.push(channel.clone());
            }
        }
        let ids: Vec<String> = moved.iter().map(|c| c.id.clone()).collect();
        let scopes = self.entries(actor, &moved, &ids).await?;
        if !scopes.is_empty() {
            let event = ReadUpdated {
                markers: scopes.clone(),
            };
            match serde_json::to_value(event) {
                Ok(data) => self.hub.send_to_actor(actor, READ_UPDATED, data),
                Err(e) => tracing::error!(error = %e, "serializing read.updated failed"),
            }
        }
        Ok(scopes)
    }

    /// The entries for `channels` (whose ids are `ids`), in that order, with
    /// `actor`'s markers and exact unread counts. A channel being deleted
    /// is left out: its log is closed, or gone while the reader still holds
    /// a marker there (only a written channel has markers, and only a
    /// deleted one loses its log).
    async fn entries(
        &self,
        actor: &Actor,
        channels: &[StoredChannel],
        ids: &[String],
    ) -> Result<Vec<ReadMarker>, MarkerError> {
        if channels.is_empty() {
            return Ok(Vec::new());
        }
        let markers = self.store.for_scopes(actor, ids).await?;
        let totals = self.messages.totals(ids, &actor.to_string()).await?;
        let mut out = Vec::with_capacity(channels.len());
        for c in channels {
            let marker = markers.get(&c.id);
            let t = match totals.get(&c.id).copied().unwrap_or(ChannelTotals::NoLog) {
                ChannelTotals::Counted(t) => t,
                ChannelTotals::NoLog if marker.is_none() => Totals::default(),
                ChannelTotals::NoLog | ChannelTotals::Closed => continue,
            };
            out.push(entry(c, marker, t)?);
        }
        Ok(out)
    }
}

/// The entry for `channel`, given the reader's marker and totals there.
fn entry(
    channel: &StoredChannel,
    marker: Option<&StoredMarker>,
    totals: Totals,
) -> Result<ReadMarker, MarkerError> {
    let bad = |what: &str| DbError::Decode(format!("read marker {}: bad {what}", channel.id));
    let last_read_message_id = match marker {
        Some(m) => Some(LocalId::new(&m.message_id).map_err(|_| bad("message id"))?),
        None => None,
    };
    Ok(ReadMarker {
        scope_id: LocalId::new(&channel.id).map_err(|_| bad("scope id"))?,
        last_read_message_id,
        unread_count: unread::count(&channel.id, totals, marker)?,
        group_id: Some(LocalId::new(&channel.group_id).map_err(|_| bad("group id"))?),
    })
}
