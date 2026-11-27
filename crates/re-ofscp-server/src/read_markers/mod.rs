//! Read markers and unread counts (spec §7.7; docs/decisions/0021): for
//! each local user, the newest message they have read in each channel
//! they can read in the groups they belong to.
//!
//! - [`request`]: reading the `PATCH` body (`400`s).
//! - [`store`]: the `ReadMarker` rows.
//! - [`unread`]: counting what is newer than a marker.
//! - [`routes`]: `GET`/`PATCH /api/me/read-markers`.
//!
//! A scope the user cannot read now is an unknown scope (§7.7, security
//! requirement 5): never listed, never stored, never reported, and a
//! marker for one is ignored with `200`, so nothing tells an outsider that
//! a channel or a message exists. Direct-message scopes join this when
//! direct messages (§7.4) are implemented.

pub mod request;
pub mod routes;
pub mod store;
pub mod unread;

use std::collections::BTreeMap;
use std::sync::Arc;

use futures_util::stream::{self, StreamExt, TryStreamExt};
use ofscp_core::LocalId;
use ofscp_core::wire::ReadMarker;
use re_ofscp_types::Actor;
use serde::Serialize;

use crate::db::DbError;
use crate::groups::Groups;
use crate::groups::listing::ListingError;
use crate::groups::model::StoredChannel;
use crate::messages::Messages;
use crate::messages::log;
use crate::ws::Hub;
use request::MarkerUpdate;
use store::{Advanced, MarkerStore, StoredMarker};

/// The `read.updated` event type (§7.7).
pub const READ_UPDATED: &str = "read.updated";
/// Unread counts computed at once for one listing.
const COUNT_CONCURRENCY: usize = 8;

/// One scope's entry in a response or a `read.updated` event: a
/// `ReadMarker` (`read-markers-response.json`), plus the extension field
/// `unreadCountCapped` (§2.3) when `unreadCount` is a lower bound.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Scope {
    /// The marker.
    #[serde(flatten)]
    pub marker: ReadMarker,
    /// Whether there may be more unread messages than `unreadCount`.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub unread_count_capped: bool,
}

/// `GET`/`PATCH /api/me/read-markers` responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScopesResponse {
    /// One entry per scope.
    pub scopes: Vec<Scope>,
}

/// `read.updated` data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ReadUpdated<'a> {
    markers: &'a [Scope],
}

/// Why a read-marker operation failed.
#[derive(Debug, thiserror::Error)]
pub enum MarkerError {
    /// The user's groups could not be listed in full (`500`).
    #[error(transparent)]
    Listing(#[from] ListingError),
    /// The database failed (`500`).
    #[error(transparent)]
    Db(#[from] DbError),
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
    /// timelines, announcing changes through `hub`.
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
    /// read now in the groups they belong to.
    pub async fn scopes(&self, actor: &Actor) -> Result<Vec<Scope>, MarkerError> {
        let channels = self.groups.readable_member_channels(actor).await?;
        let ids: Vec<String> = channels.iter().map(|c| c.id.clone()).collect();
        let markers = self.store.for_scopes(actor, &ids).await?;
        let lasts = log::last_positions(self.messages.store().db(), &ids).await?;
        // Collected first: a lazily mapped iterator here makes the handler's
        // future fail axum's `Send` bound (a higher-ranked lifetime).
        let entries: Vec<_> = channels
            .iter()
            .map(|c| {
                let last = lasts.get(&c.id).copied().unwrap_or(0);
                self.entry(actor, c, markers.get(&c.id), last)
            })
            .collect();
        stream::iter(entries)
            .buffered(COUNT_CONCURRENCY)
            .try_collect()
            .await
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
    ) -> Result<Vec<Scope>, MarkerError> {
        // The usable channel of each scope named, looked up once.
        let mut usable: BTreeMap<&str, Option<StoredChannel>> = BTreeMap::new();
        let mut moved: Vec<String> = Vec::new();
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
            let Some(message) = self
                .messages
                .store()
                .message(&channel.id, u.last_read_message_id.as_str())
                .await?
            else {
                continue;
            };
            let advanced = self
                .store
                .advance(actor, &channel.id, message.id.as_str(), message.seq, now)
                .await?;
            if matches!(advanced, Advanced::Moved(_)) && !moved.contains(&channel.id) {
                moved.push(channel.id.clone());
            }
        }
        let mut scopes = Vec::with_capacity(moved.len());
        for id in &moved {
            let Some(Some(channel)) = usable.get(id.as_str()) else {
                continue;
            };
            let marker = self.store.get(actor, id).await?;
            let last = log::read(self.messages.store().db(), id).await?.last();
            scopes.push(self.entry(actor, channel, marker.as_ref(), last).await?);
        }
        if !scopes.is_empty() {
            match serde_json::to_value(ReadUpdated { markers: &scopes }) {
                Ok(data) => self.hub.send_to_actor(actor, READ_UPDATED, data),
                Err(e) => tracing::error!(error = %e, "serializing read.updated failed"),
            }
        }
        Ok(scopes)
    }

    /// The entry for `channel`, whose timeline has handed out positions up
    /// to `last`, given `actor`'s marker there.
    async fn entry(
        &self,
        actor: &Actor,
        channel: &StoredChannel,
        marker: Option<&StoredMarker>,
        last: i64,
    ) -> Result<Scope, MarkerError> {
        let bad = |what: &str| DbError::Decode(format!("read marker {}: bad {what}", channel.id));
        let after = marker.map_or(0, |m| m.seq);
        let unread = unread::count(self.messages.store(), &channel.id, after, last, actor).await?;
        let last_read_message_id = match marker {
            Some(m) => Some(LocalId::new(&m.message_id).map_err(|_| bad("message id"))?),
            None => None,
        };
        Ok(Scope {
            marker: ReadMarker {
                scope_id: LocalId::new(&channel.id).map_err(|_| bad("scope id"))?,
                last_read_message_id,
                unread_count: unread.count,
                group_id: Some(LocalId::new(&channel.group_id).map_err(|_| bad("group id"))?),
            },
            unread_count_capped: unread.capped,
        })
    }
}
