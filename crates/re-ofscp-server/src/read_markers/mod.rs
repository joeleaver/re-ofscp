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
use crate::messages::numbering::InlineBudget;
use crate::messages::ordinals::{ChannelTotals, CountError, MarkPoint, Totals};
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
    ///
    /// §7.7 requires an entry, with an exact `unreadCount`, for every
    /// readable channel, so a channel still being numbered is not left out
    /// (that would read as a channel the user cannot read) and gets no
    /// guessed count: the whole answer is `503` with `Retry-After` until it
    /// is numbered. The background task numbers handed-over channels
    /// between the channels of its startup pass, so that wait is for the
    /// channels handed over before it, never the whole pass
    /// (`messages/numbering.rs`).
    pub async fn scopes(&self, actor: &Actor) -> Result<Vec<ReadMarker>, MarkerError> {
        let channels = self.groups.readable_member_channels(actor).await?;
        let ids: Vec<String> = channels.iter().map(|c| c.id.clone()).collect();
        self.entries(actor, &channels, &ids, &InlineBudget::new())
            .await
    }

    /// `PATCH /api/me/read-markers` at `now` (unix seconds): move each
    /// marker forward, ignoring any for an unknown or unreadable scope, a
    /// message the scope does not hold, or one behind the stored marker.
    /// Returns the scopes that advanced, and tells `actor`'s connections.
    ///
    /// It applies the whole batch or none of it. Every marker's point in
    /// its scope is found first ([`ReadMarkers::resolve`]), numbering
    /// channels from before ordinals within one request budget, and only
    /// then does any marker move. So a scope still being numbered answers
    /// `503` with nothing stored, and the retry moves, reports and
    /// announces every scope together. Skipping that scope instead would
    /// drop a marker the user set and §7.7 gives no way to tell them.
    ///
    /// Every marker stored is announced (`read.updated`), whatever fails
    /// after it moved, since a retry finds it not moved and would announce
    /// nothing. The scopes' totals are read before any marker moves
    /// ([`ReadMarkers::announced`]), so the entries for what moved can be
    /// built even if reading them again afterwards fails. A database
    /// failure while storing (`500`/`503`) after some markers moved is
    /// returned once those are announced.
    pub async fn update(
        &self,
        actor: &Actor,
        updates: &[MarkerUpdate],
        now: i64,
    ) -> Result<Vec<ReadMarker>, MarkerError> {
        // One budget for the request: `resolve` numbers what it needs, so
        // the entries below find every moved scope numbered.
        let budget = InlineBudget::new();
        let points = self.resolve(actor, updates, &budget).await?;
        let mut named: Vec<String> = points.iter().map(|(c, _)| c.id.clone()).collect();
        named.sort_unstable();
        named.dedup();
        // Read before anything moves, so a failure here stores nothing.
        let before = self
            .messages
            .totals(&named, &actor.to_string(), &budget)
            .await?;
        // Each scope that moved, with its marker as this request left it.
        let mut moved: Vec<(StoredChannel, StoredMarker)> = Vec::new();
        let mut failed = None;
        for (channel, at) in &points {
            match self.store.advance(actor, &channel.id, at, now).await {
                Ok(Advanced::Moved(marker)) => {
                    match moved.iter_mut().find(|(c, _)| c.id == channel.id) {
                        Some((_, m)) => *m = marker,
                        None => moved.push((channel.clone(), marker)),
                    }
                }
                Ok(Advanced::Behind) => {}
                Err(e) => {
                    failed = Some(e);
                    break;
                }
            }
        }
        let scopes = self.announced(actor, &moved, &before, &budget).await;
        if !scopes.is_empty() {
            let event = ReadUpdated {
                markers: scopes.clone(),
            };
            match serde_json::to_value(event) {
                Ok(data) => self.hub.send_to_actor(actor, READ_UPDATED, data),
                Err(e) => tracing::error!(error = %e, "serializing read.updated failed"),
            }
        }
        match failed {
            Some(e) => Err(e.into()),
            None => Ok(scopes),
        }
    }

    /// The entries for the scopes that `moved`, read afresh. Should that
    /// read fail, they are built from the markers as moved and the totals
    /// read `before` any moved, exact as of that read (every marker's
    /// message was stored by then); a message posted since is announced to
    /// the user's connections with its own event. Never fails, so what
    /// moved is always announced.
    async fn announced(
        &self,
        actor: &Actor,
        moved: &[(StoredChannel, StoredMarker)],
        before: &BTreeMap<String, ChannelTotals>,
        budget: &InlineBudget,
    ) -> Vec<ReadMarker> {
        let channels: Vec<StoredChannel> = moved.iter().map(|(c, _)| c.clone()).collect();
        let ids: Vec<String> = channels.iter().map(|c| c.id.clone()).collect();
        let e = match self.entries(actor, &channels, &ids, budget).await {
            Ok(scopes) => return scopes,
            Err(e) => e,
        };
        tracing::warn!(error = %e, "re-reading moved read markers failed; announcing them as read before");
        entries_as_read(moved, before)
    }

    /// Where each of `updates` would put its marker, in order, leaving out
    /// any for an unknown or unreadable scope or a message the scope does
    /// not hold. Stores nothing. Every scope is resolved even after one is
    /// found still being numbered, so the request hands over every such
    /// channel at once; then it answers [`MarkerError::Numbering`].
    async fn resolve(
        &self,
        actor: &Actor,
        updates: &[MarkerUpdate],
        budget: &InlineBudget,
    ) -> Result<Vec<(StoredChannel, MarkPoint)>, MarkerError> {
        let reader = actor.to_string();
        // The usable channel of each scope named, looked up once.
        let mut usable: BTreeMap<&str, Option<StoredChannel>> = BTreeMap::new();
        let mut points = Vec::new();
        let mut numbering = None;
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
            let point = self
                .messages
                .mark_point(
                    &channel.id,
                    u.last_read_message_id.as_str(),
                    &reader,
                    budget,
                )
                .await;
            match point {
                Ok(Some(at)) => points.push((channel.clone(), at)),
                Ok(None) => {}
                Err(CountError::Db(e)) => return Err(e.into()),
                Err(e @ CountError::Numbering(_)) => numbering = numbering.or(Some(e)),
            }
        }
        match numbering {
            Some(e) => Err(e.into()),
            None => Ok(points),
        }
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
        budget: &InlineBudget,
    ) -> Result<Vec<ReadMarker>, MarkerError> {
        if channels.is_empty() {
            return Ok(Vec::new());
        }
        let markers = self.store.for_scopes(actor, ids).await?;
        let totals = self
            .messages
            .totals(ids, &actor.to_string(), budget)
            .await?;
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

/// The entries for the scopes that `moved`, from their markers as moved
/// and the totals read `before` any moved. A scope whose log was closed
/// or gone by then is left out (deleted, as in `entries`); one whose entry
/// cannot be built is logged and left out.
fn entries_as_read(
    moved: &[(StoredChannel, StoredMarker)],
    before: &BTreeMap<String, ChannelTotals>,
) -> Vec<ReadMarker> {
    let mut out = Vec::with_capacity(moved.len());
    for (channel, marker) in moved {
        let Some(ChannelTotals::Counted(t)) = before.get(&channel.id).copied() else {
            continue;
        };
        match entry(channel, Some(marker), t) {
            Ok(e) => out.push(e),
            Err(e) => {
                tracing::error!(error = %e, channel = %channel.id, "building a moved read marker failed");
            }
        }
    }
    out
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::model::ChannelDoc;
    use re_ofscp_types::groups::{ChannelType, Tier};

    fn channel(id: &str) -> StoredChannel {
        StoredChannel {
            id: id.into(),
            group_id: "grp_g".into(),
            kind: ChannelType::Text,
            tier: Tier::Public,
            revision: 0,
            doc: ChannelDoc::default(),
            created_at: String::new(),
            updated_at: String::new(),
        }
    }

    fn marker(scope: &str, message: &str, n: i64, own: i64) -> StoredMarker {
        StoredMarker {
            scope_id: scope.into(),
            message_id: message.into(),
            n,
            own,
        }
    }

    #[test]
    fn moved_scopes_are_built_from_the_totals_read_before() {
        let moved = [
            (channel("chn_a"), marker("chn_a", "msg_a", 3, 1)),
            (channel("chn_closed"), marker("chn_closed", "msg_c", 1, 0)),
            (channel("chn_gone"), marker("chn_gone", "msg_g", 1, 0)),
        ];
        let before = BTreeMap::from([
            (
                "chn_a".to_owned(),
                ChannelTotals::Counted(Totals {
                    messages: 10,
                    own: 4,
                }),
            ),
            ("chn_closed".to_owned(), ChannelTotals::Closed),
        ]);
        // 7 after the marker, 3 of them the reader's own; the deleted
        // channels are left out.
        let got = entries_as_read(&moved, &before);
        let want = ReadMarker {
            scope_id: LocalId::new("chn_a").unwrap(),
            last_read_message_id: Some(LocalId::new("msg_a").unwrap()),
            unread_count: 4,
            group_id: Some(LocalId::new("grp_g").unwrap()),
        };
        assert_eq!(got, [want]);
    }

    #[test]
    fn a_scope_whose_entry_cannot_be_built_is_left_out() {
        // A marker past the count is a contradiction, never a guess.
        let moved = [
            (channel("chn_a"), marker("chn_a", "msg_a", 5, 0)),
            (channel("chn_b"), marker("chn_b", "msg_b", 1, 0)),
        ];
        let counted = |messages| ChannelTotals::Counted(Totals { messages, own: 0 });
        let before = BTreeMap::from([
            ("chn_a".to_owned(), counted(2)),
            ("chn_b".to_owned(), counted(2)),
        ]);
        let got = entries_as_read(&moved, &before);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].scope_id.as_str(), "chn_b");
        assert_eq!(got[0].unread_count, 1);
    }
}
