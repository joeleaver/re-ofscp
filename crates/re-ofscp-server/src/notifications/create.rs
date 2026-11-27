//! Making feed entries when a channel message is created (§10.1 *When
//! entries are created*), through the [`Notify`] seam.
//!
//! The candidates come in two sets, made separately:
//!
//! - **Direct:** the local users the message mentions (at most
//!   `MAX_MENTIONS`, `mentions.rs`) and the local author of the message it
//!   replies to. These are made in the future the create awaits.
//! - **`all`:** the users whose channel or group setting is `all`. Anyone
//!   may hold such a setting for any scope (§10.2), so once the direct
//!   entries are made the future only queues the message's id
//!   ([`super::background`]), and only if its channel or group has an `all`
//!   setting at all; the entries are made off the request path
//!   (`all_mode.rs`), and a direct candidate's entry, made first, outranks
//!   a `message` one.
//!
//! Each candidate gets at most one entry, of the highest-precedence type
//! that applies (mention, then reply, then message), and only if, at that
//! moment, they are not the author, they can read the channel (security
//! requirement 7), their account exists and is active, and their effective
//! mode for the channel is not `none` (and is `all` for a `message` entry).
//! The checks run in that order, each one batched over every candidate
//! still standing, so a candidate who fails the first costs a share of one
//! batched lookup and nothing more. Readability is checked again just
//! before each `notification.created` is sent.

use std::collections::BTreeMap;
use std::sync::{Arc, Weak};

use futures_util::stream::{self, StreamExt};
use ofscp_core::Actor;
use ofscp_core::ws::NotificationCreated;

use super::settings::mode;
use super::store::{NewEntry, StoredEntry, kind};
use super::{NOTIFICATION_CREATED, Notifications, mentions, to_wire};
use crate::accounts::store::StoreError;
use crate::db::DbError;
use crate::messages::model::StoredMessage;
use crate::messages::{Notify, NotifyFuture};

/// Entries written at once for one message.
const CONCURRENCY: usize = 16;

/// Why a set of entries was not made.
#[derive(Debug, thiserror::Error)]
pub(super) enum MakeError {
    #[error(transparent)]
    Db(#[from] DbError),
    #[error(transparent)]
    Accounts(#[from] StoreError),
}

/// Candidates by handle, with the type of entry each would get.
pub(super) type Candidates = BTreeMap<String, &'static str>;

impl Notify for Notifications {
    fn message_created(
        self: Arc<Self>,
        message: StoredMessage,
        parent_author: Option<Actor>,
    ) -> NotifyFuture {
        let direct = self.direct_candidates(&message, parent_author.as_ref());
        Box::pin(async move {
            if let Err(e) = self.make(&message, direct).await {
                tracing::error!(error = %e, message = %message.id, "making notification entries failed");
            }
            // After the direct entries, so none of them can lose to a
            // `message` entry for the same user.
            self.queue_all_mode(&message).await;
        })
    }
}

impl Notifications {
    /// The mentioned and replied-to local users of `m`, less its author.
    /// Reads nothing.
    fn direct_candidates(&self, m: &StoredMessage, parent_author: Option<&Actor>) -> Candidates {
        let mut want = Candidates::new();
        let text = m.doc.content.as_ref().map(|c| c.text.as_str());
        for handle in mentions::local_mentions(m.doc.mentions.as_deref(), text, &self.home) {
            want.insert(handle, kind::MENTION);
        }
        if let Some(p) = parent_author.filter(|p| p.is_local_to(&self.home)) {
            want.entry(p.handle().to_owned()).or_insert(kind::REPLY);
        }
        self.drop_author(m, &mut want);
        want
    }

    fn drop_author(&self, m: &StoredMessage, want: &mut Candidates) {
        if m.author.is_local_to(&self.home) {
            want.remove(m.author.handle());
        }
    }

    /// Make the entries `want` names for `m`, for the candidates every
    /// rule allows, and announce them.
    async fn make(&self, m: &StoredMessage, want: Candidates) -> Result<(), MakeError> {
        let channel_id = m.channel_id.as_str();
        let work = self
            .permitted(channel_id, m.group_id.as_str(), &want)
            .await?;
        let made = self.insert_all(m, work).await;
        self.announce(channel_id, made).await
    }

    /// Those of `want` that every rule allows the entry `want` names for a
    /// message of `channel_id` in `group_id`, checked now (all but the
    /// author rule, which is the caller's).
    pub(super) async fn permitted(
        &self,
        channel_id: &str,
        group_id: &str,
        want: &Candidates,
    ) -> Result<Vec<(Actor, &'static str)>, MakeError> {
        if want.is_empty() {
            return Ok(Vec::new());
        }
        let actors: Vec<Actor> = want
            .keys()
            .filter_map(|h| Actor::new(h, self.home.clone()).ok())
            .collect();
        // 1. Who can read the channel: one batched membership lookup, or
        //    none when anyone may read it.
        let readers = self.groups.readers_among(channel_id, &actors).await?;
        let handles: Vec<String> = readers.iter().map(|a| a.handle().to_owned()).collect();
        // 2. Whose account is active.
        let active = self.accounts.active_handles(&handles).await?;
        let owners: Vec<String> = readers
            .iter()
            .filter(|a| active.contains(a.handle()))
            .map(ToString::to_string)
            .collect();
        // 3. Whose effective mode allows the entry.
        let modes = self
            .settings
            .effective_modes(&owners, channel_id, group_id)
            .await?;
        Ok(readers
            .into_iter()
            .filter_map(|actor| {
                let k = *want.get(actor.handle())?;
                let mode = modes.get(&actor.to_string())?;
                let allowed = mode != mode::NONE && (k != kind::MESSAGE || mode == mode::ALL);
                allowed.then_some((actor, k))
            })
            .collect())
    }

    /// Write each of `work`'s entries for `m`, [`CONCURRENCY`] at a time:
    /// those made.
    pub(super) async fn insert_all(
        &self,
        m: &StoredMessage,
        work: Vec<(Actor, &'static str)>,
    ) -> Vec<(Actor, StoredEntry)> {
        let writes: Vec<_> = work
            .into_iter()
            .map(|(actor, k)| self.insert(m, actor, k))
            .collect();
        stream::iter(writes)
            .buffer_unordered(CONCURRENCY)
            .filter_map(|made| async move { made })
            .collect()
            .await
    }

    /// Write `actor`'s entry of `kind` for `m`: `None` if it was not made
    /// (one exists already, or the write failed, which is logged here so
    /// the other candidates' entries are still made).
    async fn insert(
        &self,
        m: &StoredMessage,
        actor: Actor,
        kind: &'static str,
    ) -> Option<(Actor, StoredEntry)> {
        let owner = actor.to_string();
        let author = m.author.to_string();
        let new = NewEntry {
            owner: &owner,
            kind,
            message_id: m.id.as_str(),
            channel_id: m.channel_id.as_str(),
            group_id: m.group_id.as_str(),
            author: &author,
            now: m.created_at.as_second(),
        };
        match self.feed.insert(&new).await {
            Ok(stored) => stored.map(|s| (actor, s)),
            Err(e) => {
                tracing::error!(error = %e, user = %owner, message = %m.id, "making a notification entry failed");
                None
            }
        }
    }

    /// Send `notification.created` for each entry `made`, to owners who
    /// can still read the channel. Readability is read again here, after
    /// the writes, so access lost while the entries were written sends
    /// nothing; the event carries no counts. An entry left unsent this way
    /// stays stored, unlisted while the channel is unreadable (`visible`).
    pub(super) async fn announce(
        &self,
        channel_id: &str,
        made: Vec<(Actor, StoredEntry)>,
    ) -> Result<(), MakeError> {
        let Some(hub) = self.hub.get().and_then(Weak::upgrade) else {
            return Ok(());
        };
        if made.is_empty() {
            return Ok(());
        }
        let owners: Vec<Actor> = made.iter().map(|(a, _)| a.clone()).collect();
        let still = self.groups.readers_among(channel_id, &owners).await?;
        // Nothing is awaited from the read above to the last send.
        for (actor, stored) in made {
            if !still.contains(&actor) {
                continue;
            }
            let notification = match to_wire(&stored) {
                Ok(n) => n,
                Err(e) => {
                    tracing::error!(error = %e, "a stored notification has no wire form");
                    continue;
                }
            };
            match serde_json::to_value(NotificationCreated { notification }) {
                Ok(data) => hub.send_to_actor(&actor, NOTIFICATION_CREATED, data),
                Err(e) => tracing::error!(error = %e, "serializing notification.created failed"),
            }
        }
        Ok(())
    }
}
