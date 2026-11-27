//! Making feed entries when a channel message is created (§10.1 *When
//! entries are created*), through the [`Notify`] seam.
//!
//! The candidates are the local users the message mentions, the local
//! author of the message it replies to, and the users whose mode for the
//! channel is `all`. Each gets at most one entry, of the highest-precedence
//! type that applies (mention, then reply, then message), and only if, at
//! that moment, they are not the author, their account exists and is
//! active, their effective mode for the channel is not `none` (and is `all`
//! for a `message` entry), and they can read the channel (security
//! requirement 7).

use std::collections::BTreeMap;
use std::sync::{Arc, Weak};

use futures_util::stream::{self, StreamExt};
use ofscp_core::Actor;
use ofscp_core::ws::NotificationCreated;

use super::settings::{mode, scope};
use super::store::{NewEntry, kind};
use super::{NOTIFICATION_CREATED, Notifications, mentions, to_wire};
use crate::accounts::store::StoreError;
use crate::db::DbError;
use crate::messages::model::StoredMessage;
use crate::messages::{Notify, NotifyFuture};

/// Candidates handled at once.
const CONCURRENCY: usize = 16;

/// Why one candidate's entry was not made.
#[derive(Debug, thiserror::Error)]
enum CandidateError {
    #[error(transparent)]
    Db(#[from] DbError),
    #[error(transparent)]
    Accounts(#[from] StoreError),
}

impl Notify for Notifications {
    fn message_created(
        self: Arc<Self>,
        message: StoredMessage,
        parent_author: Option<Actor>,
    ) -> NotifyFuture {
        Box::pin(async move {
            if let Err(e) = self.make_entries(&message, parent_author.as_ref()).await {
                tracing::error!(error = %e, message = %message.id, "making notification entries failed");
            }
        })
    }
}

impl Notifications {
    /// Make the entries for new message `m`.
    async fn make_entries(
        &self,
        m: &StoredMessage,
        parent_author: Option<&Actor>,
    ) -> Result<(), DbError> {
        let candidates = self.candidates(m, parent_author).await?;
        // Collected first: a lazily mapped iterator here makes the future
        // fail the `Send` bound of a spawned task (a higher-ranked
        // lifetime), as in `read_markers`.
        let work: Vec<_> = candidates
            .into_iter()
            .map(|(handle, kind)| self.logged_entry_for(m, handle, kind))
            .collect();
        stream::iter(work)
            .buffer_unordered(CONCURRENCY)
            .collect::<Vec<()>>()
            .await;
        Ok(())
    }

    /// [`Self::entry_for`], logging a failure: one candidate's failure
    /// leaves the others' entries to be made.
    async fn logged_entry_for(&self, m: &StoredMessage, handle: String, kind: &'static str) {
        if let Err(e) = self.entry_for(m, &handle, kind).await {
            tracing::error!(error = %e, user = %handle, message = %m.id, "making a notification entry failed");
        }
    }

    /// Each candidate's handle, with the type of entry they would get.
    async fn candidates(
        &self,
        m: &StoredMessage,
        parent_author: Option<&Actor>,
    ) -> Result<BTreeMap<String, &'static str>, DbError> {
        let mut want: BTreeMap<String, &'static str> = BTreeMap::new();
        let text = m.doc.content.as_ref().map(|c| c.text.as_str());
        for handle in mentions::local_mentions(m.doc.mentions.as_deref(), text, &self.home) {
            want.insert(handle, kind::MENTION);
        }
        if let Some(p) = parent_author.filter(|p| p.is_local_to(&self.home)) {
            want.entry(p.handle().to_owned()).or_insert(kind::REPLY);
        }
        let mut all = self
            .settings
            .all_mode_owners(scope::CHANNEL, m.channel_id.as_str())
            .await?;
        all.extend(
            self.settings
                .all_mode_owners(scope::GROUP, m.group_id.as_str())
                .await?,
        );
        for owner in all {
            if let Ok(a) = Actor::parse_canonical(&owner)
                && a.is_local_to(&self.home)
            {
                want.entry(a.handle().to_owned()).or_insert(kind::MESSAGE);
            }
        }
        if m.author.is_local_to(&self.home) {
            want.remove(m.author.handle());
        }
        Ok(want)
    }

    /// The effective mode of `owner` for channel `channel_id` of
    /// `group_id` (§10.2): the channel's setting, else the group's, else
    /// `mentions`.
    async fn effective_mode(
        &self,
        owner: &str,
        channel_id: &str,
        group_id: &str,
    ) -> Result<String, DbError> {
        // A setting being cleared reads as an empty mode: no setting.
        let set = |m: Option<String>| m.filter(|m| !m.is_empty());
        if let Some(m) = set(self
            .settings
            .mode(owner, scope::CHANNEL, channel_id)
            .await?)
        {
            return Ok(m);
        }
        if let Some(m) = set(self.settings.mode(owner, scope::GROUP, group_id).await?) {
            return Ok(m);
        }
        Ok(mode::MENTIONS.to_owned())
    }

    /// Make `handle`'s entry of `kind` for `m`, if every rule allows it,
    /// and announce it.
    async fn entry_for(
        &self,
        m: &StoredMessage,
        handle: &str,
        kind: &'static str,
    ) -> Result<(), CandidateError> {
        let Ok(actor) = Actor::new(handle, self.home.clone()) else {
            return Ok(());
        };
        let owner = actor.to_string();
        let mode = self
            .effective_mode(&owner, m.channel_id.as_str(), m.group_id.as_str())
            .await?;
        if mode == mode::NONE || (kind == kind::MESSAGE && mode != mode::ALL) {
            return Ok(());
        }
        if !self
            .accounts
            .find_user(handle)
            .await?
            .is_some_and(|u| u.is_active())
        {
            return Ok(());
        }
        if self
            .groups
            .readable_channel(&actor, m.channel_id.as_str())
            .await?
            .is_none()
        {
            return Ok(());
        }
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
        let Some(stored) = self.feed.insert(&new).await? else {
            return Ok(());
        };
        let Some(hub) = self.hub.get().and_then(Weak::upgrade) else {
            return Ok(());
        };
        let event = NotificationCreated {
            notification: to_wire(&stored)?,
        };
        match serde_json::to_value(event) {
            Ok(data) => hub.send_to_actor(&actor, NOTIFICATION_CREATED, data),
            Err(e) => tracing::error!(error = %e, "serializing notification.created failed"),
        }
        Ok(())
    }
}
