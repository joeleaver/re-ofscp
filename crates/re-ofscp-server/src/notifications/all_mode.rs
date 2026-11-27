//! `message` entries for the users whose mode is `all` (§10.1, §10.2;
//! docs/decisions/0023, *The background queue*).
//!
//! A create queues its message's id once its direct entries are made, and
//! only when the channel or its group has an `all` setting at all
//! ([`Notifications::queue_all_mode`]). The queue's turns
//! ([`super::background`]) then make the entries a batch of one channel's
//! messages at a time ([`Notifications::all_mode_entries`]):
//!
//! 1. the scope's `all` owners are read once for the batch, and checked
//!    once, as a direct candidate is (readable channel, active account,
//!    effective mode `all`);
//! 2. the messages are read again, in one batched lookup: a message deleted
//!    since it was queued, or gone with its channel, gets no entries;
//! 3. message by message, in creation order, the checked owners less its
//!    author, less those who already have an entry for it (a mention or
//!    reply made directly), get a `message` entry, and each is announced.

use ofscp_core::Actor;

use super::Notifications;
use super::background::{Batch, Job};
use super::create::{Candidates, MakeError};
use super::settings::scope;
use super::store::kind;
use crate::messages::model::StoredMessage;

impl Notifications {
    /// Queue `m` for its `message` entries, unless neither its channel nor
    /// its group has an `all` setting now. A setting stored after this
    /// check does not apply to `m` (it came after the message); if the
    /// check fails, `m` is queued anyway and its turn reads the settings.
    pub(super) async fn queue_all_mode(&self, m: &StoredMessage) {
        match self.any_all_mode(m).await {
            Ok(false) => return,
            Ok(true) => {}
            Err(e) => {
                tracing::warn!(error = %e, message = %m.id, "checking for `all` settings failed; queueing the message anyway");
            }
        }
        self.background
            .enqueue(Job {
                channel_id: m.channel_id.to_string(),
                group_id: m.group_id.to_string(),
                message_id: m.id.to_string(),
            })
            .await;
    }

    async fn any_all_mode(&self, m: &StoredMessage) -> Result<bool, MakeError> {
        Ok(self
            .settings
            .has_all_mode(scope::CHANNEL, m.channel_id.as_str())
            .await?
            || self
                .settings
                .has_all_mode(scope::GROUP, m.group_id.as_str())
                .await?)
    }

    /// One turn of the queue: make the `message` entries of `batch`'s
    /// messages. Failures are logged; a failure before the messages are
    /// handled loses the batch's entries, one while handling a message
    /// loses that message's.
    pub(super) async fn all_mode_entries(&self, batch: Batch) {
        if let Err(e) = self.try_all_mode_entries(&batch).await {
            tracing::error!(
                error = %e,
                channel = %batch.channel_id,
                messages = batch.message_ids.len(),
                "making `all` notification entries failed"
            );
        }
    }

    async fn try_all_mode_entries(&self, batch: &Batch) -> Result<(), MakeError> {
        let channel_id = batch.channel_id.as_str();
        let eligible = self.all_mode_readers(channel_id, &batch.group_id).await?;
        if eligible.is_empty() {
            return Ok(());
        }
        let mut messages = self.messages.by_ids(&batch.message_ids).await?;
        messages.retain(|m| !m.is_deleted() && m.channel_id.as_str() == channel_id);
        messages.sort_by_key(|m| m.seq);
        for m in &messages {
            if let Err(e) = self.message_entries(m, &eligible).await {
                tracing::error!(error = %e, message = %m.id, "making `all` notification entries failed");
            }
        }
        Ok(())
    }

    /// The local users whose effective mode for `channel_id` is `all` and
    /// who may get an entry about it now.
    async fn all_mode_readers(
        &self,
        channel_id: &str,
        group_id: &str,
    ) -> Result<Vec<Actor>, MakeError> {
        let mut owners = self
            .settings
            .all_mode_owners(scope::CHANNEL, channel_id)
            .await?;
        owners.extend(
            self.settings
                .all_mode_owners(scope::GROUP, group_id)
                .await?,
        );
        let mut want = Candidates::new();
        for owner in owners {
            if let Ok(a) = Actor::parse_canonical(&owner)
                && a.is_local_to(&self.home)
            {
                want.insert(a.handle().to_owned(), kind::MESSAGE);
            }
        }
        Ok(self
            .permitted(channel_id, group_id, &want)
            .await?
            .into_iter()
            .map(|(actor, _)| actor)
            .collect())
    }

    /// Give each of `eligible` but `m`'s author, and those who already
    /// have an entry for `m`, a `message` entry for it, and announce them.
    async fn message_entries(
        &self,
        m: &StoredMessage,
        eligible: &[Actor],
    ) -> Result<(), MakeError> {
        let mut want: Vec<Actor> = eligible
            .iter()
            .filter(|a| **a != m.author)
            .cloned()
            .collect();
        let owners: Vec<String> = want.iter().map(ToString::to_string).collect();
        let have = self.feed.owners_with_entry(m.id.as_str(), &owners).await?;
        want.retain(|a| !have.contains(&a.to_string()));
        let work = want.into_iter().map(|a| (a, kind::MESSAGE)).collect();
        let made = self.insert_all(m, work).await;
        self.announce(m.channel_id.as_str(), made).await
    }
}
