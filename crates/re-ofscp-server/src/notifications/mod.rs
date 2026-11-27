//! The notification feed, mentions and notification settings (spec §10.1,
//! §10.2; docs/decisions/0023).
//!
//! - [`mentions`]: who a message mentions.
//! - [`create`]: making entries when a channel message is created (the
//!   [`crate::messages::Notify`] seam).
//! - [`store`]: the `Notification` rows and each user's feed positions.
//! - [`settings`]: the `NotificationSetting` rows.
//! - [`request`]: reading queries and bodies (`400`s).
//! - [`routes`]: `/api/me/notifications…` and
//!   `/api/me/notification-settings`.
//!
//! An entry about a channel the user cannot read now is no entry (security
//! requirements 5 and 7): never made, never listed, never counted and never
//! marked, so nothing tells the user more than the channel would.

pub mod create;
pub mod mentions;
pub mod request;
pub mod routes;
pub mod settings;
pub mod store;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock, Weak};

use ofscp_core::wire::{
    Notification, NotificationCounts, NotificationKind, NotificationSetting, NotificationsResponse,
};
use ofscp_core::{Actor, Authority, LocalId};

use crate::accounts::store::AccountStore;
use crate::db::{Db, DbError};
use crate::groups::Groups;
use crate::timefmt;
use crate::ws::Hub;
use request::{ListQuery, Scope};
use settings::{PutError, SettingStore};
use store::{FeedStore, Mark, StoredEntry, kind};

/// The `notification.created` event type (§10.1).
pub const NOTIFICATION_CREATED: &str = "notification.created";

/// Why a notification operation failed.
#[derive(Debug, thiserror::Error)]
pub enum NotificationError {
    /// The user holds as many settings as they may (`400`).
    #[error(transparent)]
    TooMany(PutError),
    /// The database failed (`500`).
    #[error(transparent)]
    Db(#[from] DbError),
}

impl From<PutError> for NotificationError {
    fn from(e: PutError) -> Self {
        match e {
            PutError::Db(e) => Self::Db(e),
            e @ PutError::TooMany => Self::TooMany(e),
        }
    }
}

/// The feed and its settings.
pub struct Notifications {
    feed: FeedStore,
    settings: SettingStore,
    groups: Arc<Groups>,
    accounts: AccountStore,
    home: Authority,
    /// Where `notification.created` goes; attached once the hub is built
    /// (the hub owns the messages that own this, so it is held weakly).
    hub: OnceLock<Weak<Hub>>,
}

impl std::fmt::Debug for Notifications {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Notifications")
            .field("home", &self.home)
            .finish_non_exhaustive()
    }
}

impl Notifications {
    /// Feeds stored in `db`, for `accounts`' users, over `groups`'
    /// channels.
    pub fn new(db: Arc<Db>, groups: Arc<Groups>, accounts: AccountStore) -> Self {
        Self {
            feed: FeedStore::new(db.clone()),
            settings: SettingStore::new(db),
            home: groups.home().clone(),
            groups,
            accounts,
            hub: OnceLock::new(),
        }
    }

    /// Announce new entries through `hub` from now on. Attached once; a
    /// later call changes nothing.
    pub fn attach(&self, hub: &Arc<Hub>) {
        if self.hub.set(Arc::downgrade(hub)).is_err() {
            tracing::warn!("notifications are already attached to a hub; ignoring another");
        }
    }

    /// `actor`'s entries about channels they can read now.
    async fn visible(&self, actor: &Actor) -> Result<Vec<StoredEntry>, DbError> {
        let entries = self.feed.entries(&actor.to_string()).await?;
        let channels: BTreeSet<&str> = entries.iter().map(|e| e.channel_id.as_str()).collect();
        let ids: Vec<String> = channels.into_iter().map(str::to_owned).collect();
        let readable = self.groups.readable_among(actor, &ids).await?;
        Ok(entries
            .into_iter()
            .filter(|e| readable.channels.contains_key(&e.channel_id))
            .collect())
    }

    /// `GET /api/me/notifications`.
    pub async fn list(
        &self,
        actor: &Actor,
        query: &ListQuery,
    ) -> Result<NotificationsResponse, NotificationError> {
        let mut entries = self.visible(actor).await?;
        let counts = counts(&entries);
        entries.retain(|e| {
            query.kind.is_none_or(|k| e.kind == k) && query.before.is_none_or(|b| e.n < b)
        });
        entries.sort_by_key(|e| std::cmp::Reverse(e.n));
        let next_cursor = if entries.len() > query.limit {
            entries.truncate(query.limit);
            entries.last().map(|e| request::encode_cursor(e.n))
        } else {
            None
        };
        let items = entries.iter().map(to_wire).collect::<Result<_, _>>()?;
        Ok(NotificationsResponse {
            items,
            counts,
            next_cursor,
        })
    }

    /// `POST /api/me/notifications/{seen,read}` at `now`: mark the entries
    /// `ids` names (all of them when empty), ignoring ids that are not the
    /// caller's visible entries. Returns how many changed, and the counts.
    pub async fn mark(
        &self,
        actor: &Actor,
        ids: &[String],
        mark: Mark,
        now: i64,
    ) -> Result<(u64, NotificationCounts), NotificationError> {
        let mut entries = self.visible(actor).await?;
        let wanted: BTreeSet<&str> = ids.iter().map(String::as_str).collect();
        let targets: Vec<String> = entries
            .iter()
            .filter(|e| wanted.is_empty() || wanted.contains(e.id.as_str()))
            .filter(|e| match mark {
                Mark::Seen => e.seen_at == 0,
                Mark::Read => e.read_at == 0,
            })
            .map(|e| e.id.clone())
            .collect();
        if targets.is_empty() {
            return Ok((0, counts(&entries)));
        }
        let changed = self
            .feed
            .mark(&actor.to_string(), &targets, mark, now)
            .await?;
        let affected = changed.len() as u64;
        let mut by_id: BTreeMap<String, StoredEntry> =
            changed.into_iter().map(|e| (e.id.clone(), e)).collect();
        for e in &mut entries {
            if let Some(now) = by_id.remove(&e.id) {
                *e = now;
            }
        }
        Ok((affected, counts(&entries)))
    }

    /// `GET /api/me/notification-settings`.
    pub async fn settings(&self, actor: &Actor) -> Result<Vec<NotificationSetting>, DbError> {
        let mut prefs: Vec<NotificationSetting> = self
            .settings
            .list(&actor.to_string())
            .await?
            .iter()
            .filter_map(settings::StoredSetting::to_wire)
            .collect();
        prefs.sort_by(|a, b| {
            (a.scope_type.as_str(), a.scope_id.as_str())
                .cmp(&(b.scope_type.as_str(), b.scope_id.as_str()))
        });
        Ok(prefs)
    }

    /// `PUT /api/me/notification-settings` at `now`.
    pub async fn put_setting(
        &self,
        actor: &Actor,
        scope: &Scope,
        mode: &str,
        now: i64,
    ) -> Result<(), NotificationError> {
        Ok(self
            .settings
            .put(
                &actor.to_string(),
                scope.scope_type,
                scope.scope_id.as_str(),
                mode,
                now,
            )
            .await?)
    }

    /// `DELETE /api/me/notification-settings`: whether a setting was there.
    pub async fn clear_setting(&self, actor: &Actor, scope: &Scope) -> Result<bool, DbError> {
        self.settings
            .clear(
                &actor.to_string(),
                scope.scope_type,
                scope.scope_id.as_str(),
            )
            .await
    }
}

/// Unseen entries per kind.
fn counts(entries: &[StoredEntry]) -> NotificationCounts {
    let unseen = |k: &str| {
        entries
            .iter()
            .filter(|e| e.seen_at == 0 && e.kind == k)
            .count() as u64
    };
    NotificationCounts {
        mention: unseen(kind::MENTION),
        reply: unseen(kind::REPLY),
        message: Some(unseen(kind::MESSAGE)),
    }
}

/// An entry's wire form.
fn to_wire(e: &StoredEntry) -> Result<Notification, DbError> {
    let bad = |what: &str| DbError::Decode(format!("notification {}: bad {what}", e.id));
    let id = |v: &str, what: &str| LocalId::new(v).map_err(|_| bad(what));
    let set = |unix: i64| (unix > 0).then(|| timefmt::timestamp(unix));
    Ok(Notification {
        id: id(&e.id, "id")?,
        kind: NotificationKind::from(e.kind.as_str()),
        source_message_id: id(&e.message_id, "message id")?,
        channel_id: id(&e.channel_id, "channel id")?,
        group_id: id(&e.group_id, "group id")?,
        author: Actor::parse_canonical(&e.author).map_err(|_| bad("author"))?,
        created_at: timefmt::timestamp(e.created_at),
        seen_at: set(e.seen_at),
        read_at: set(e.read_at),
    })
}

/// Remove every entry and channel setting about the deleted channel
/// `channel_id` (the messages sweeper calls this). Idempotent.
pub async fn purge_channel(db: &Db, channel_id: &str) -> Result<(), DbError> {
    store::purge_channel(db, channel_id).await?;
    settings::purge_channel(db, channel_id).await
}
