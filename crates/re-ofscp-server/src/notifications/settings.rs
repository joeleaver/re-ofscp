//! Notification settings in rhypedb (`NotificationSetting` in
//! `schema.rhype`; §10.2): one row per (owner, scope), keyed `@unique` by
//! `"{owner} {scope_type} {scope_id}"`. Neither a canonical actor, a scope
//! type nor a local id holds a space, so the key is unambiguous.

use std::sync::Arc;

use ofscp_core::LocalId;
use ofscp_core::wire::{NotificationMode, NotificationScope, NotificationSetting};
use serde::Deserialize;

use crate::db::{Db, DbError, Ql};
use crate::messages::locks::ChannelLocks;

/// Settings one user may hold. A user's settings are listed whole, so they
/// are bounded; a `PUT` of a new scope past this is refused (`400`). `PUT`s
/// take turns per user in this process, so only processes racing each
/// other can pass it, by at most one setting each; [`LIST_LIMIT`] leaves
/// room for that.
pub const MAX_SETTINGS_PER_USER: usize = 1000;
/// Most rows a listing reads.
const LIST_LIMIT: usize = 2 * MAX_SETTINGS_PER_USER;
/// Rows read per page when listing a scope's `all` settings.
const SCAN_PAGE: usize = 1000;

/// `scope_type` values.
pub mod scope {
    /// A whole group.
    pub const GROUP: &str = "group";
    /// One channel.
    pub const CHANNEL: &str = "channel";
}

/// `mode` values.
pub mod mode {
    /// Every message.
    pub const ALL: &str = "all";
    /// Mentions and replies (the default).
    pub const MENTIONS: &str = "mentions";
    /// Nothing.
    pub const NONE: &str = "none";
}

/// A setting, as stored: all three fields known values.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct StoredSetting {
    /// The local user it belongs to.
    pub owner: String,
    /// [`scope::GROUP`] or [`scope::CHANNEL`].
    pub scope_type: String,
    /// The group's or channel's local id.
    pub scope_id: String,
    /// One of [`mode`].
    pub mode: String,
}

impl StoredSetting {
    /// Its wire form, or `None` for a row this code did not write (or one
    /// being cleared, whose mode is empty).
    pub fn to_wire(&self) -> Option<NotificationSetting> {
        let scope_type = NotificationScope::from(self.scope_type.as_str());
        let mode = NotificationMode::from(self.mode.as_str());
        if !scope_type.is_known() || !mode.is_known() {
            return None;
        }
        Some(NotificationSetting {
            scope_type,
            scope_id: LocalId::new(&self.scope_id).ok()?,
            mode,
        })
    }
}

/// Why a `PUT` was not stored.
#[derive(Debug, thiserror::Error)]
pub enum PutError {
    /// The user already holds [`MAX_SETTINGS_PER_USER`] settings (`400`).
    #[error("at most {MAX_SETTINGS_PER_USER} notification settings may be held")]
    TooMany,
    /// The database failed (`500`).
    #[error(transparent)]
    Db(#[from] DbError),
}

fn key(owner: &str, scope_type: &str, scope_id: &str) -> String {
    format!("{owner} {scope_type} {scope_id}")
}

/// Storage for notification settings.
#[derive(Debug)]
pub struct SettingStore {
    db: Arc<Db>,
    /// Per-owner turns at `PUT`, in this process.
    turns: ChannelLocks,
}

impl SettingStore {
    /// Settings stored in `db`.
    pub fn new(db: Arc<Db>) -> Self {
        Self {
            db,
            turns: ChannelLocks::default(),
        }
    }

    /// Every setting `owner` holds, in no particular order.
    pub async fn list(&self, owner: &str) -> Result<Vec<StoredSetting>, DbError> {
        let q = Ql::new("NotificationSetting.filter(.owner == ")
            .str(owner)
            .raw(").limit(")
            .uint(LIST_LIMIT as u64)
            .raw(")");
        Ok(self
            .db
            .fetch::<StoredSetting>(&q)
            .await?
            .into_iter()
            .map(|r| r.data)
            .collect())
    }

    /// `owner`'s mode for the scope, if they set one.
    pub async fn mode(
        &self,
        owner: &str,
        scope_type: &str,
        scope_id: &str,
    ) -> Result<Option<String>, DbError> {
        let q = Ql::new("NotificationSetting.filter(.key == ")
            .str(&key(owner, scope_type, scope_id))
            .raw(")");
        Ok(self
            .db
            .fetch::<StoredSetting>(&q)
            .await?
            .into_iter()
            .next()
            .map(|r| r.data.mode))
    }

    /// Store `mode` for `owner`'s scope at `now`, replacing any earlier
    /// setting there.
    pub async fn put(
        &self,
        owner: &str,
        scope_type: &str,
        scope_id: &str,
        mode: &str,
        now: i64,
    ) -> Result<(), PutError> {
        let _turn = self.turns.lock(owner).await;
        let k = key(owner, scope_type, scope_id);
        let update = Ql::new("NotificationSetting.filter(.key == ")
            .str(&k)
            .raw(").update({ mode: ")
            .str(mode)
            .raw(", updated_at: ")
            .int(now)
            .raw(" })");
        // An existing setting changes in place; the bound is about new ones.
        // Two passes cover a create racing this one (the loser updates).
        for _ in 0..2 {
            if !self
                .db
                .write_one_object(&update)
                .await?
                .into_objects()
                .is_empty()
            {
                return Ok(());
            }
            if self.list(owner).await?.len() >= MAX_SETTINGS_PER_USER {
                return Err(PutError::TooMany);
            }
            let create = Ql::new("NotificationSetting.create({ key: ")
                .str(&k)
                .raw(", owner: ")
                .str(owner)
                .raw(", scope_type: ")
                .str(scope_type)
                .raw(", scope_id: ")
                .str(scope_id)
                .raw(", mode: ")
                .str(mode)
                .raw(", updated_at: ")
                .int(now)
                .raw(" })");
            match self.db.write_one_object(&create).await {
                Ok(_) => return Ok(()),
                // Created meanwhile: update that one.
                Err(DbError::Conflict(_)) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err(DbError::Contended(format!("notification setting {k}: kept changing")).into())
    }

    /// Remove `owner`'s setting for the scope. Whether there was one.
    pub async fn clear(
        &self,
        owner: &str,
        scope_type: &str,
        scope_id: &str,
    ) -> Result<bool, DbError> {
        let k = key(owner, scope_type, scope_id);
        // `delete` returns no rows: claim the row with a guarded update
        // first, so exactly one of two racing clears reports `true`.
        let claim = Ql::new("NotificationSetting.filter(.key == ")
            .str(&k)
            .raw(" && .mode != \"\").update({ mode: \"\" })");
        let claimed = !self
            .db
            .write_one_object(&claim)
            .await?
            .into_objects()
            .is_empty();
        let delete = Ql::new("NotificationSetting.filter(.key == ")
            .str(&k)
            .raw(" && .mode == \"\").delete()");
        self.db.write_one_object(&delete).await?;
        Ok(claimed)
    }

    /// Every owner whose mode for the scope is `all`.
    ///
    /// rhypedb cannot order, so this pages by offset over the scope's rows.
    /// A scope's rows fit in one page up to [`SCAN_PAGE`] settings, and then
    /// the answer is one snapshot; past that, a setting of the same scope
    /// changed or removed while the pages are read can shift a row from an
    /// unread page into one already read, and that owner gets no `message`
    /// entry for this one message (decision 0023).
    pub async fn all_mode_owners(
        &self,
        scope_type: &str,
        scope_id: &str,
    ) -> Result<Vec<String>, DbError> {
        let mut out = Vec::new();
        let mut offset = 0u64;
        loop {
            let q = Ql::new("NotificationSetting.filter(.scope_id == ")
                .str(scope_id)
                .raw(" && .scope_type == ")
                .str(scope_type)
                .raw(" && .mode == ")
                .str(mode::ALL)
                .raw(").offset(")
                .uint(offset)
                .raw(").limit(")
                .uint(SCAN_PAGE as u64)
                .raw(")");
            let rows = self.db.fetch::<StoredSetting>(&q).await?;
            let full = rows.len() == SCAN_PAGE;
            out.extend(rows.into_iter().map(|r| r.data.owner));
            if !full {
                break;
            }
            offset += SCAN_PAGE as u64;
        }
        out.sort();
        out.dedup();
        Ok(out)
    }
}

/// Remove every setting for the deleted channel `channel_id`. Idempotent.
pub async fn purge_channel(db: &Db, channel_id: &str) -> Result<(), DbError> {
    let q = Ql::new("NotificationSetting.filter(.scope_id == ")
        .str(channel_id)
        .raw(" && .scope_type == ")
        .str(scope::CHANNEL)
        .raw(").delete()");
    db.execute(&q).await
}
