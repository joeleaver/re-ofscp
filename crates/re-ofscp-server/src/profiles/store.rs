//! Profiles, privacy settings and presence in rhypedb (the profile fields of
//! `User`, and `PrivacySettings` and `Presence` in `schema.rhype`). Every
//! query goes through [`Ql`].
//!
//! Metadata lists and actor lists are stored as JSON text in `String`
//! fields: written by `serde_json` and escaped by [`Ql::str`], they never
//! become query syntax.

use std::sync::Arc;

use re_ofscp_types::Actor;
use re_ofscp_types::profile::{Availability, MetadataObject, Visibility};
use serde::Deserialize;

use crate::accounts::store::status;
use crate::db::{Db, DbError, Ql};
use crate::timefmt::unix;

/// The defaults for an account that has never saved privacy settings
/// (docs/decisions/0009; the same as Forumall's).
pub const DEFAULT_PRESENCE_VISIBILITY: Visibility = Visibility::SharedGroups;
/// See [`DEFAULT_PRESENCE_VISIBILITY`].
pub const DEFAULT_PROFILE_VISIBILITY: Visibility = Visibility::Public;
/// See [`DEFAULT_PRESENCE_VISIBILITY`].
pub const DEFAULT_MEMBERSHIP_VISIBILITY: Visibility = Visibility::Authenticated;

/// An active account's profile as stored.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredProfile {
    /// The handle.
    pub handle: String,
    /// Display name (never empty).
    pub display_name: String,
    /// Avatar URL, if set.
    pub avatar: Option<String>,
    /// Bio, if set.
    pub bio: Option<String>,
    /// Profile metadata.
    pub metadata: Vec<MetadataObject>,
    /// Unix seconds of the last profile change (the account's creation
    /// before its first change).
    pub updated_at: i64,
}

#[derive(Deserialize)]
struct ProfileRow {
    handle: String,
    display_name: String,
    status: String,
    created_at: String,
    // Absent on accounts created before profiles existed.
    #[serde(default)]
    avatar: Option<String>,
    #[serde(default)]
    bio: Option<String>,
    #[serde(default)]
    profile_metadata: Option<String>,
    #[serde(default)]
    profile_updated_at: Option<String>,
}

fn decode(what: &str) -> DbError {
    DbError::Decode(format!("stored {what} is malformed"))
}

fn non_empty(s: Option<String>) -> Option<String> {
    s.filter(|s| !s.is_empty())
}

fn metadata_from(json: Option<&str>) -> Result<Vec<MetadataObject>, DbError> {
    match json {
        None | Some("") => Ok(Vec::new()),
        Some(text) => serde_json::from_str(text).map_err(|_| decode("metadata")),
    }
}

/// `metadata` as the JSON text stored for it.
pub fn metadata_json(metadata: &[MetadataObject]) -> String {
    // Serializing plain data with string keys cannot fail; an empty list
    // is the only sane fallback if it ever did.
    serde_json::to_string(metadata).unwrap_or_else(|_| "[]".to_owned())
}

impl ProfileRow {
    /// The profile, or `None` for a disabled account.
    fn into_profile(self) -> Result<Option<StoredProfile>, DbError> {
        if self.status != status::ACTIVE {
            return Ok(None);
        }
        let updated = self
            .profile_updated_at
            .as_deref()
            .unwrap_or(&self.created_at);
        Ok(Some(StoredProfile {
            metadata: metadata_from(self.profile_metadata.as_deref())?,
            updated_at: unix(updated).ok_or_else(|| decode("profile time"))?,
            handle: self.handle,
            display_name: self.display_name,
            avatar: non_empty(self.avatar),
            bio: non_empty(self.bio),
        }))
    }
}

/// A validated change to a profile. `None` leaves a field unchanged.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProfileChanges {
    /// New display name.
    pub display_name: Option<String>,
    /// New avatar URL; the empty string removes it.
    pub avatar: Option<String>,
    /// New bio; the empty string removes it.
    pub bio: Option<String>,
    /// New metadata list.
    pub metadata: Option<Vec<MetadataObject>>,
}

/// Privacy settings as stored (or the defaults).
#[derive(Debug, Clone, PartialEq)]
pub struct StoredPrivacy {
    /// Who may see presence.
    pub presence: Visibility,
    /// Who may see profile extras.
    pub profile: Visibility,
    /// Who may see group memberships.
    pub membership: Visibility,
    /// Always admitted.
    pub allow: Vec<Actor>,
    /// Always refused.
    pub deny: Vec<Actor>,
    /// Settings metadata.
    pub metadata: Vec<MetadataObject>,
}

impl Default for StoredPrivacy {
    fn default() -> Self {
        Self {
            presence: DEFAULT_PRESENCE_VISIBILITY,
            profile: DEFAULT_PROFILE_VISIBILITY,
            membership: DEFAULT_MEMBERSHIP_VISIBILITY,
            allow: Vec::new(),
            deny: Vec::new(),
            metadata: Vec::new(),
        }
    }
}

/// A validated change to privacy settings. `None` leaves a field unchanged.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PrivacyChanges {
    /// New presence visibility.
    pub presence: Option<Visibility>,
    /// New profile-extras visibility.
    pub profile: Option<Visibility>,
    /// New membership visibility.
    pub membership: Option<Visibility>,
    /// New allow list (canonical, deduplicated).
    pub allow: Option<Vec<Actor>>,
    /// New deny list (canonical, deduplicated).
    pub deny: Option<Vec<Actor>>,
    /// New metadata list.
    pub metadata: Option<Vec<MetadataObject>>,
}

impl PrivacyChanges {
    /// `current` with these changes applied.
    pub fn apply(&self, current: StoredPrivacy) -> StoredPrivacy {
        StoredPrivacy {
            presence: self.presence.unwrap_or(current.presence),
            profile: self.profile.unwrap_or(current.profile),
            membership: self.membership.unwrap_or(current.membership),
            allow: self.allow.clone().unwrap_or(current.allow),
            deny: self.deny.clone().unwrap_or(current.deny),
            metadata: self.metadata.clone().unwrap_or(current.metadata),
        }
    }
}

#[derive(Deserialize)]
struct PrivacyRow {
    presence_visibility: String,
    profile_visibility: String,
    membership_visibility: String,
    allow_list: String,
    deny_list: String,
    metadata: String,
}

fn visibility(s: &str) -> Result<Visibility, DbError> {
    Visibility::parse(s).ok_or_else(|| decode("visibility"))
}

fn actors_from(json: &str) -> Result<Vec<Actor>, DbError> {
    let list: Vec<String> = serde_json::from_str(json).map_err(|_| decode("actor list"))?;
    list.iter()
        .map(|a| Actor::parse_canonical(a).map_err(|_| decode("actor list")))
        .collect()
}

fn actors_json(actors: &[Actor]) -> String {
    let list: Vec<String> = actors.iter().map(ToString::to_string).collect();
    serde_json::to_string(&list).unwrap_or_else(|_| "[]".to_owned())
}

impl PrivacyRow {
    fn into_privacy(self) -> Result<StoredPrivacy, DbError> {
        Ok(StoredPrivacy {
            presence: visibility(&self.presence_visibility)?,
            profile: visibility(&self.profile_visibility)?,
            membership: visibility(&self.membership_visibility)?,
            allow: actors_from(&self.allow_list)?,
            deny: actors_from(&self.deny_list)?,
            metadata: metadata_from(Some(&self.metadata))?,
        })
    }
}

/// Presence as stored.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredPresence {
    /// The explicit availability (`online`, `away` or `dnd`).
    pub availability: Availability,
    /// Free-text status, if set.
    pub status: Option<String>,
    /// Presence metadata.
    pub metadata: Vec<MetadataObject>,
    /// When the user's last connection ended (RFC 3339), if ever.
    pub last_seen: Option<String>,
}

#[derive(Deserialize)]
struct PresenceRow {
    availability: String,
    status: String,
    metadata: String,
    #[serde(default)]
    last_seen: Option<String>,
}

impl PresenceRow {
    fn into_presence(self) -> Result<StoredPresence, DbError> {
        Ok(StoredPresence {
            availability: Availability::parse(&self.availability)
                .ok_or_else(|| decode("availability"))?,
            status: non_empty(Some(self.status)),
            metadata: metadata_from(Some(&self.metadata))?,
            last_seen: self.last_seen,
        })
    }
}

/// Storage for profiles, privacy settings and presence.
#[derive(Debug, Clone)]
pub struct ProfileStore {
    db: Arc<Db>,
}

impl ProfileStore {
    /// A store over `db`.
    pub fn new(db: Arc<Db>) -> Self {
        Self { db }
    }

    /// The profile of the active account `handle`; `None` if there is no
    /// such account or it is disabled.
    pub async fn profile(&self, handle: &str) -> Result<Option<StoredProfile>, DbError> {
        let q = Ql::new("User.filter(.handle == ").str(handle).raw(")");
        match self.db.fetch::<ProfileRow>(&q).await?.into_iter().next() {
            Some(row) => row.data.into_profile(),
            None => Ok(None),
        }
    }

    /// Apply `changes` to the active account `handle` in one update and
    /// stamp the change time (nothing is written if nothing changes).
    /// `None` if there is no such active account.
    pub async fn update_profile(
        &self,
        handle: &str,
        changes: &ProfileChanges,
        now: i64,
    ) -> Result<Option<StoredProfile>, DbError> {
        // Nothing to change: `updatedAt` is the time of the last change
        // (§6.3), so an empty update writes nothing.
        if *changes == ProfileChanges::default() {
            return self.profile(handle).await;
        }
        let mut q = Ql::new("User.filter(.handle == ")
            .str(handle)
            .raw(" && .status == ")
            .str(status::ACTIVE)
            .raw(").update({ profile_updated_at: ")
            .unix_seconds(now);
        if let Some(name) = &changes.display_name {
            q = q.raw(", display_name: ").str(name);
        }
        if let Some(avatar) = &changes.avatar {
            q = q.raw(", avatar: ").str(avatar);
        }
        if let Some(bio) = &changes.bio {
            q = q.raw(", bio: ").str(bio);
        }
        if let Some(metadata) = &changes.metadata {
            q = q.raw(", profile_metadata: ").str(&metadata_json(metadata));
        }
        let q = q.raw(" })");
        match self
            .db
            .write_one_object_as::<ProfileRow>(&q)
            .await?
            .into_iter()
            .next()
        {
            Some(row) => row.data.into_profile(),
            None => Ok(None),
        }
    }

    /// `handle`'s privacy settings, or the defaults if never saved.
    pub async fn privacy(&self, handle: &str) -> Result<StoredPrivacy, DbError> {
        let q = Ql::new("PrivacySettings.filter(.handle == ")
            .str(handle)
            .raw(")");
        match self.db.fetch::<PrivacyRow>(&q).await?.into_iter().next() {
            Some(row) => row.data.into_privacy(),
            None => Ok(StoredPrivacy::default()),
        }
    }

    /// Apply `changes` to `handle`'s privacy settings, which were `seen`
    /// when `changes` was validated, and return the result.
    ///
    /// Only the changed fields are written, in one single-object update, so
    /// concurrent updates of different visibility fields both take effect.
    /// A change to either list writes both, as the pair validated against
    /// `seen`: an object's update is one transaction, so the stored lists
    /// are always a pair that passed the no-actor-on-both-lists check, and
    /// of two concurrent list changes the later wins whole. (A guard in the
    /// filter would not help: rhypedb evaluates the filter on a snapshot and
    /// updates each object in a transaction of its own.)
    ///
    /// The first save creates the row from `seen` (the defaults). `None`
    /// if a concurrent first save created it meanwhile: re-read,
    /// re-validate and call again.
    pub async fn update_privacy(
        &self,
        handle: &str,
        changes: &PrivacyChanges,
        seen: &StoredPrivacy,
        now: i64,
    ) -> Result<Option<StoredPrivacy>, DbError> {
        let mut q = Ql::new("PrivacySettings.filter(.handle == ")
            .str(handle)
            .raw(").update({ updated_at: ")
            .unix_seconds(now);
        if let Some(v) = changes.presence {
            q = q.raw(", presence_visibility: ").str(v.as_str());
        }
        if let Some(v) = changes.profile {
            q = q.raw(", profile_visibility: ").str(v.as_str());
        }
        if let Some(v) = changes.membership {
            q = q.raw(", membership_visibility: ").str(v.as_str());
        }
        if changes.allow.is_some() || changes.deny.is_some() {
            let allow = changes.allow.as_ref().unwrap_or(&seen.allow);
            let deny = changes.deny.as_ref().unwrap_or(&seen.deny);
            q = q
                .raw(", allow_list: ")
                .str(&actors_json(allow))
                .raw(", deny_list: ")
                .str(&actors_json(deny));
        }
        if let Some(metadata) = &changes.metadata {
            q = q.raw(", metadata: ").str(&metadata_json(metadata));
        }
        let q = q.raw(" })");
        if let Some(row) = self.db.write_one_object_as::<PrivacyRow>(&q).await?.pop() {
            return row.data.into_privacy().map(Some);
        }
        let new = changes.apply(seen.clone());
        let q = Ql::new("PrivacySettings.create({ handle: ")
            .str(handle)
            .raw(", presence_visibility: ")
            .str(new.presence.as_str())
            .raw(", profile_visibility: ")
            .str(new.profile.as_str())
            .raw(", membership_visibility: ")
            .str(new.membership.as_str())
            .raw(", allow_list: ")
            .str(&actors_json(&new.allow))
            .raw(", deny_list: ")
            .str(&actors_json(&new.deny))
            .raw(", metadata: ")
            .str(&metadata_json(&new.metadata))
            .raw(", updated_at: ")
            .unix_seconds(now)
            .raw(" })");
        match self.db.write_one_object_as::<PrivacyRow>(&q).await {
            Ok(mut rows) => match rows.pop() {
                Some(row) => row.data.into_privacy().map(Some),
                None => Err(DbError::Decode("create returned nothing".to_owned())),
            },
            Err(DbError::Conflict(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// `handle`'s stored presence, if ever set.
    pub async fn presence(&self, handle: &str) -> Result<Option<StoredPresence>, DbError> {
        let q = Ql::new("Presence.filter(.handle == ").str(handle).raw(")");
        match self.db.fetch::<PresenceRow>(&q).await?.into_iter().next() {
            Some(row) => row.data.into_presence().map(Some),
            None => Ok(None),
        }
    }

    /// Replace `handle`'s explicit presence (`availability`, `status`,
    /// `metadata`; `last_seen` is kept). Creates the row on first use, and
    /// retries as an update if a concurrent first use wins the `@unique`
    /// race.
    pub async fn set_presence(
        &self,
        handle: &str,
        availability: Availability,
        status: Option<&str>,
        metadata: &[MetadataObject],
        now: i64,
    ) -> Result<StoredPresence, DbError> {
        let status = status.unwrap_or("");
        let metadata = metadata_json(metadata);
        for _ in 0..2 {
            let q = Ql::new("Presence.filter(.handle == ")
                .str(handle)
                .raw(").update({ availability: ")
                .str(availability.as_str())
                .raw(", status: ")
                .str(status)
                .raw(", metadata: ")
                .str(&metadata)
                .raw(", updated_at: ")
                .unix_seconds(now)
                .raw(" })");
            if let Some(row) = self
                .db
                .write_one_object_as::<PresenceRow>(&q)
                .await?
                .into_iter()
                .next()
            {
                return row.data.into_presence();
            }
            let q = Ql::new("Presence.create({ handle: ")
                .str(handle)
                .raw(", availability: ")
                .str(availability.as_str())
                .raw(", status: ")
                .str(status)
                .raw(", metadata: ")
                .str(&metadata)
                .raw(", updated_at: ")
                .unix_seconds(now)
                .raw(" })");
            match self.db.write_one_object_as::<PresenceRow>(&q).await {
                Ok(mut rows) => match rows.pop() {
                    Some(row) => return row.data.into_presence(),
                    None => return Err(DbError::Decode("create returned nothing".to_owned())),
                },
                Err(DbError::Conflict(_)) => continue,
                Err(e) => return Err(e),
            }
        }
        Err(DbError::Query(
            "presence row neither updatable nor creatable".to_owned(),
        ))
    }
}
