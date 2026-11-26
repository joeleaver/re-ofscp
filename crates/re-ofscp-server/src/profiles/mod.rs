//! User profiles, presence, membership listing and privacy settings
//! (spec §5.1, §6; docs/decisions/0009).
//!
//! [`Profiles`] decides what a [`Viewer`] sees of a subject; the routes in
//! [`routes`] only translate HTTP. The same methods are what the WebSocket
//! presence fan-out (§7.5) must call, so the REST and real-time surfaces
//! filter identically, as §7.5 requires.

pub mod routes;
pub mod store;
pub mod user_ref;
pub mod validate;

use std::sync::Arc;

use re_ofscp_types::profile::{
    Availability, GroupEntry, Presence, PrivacySettings, UserGroups, UserProfile,
};
use re_ofscp_types::{Actor, Authority};

use crate::db::{Db, DbError};
use crate::privacy::{Liveness, Policy, RelError, Relationships, Viewer};
use crate::timefmt::rfc3339;

pub use store::{ProfileStore, StoredPresence, StoredPrivacy, StoredProfile};

/// Why a profile operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProfileError {
    /// The database failed.
    #[error(transparent)]
    Db(#[from] DbError),
    /// A relationship lookup failed.
    #[error(transparent)]
    Rel(#[from] RelError),
}

/// Profiles, presence and privacy for this provider's users.
pub struct Profiles {
    /// This provider's authority.
    pub domain: Authority,
    /// Storage.
    pub store: ProfileStore,
    /// Groups and contacts, for the visibility tiers.
    pub relationships: Relationships,
    /// Live connections, for online/offline.
    pub liveness: Arc<dyn Liveness>,
}

/// The uniform presence a viewer who may not see the subject's gets: the
/// same as genuinely offline, without `status` or `lastSeen` (§7.5).
pub fn hidden_presence() -> Presence {
    Presence {
        availability: Availability::Offline,
        status: None,
        last_seen: None,
        metadata: Vec::new(),
    }
}

impl Profiles {
    /// Profiles over `db`, with the given relationships and liveness.
    pub fn new(
        domain: Authority,
        db: Arc<Db>,
        relationships: Relationships,
        liveness: Arc<dyn Liveness>,
    ) -> Self {
        Self {
            domain,
            store: ProfileStore::new(db),
            relationships,
            liveness,
        }
    }

    /// The local actor `handle`.
    pub fn local_actor(&self, handle: &str) -> Result<Actor, DbError> {
        Actor::new(handle, self.domain.clone())
            .map_err(|e| DbError::Decode(format!("stored handle {handle:?}: {e}")))
    }

    /// `profile` as a `UserProfile` (§5.1.1), with the bio when `with_bio`.
    pub fn render(&self, profile: StoredProfile, with_bio: bool) -> UserProfile {
        UserProfile {
            id: user_ref::user_uri(&profile.handle, &self.domain),
            domain: self.domain.to_string(),
            display_name: Some(profile.display_name),
            avatar: profile.avatar,
            bio: profile.bio.filter(|_| with_bio),
            updated_at: rfc3339(profile.updated_at),
            metadata: profile.metadata,
            handle: profile.handle,
        }
    }

    /// What `viewer` sees of `profile` (§6.2): the `UserProfile` always,
    /// and the bio only if the subject's `profileVisibility` admits them.
    pub async fn profile_for(
        &self,
        profile: StoredProfile,
        viewer: &Viewer,
    ) -> Result<UserProfile, ProfileError> {
        let subject = self.local_actor(&profile.handle)?;
        let privacy = self.store.privacy(&profile.handle).await?;
        let with_bio = profile.bio.is_some()
            && policy(&privacy, privacy.profile)
                .admits(&subject, viewer, &self.relationships)
                .await?;
        Ok(self.render(profile, with_bio))
    }

    /// The presence a permitted viewer sees: `offline` unless the subject
    /// has a live connection, in which case their explicit availability
    /// (`online` if never set); `status`, `lastSeen` and metadata as stored.
    pub fn effective_presence(&self, subject: &Actor, stored: Option<StoredPresence>) -> Presence {
        let connected = self.liveness.is_connected(subject);
        match stored {
            None => Presence {
                availability: if connected {
                    Availability::Online
                } else {
                    Availability::Offline
                },
                ..hidden_presence()
            },
            Some(p) => Presence {
                availability: if connected {
                    p.availability
                } else {
                    Availability::Offline
                },
                status: p.status,
                last_seen: p.last_seen,
                metadata: p.metadata,
            },
        }
    }

    /// What `viewer` sees of local user `handle`'s presence (§6.4, §7.5):
    /// the effective presence if `presenceVisibility` admits them, else
    /// [`hidden_presence`].
    pub async fn presence_for(
        &self,
        handle: &str,
        viewer: &Viewer,
    ) -> Result<Presence, ProfileError> {
        let subject = self.local_actor(handle)?;
        let privacy = self.store.privacy(handle).await?;
        if !policy(&privacy, privacy.presence)
            .admits(&subject, viewer, &self.relationships)
            .await?
        {
            return Ok(hidden_presence());
        }
        let stored = self.store.presence(handle).await?;
        Ok(self.effective_presence(&subject, stored))
    }

    /// The groups `viewer` sees local user `handle` in (§6.5): none unless
    /// `membershipVisibility` admits them, and then only groups the viewer
    /// may know of.
    pub async fn groups_for(
        &self,
        handle: &str,
        viewer: &Viewer,
    ) -> Result<UserGroups, ProfileError> {
        let subject = self.local_actor(handle)?;
        let privacy = self.store.privacy(handle).await?;
        let groups = if policy(&privacy, privacy.membership)
            .admits(&subject, viewer, &self.relationships)
            .await?
        {
            self.relationships
                .groups
                .groups_visible_to(&subject, viewer)
                .await?
        } else {
            Vec::new()
        };
        Ok(UserGroups {
            groups: groups.into_iter().map(|id| GroupEntry { id }).collect(),
            metadata: Vec::new(),
        })
    }
}

/// One visibility setting of `privacy`, with its lists.
fn policy(privacy: &StoredPrivacy, visibility: re_ofscp_types::profile::Visibility) -> Policy<'_> {
    Policy {
        visibility,
        allow: &privacy.allow,
        deny: &privacy.deny,
    }
}

/// `privacy` on the wire (§6.6).
pub fn render_privacy(privacy: StoredPrivacy) -> PrivacySettings {
    PrivacySettings {
        presence_visibility: privacy.presence,
        profile_visibility: privacy.profile,
        membership_visibility: privacy.membership,
        allow_list: privacy.allow.iter().map(ToString::to_string).collect(),
        deny_list: privacy.deny.iter().map(ToString::to_string).collect(),
        metadata: privacy.metadata,
    }
}
