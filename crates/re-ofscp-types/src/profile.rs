//! User profiles, presence and privacy settings (spec §5.1, §6).
//!
//! Field names are camelCase on the wire (§2.5). Every request type ignores
//! unknown fields (§2.3); the server validates values beyond their shape
//! (lengths, URLs, actors) before storing anything.

use serde::de::Deserializer;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// A metadata object (§5.4): `{ schema, version, data }`, plus any further
/// fields the sender included, kept as they came.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetadataObject {
    /// The metadata schema's HTTPS URI.
    pub schema: String,
    /// The schema version.
    pub version: String,
    /// Arbitrary JSON for that schema. Required, but may be `null`.
    #[serde(deserialize_with = "present_value")]
    pub data: Value,
    /// Any other fields, preserved.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `data` must be present; `null` is a value. Without this, serde would
/// accept a missing `data` as `null`.
fn present_value<'de, D: Deserializer<'de>>(d: D) -> Result<Value, D::Error> {
    Value::deserialize(d)
}

/// A present optional field must hold a value: `null` is refused rather
/// than read as absent (only `avatar` gives `null` a meaning, [`Patch`]).
fn some<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

/// `UserProfile` (§5.1.1), and the `GET /api/users/{userRef}/profile`
/// response (§6.2), which adds the profile extras the viewer may see.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserProfile {
    /// The user's object URI, `https://{domain}/api/users/{handle}` (§2.2).
    pub id: String,
    /// The handle (§2.2.1).
    pub handle: String,
    /// The home provider's canonical authority.
    pub domain: String,
    /// Display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Avatar URL (an `Attachment` URL this provider hosts, §6.3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,
    /// Profile extra, shown only to viewers the subject's
    /// `profileVisibility` admits (§6.2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bio: Option<String>,
    /// When the profile last changed (RFC 3339).
    pub updated_at: String,
    /// Profile metadata (§5.4).
    #[serde(default)]
    pub metadata: Vec<MetadataObject>,
}

/// `UserAccount` (§5.1.2): returned only to the account itself by
/// `GET /api/me`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserAccount {
    /// The caller's own profile, extras included.
    pub profile: UserProfile,
    /// Provider-specific settings. This provider defines none yet.
    pub settings: Map<String, Value>,
}

/// A field of a partial update that may also be cleared with `null`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Patch<T> {
    /// Absent: leave it unchanged.
    #[default]
    Keep,
    /// `null`: remove it.
    Clear,
    /// A new value.
    Set(T),
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Patch<T> {
    // Called only when the field is present (absent fields take the
    // `Default`, `Keep`), so `null` here means "clear".
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(match Option::<T>::deserialize(d)? {
            None => Self::Clear,
            Some(v) => Self::Set(v),
        })
    }
}

/// `PATCH /api/me/profile` request (§6.3). Every field is optional; an
/// absent field is left unchanged.
#[derive(Debug, Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileUpdate {
    /// A new display name.
    #[serde(default, deserialize_with = "some")]
    pub display_name: Option<String>,
    /// A new avatar URL, or `null` to remove the avatar.
    #[serde(default)]
    pub avatar: Patch<String>,
    /// A new bio; the empty string removes it.
    #[serde(default, deserialize_with = "some")]
    pub bio: Option<String>,
    /// A new metadata list, replacing the old one.
    #[serde(default, deserialize_with = "some")]
    pub metadata: Option<Vec<MetadataObject>>,
}

/// The shared visibility policy (§6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Visibility {
    /// Visible to anyone.
    Public,
    /// Visible to any authenticated user.
    Authenticated,
    /// Visible to viewers who share at least one group with the subject.
    SharedGroups,
    /// Visible only to the subject's mutual, accepted contacts (§6.7).
    Contacts,
    /// Visible to no one but the subject.
    Nobody,
}

impl Visibility {
    /// The wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Authenticated => "authenticated",
            Self::SharedGroups => "sharedGroups",
            Self::Contacts => "contacts",
            Self::Nobody => "nobody",
        }
    }

    /// Parse the wire spelling.
    pub fn parse(s: &str) -> Option<Self> {
        [
            Self::Public,
            Self::Authenticated,
            Self::SharedGroups,
            Self::Contacts,
            Self::Nobody,
        ]
        .into_iter()
        .find(|v| v.as_str() == s)
    }
}

/// Privacy settings (§6.6): `GET /api/me/privacy` and the response to
/// `PUT /api/me/privacy`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivacySettings {
    /// Who may see the subject's presence.
    pub presence_visibility: Visibility,
    /// Who may see the subject's profile extras (`bio`).
    pub profile_visibility: Visibility,
    /// Who may see the subject's group memberships.
    pub membership_visibility: Visibility,
    /// Actors always admitted, whatever the policy (canonical form).
    pub allow_list: Vec<String>,
    /// Actors always refused, whatever the policy (canonical form).
    pub deny_list: Vec<String>,
    /// Settings metadata (§5.4).
    pub metadata: Vec<MetadataObject>,
}

/// `PUT /api/me/privacy` request (§6.6). An absent field is left unchanged
/// (docs/decisions/0008).
#[derive(Debug, Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivacyUpdate {
    /// New presence visibility.
    #[serde(default, deserialize_with = "some")]
    pub presence_visibility: Option<Visibility>,
    /// New profile-extras visibility.
    #[serde(default, deserialize_with = "some")]
    pub profile_visibility: Option<Visibility>,
    /// New membership visibility.
    #[serde(default, deserialize_with = "some")]
    pub membership_visibility: Option<Visibility>,
    /// A new allow list, replacing the old one. Entries are actors.
    #[serde(default, deserialize_with = "some")]
    pub allow_list: Option<Vec<String>>,
    /// A new deny list, replacing the old one. Entries are actors.
    #[serde(default, deserialize_with = "some")]
    pub deny_list: Option<Vec<String>>,
    /// New settings metadata, replacing the old list.
    #[serde(default, deserialize_with = "some")]
    pub metadata: Option<Vec<MetadataObject>>,
}

/// Presence availability (§6.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Availability {
    /// Connected and available.
    Online,
    /// Away.
    Away,
    /// Do not disturb.
    Dnd,
    /// Not connected. Derived from connection liveness, never set (§7.5).
    Offline,
}

impl Availability {
    /// The wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Online => "online",
            Self::Away => "away",
            Self::Dnd => "dnd",
            Self::Offline => "offline",
        }
    }

    /// Parse the wire spelling.
    pub fn parse(s: &str) -> Option<Self> {
        [Self::Online, Self::Away, Self::Dnd, Self::Offline]
            .into_iter()
            .find(|v| v.as_str() == s)
    }
}

/// `Presence` (§6.4): the `GET /api/users/{userRef}/presence` response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Presence {
    /// Current availability.
    pub availability: Availability,
    /// Free-text status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// When the user was last connected (RFC 3339).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
    /// Presence metadata (§5.4).
    #[serde(default)]
    pub metadata: Vec<MetadataObject>,
}

/// `PUT /api/me/presence` request (§6.4): replaces the stored presence.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PresenceUpdate {
    /// The explicit availability: `online`, `away` or `dnd`.
    pub availability: Availability,
    /// Free-text status; absent clears it.
    #[serde(default, deserialize_with = "some")]
    pub status: Option<String>,
    /// Presence metadata; absent clears it.
    #[serde(default)]
    pub metadata: Vec<MetadataObject>,
}

/// One entry of [`UserGroups`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupEntry {
    /// The group's object URI (§2.2).
    pub id: String,
}

/// `GET /api/users/{userRef}/groups` response (§6.5).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserGroups {
    /// The subject's groups the viewer may see.
    pub groups: Vec<GroupEntry>,
    /// Listing metadata (§5.4).
    pub metadata: Vec<MetadataObject>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn patch_tells_absent_from_null() {
        let u: ProfileUpdate = serde_json::from_value(json!({})).unwrap();
        assert_eq!(u.avatar, Patch::Keep);
        let u: ProfileUpdate = serde_json::from_value(json!({"avatar": null})).unwrap();
        assert_eq!(u.avatar, Patch::Clear);
        let u: ProfileUpdate =
            serde_json::from_value(json!({"avatar": "https://a.com/m/1"})).unwrap();
        assert_eq!(u.avatar, Patch::Set("https://a.com/m/1".to_owned()));
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let u: ProfileUpdate = serde_json::from_value(json!({"bio": "hi", "future": 1})).unwrap();
        assert_eq!(u.bio.as_deref(), Some("hi"));
        let p: PrivacyUpdate = serde_json::from_value(json!({"x": true})).unwrap();
        assert_eq!(p, PrivacyUpdate::default());
    }

    #[test]
    fn null_is_refused_where_it_means_nothing() {
        for body in [
            json!({"bio": null}),
            json!({"displayName": null}),
            json!({"metadata": null}),
        ] {
            assert!(serde_json::from_value::<ProfileUpdate>(body).is_err());
        }
        assert!(serde_json::from_value::<PrivacyUpdate>(json!({"allowList": null})).is_err());
        assert!(
            serde_json::from_value::<PresenceUpdate>(
                json!({"availability": "away", "status": null})
            )
            .is_err()
        );
    }

    #[test]
    fn metadata_requires_data_but_allows_null_and_keeps_extras() {
        let m: Result<MetadataObject, _> =
            serde_json::from_value(json!({"schema": "https://s", "version": "1"}));
        assert!(m.is_err());
        let m: MetadataObject = serde_json::from_value(
            json!({"schema": "https://s", "version": "1", "data": null, "k": 2}),
        )
        .unwrap();
        assert_eq!(m.data, Value::Null);
        assert_eq!(
            serde_json::to_value(&m).unwrap(),
            json!({"schema": "https://s", "version": "1", "data": null, "k": 2})
        );
    }

    #[test]
    fn enums_use_the_wire_spellings() {
        for v in [
            Visibility::Public,
            Visibility::Authenticated,
            Visibility::SharedGroups,
            Visibility::Contacts,
            Visibility::Nobody,
        ] {
            assert_eq!(serde_json::to_value(v).unwrap(), json!(v.as_str()));
            assert_eq!(Visibility::parse(v.as_str()), Some(v));
        }
        assert_eq!(Visibility::parse("shared_groups"), None);
        for a in [
            Availability::Online,
            Availability::Away,
            Availability::Dnd,
            Availability::Offline,
        ] {
            assert_eq!(serde_json::to_value(a).unwrap(), json!(a.as_str()));
            assert_eq!(Availability::parse(a.as_str()), Some(a));
        }
    }
}
