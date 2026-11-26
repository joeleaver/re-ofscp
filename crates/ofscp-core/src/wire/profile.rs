//! Users: profiles, the account and group lists (spec §5.1, §6.2, §6.3,
//! §6.5).

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

use super::{MetadataObject, Timestamp};
use crate::Authority;

/// A present optional field must hold a value: `null` is refused rather
/// than read as absent (only fields typed [`Patch`] give `null` a meaning).
pub(crate) fn some<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

/// A user's public profile (§5.1.1), also the answer to
/// `GET /api/users/{userRef}/profile` (§6.2), which adds the profile
/// extras (`bio`) the viewer may see.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserProfile {
    /// The user's object URI, `https://{domain}/api/users/{handle}` (§2.2).
    pub id: String,
    /// The handle (§2.2.1).
    pub handle: String,
    /// The home provider's canonical authority.
    pub domain: Authority,
    /// The name to show.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// The avatar picture's URL (HTTPS).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,
    /// A short self-description, shown only to viewers the subject's
    /// `profileVisibility` admits (§6.2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bio: Option<String>,
    /// Whether this is a provider-local guest (§4.8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest: Option<bool>,
    /// When a guest account expires (§4.8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Timestamp>,
    /// When the profile last changed.
    pub updated_at: Timestamp,
    /// Extension data (§5.4).
    #[serde(default)]
    pub metadata: Vec<MetadataObject>,
}

/// `GET /api/me`: the caller's own account, never federated (§5.1.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserAccount {
    /// The caller's own profile, extras included.
    pub profile: UserProfile,
    /// Provider-defined settings.
    pub settings: Map<String, Value>,
}

/// A field of a partial update that may also be cleared with `null`.
/// Give the field `#[serde(default, skip_serializing_if = "Patch::is_keep")]`.
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

impl<T> Patch<T> {
    /// Whether the field is left out.
    pub fn is_keep(&self) -> bool {
        matches!(self, Self::Keep)
    }
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

impl<T: Serialize> Serialize for Patch<T> {
    // `Keep` is skipped by `skip_serializing_if`; if it is serialized
    // anyway it becomes `null`, like `Clear`.
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Keep | Self::Clear => s.serialize_none(),
            Self::Set(v) => s.serialize_some(v),
        }
    }
}

/// `PATCH /api/me/profile` (§6.3). Every field is optional; an absent field
/// is left unchanged.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileUpdate {
    /// A new display name.
    #[serde(
        default,
        deserialize_with = "some",
        skip_serializing_if = "Option::is_none"
    )]
    pub display_name: Option<String>,
    /// A new avatar URL, or `null` to remove the avatar.
    #[serde(default, skip_serializing_if = "Patch::is_keep")]
    pub avatar: Patch<String>,
    /// A new bio; the empty string removes it.
    #[serde(
        default,
        deserialize_with = "some",
        skip_serializing_if = "Option::is_none"
    )]
    pub bio: Option<String>,
    /// A new metadata list, replacing the old one.
    #[serde(
        default,
        deserialize_with = "some",
        skip_serializing_if = "Option::is_none"
    )]
    pub metadata: Option<Vec<MetadataObject>>,
}

/// One entry of [`UserGroups`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupEntry {
    /// The group's object URI (§2.2).
    pub id: String,
}

/// `GET /api/users/{userRef}/groups`: the groups a user is in that the
/// viewer may see (§6.5).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserGroups {
    /// The groups, by object URI.
    pub groups: Vec<GroupEntry>,
    /// Extension data (§5.4).
    #[serde(default)]
    pub metadata: Vec<MetadataObject>,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

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
    fn patch_encodes_as_it_decodes() {
        for body in [
            json!({}),
            json!({"avatar": null}),
            json!({"avatar": "https://a.com/m/1", "bio": "hi"}),
        ] {
            let u: ProfileUpdate = serde_json::from_value(body.clone()).unwrap();
            assert_eq!(serde_json::to_value(&u).unwrap(), body);
        }
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let u: ProfileUpdate = serde_json::from_value(json!({"bio": "hi", "future": 1})).unwrap();
        assert_eq!(u.bio.as_deref(), Some("hi"));
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
}
