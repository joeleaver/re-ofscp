//! Presence (§6.4) and privacy settings (§6.1, §6.6).
//!
//! Each enumeration comes in two forms: an open one for what a provider
//! answers ([`Availability`], [`VisibilityPolicy`]), and a closed one for
//! what a client may send ([`SetAvailability`], [`Visibility`]), so a
//! provider refuses an unknown or forbidden value (such as setting yourself
//! `offline`) while decoding.

use serde::{Deserialize, Serialize};

use super::{MetadataObject, Timestamp, open_enum, some};
use crate::Actor;

open_enum! {
    /// A user's availability, as a provider reports it (§6.4).
    pub enum Availability {
        /// Connected and available.
        Online = "online",
        /// Away.
        Away = "away",
        /// Do not disturb.
        Dnd = "dnd",
        /// Not connected. Derived from connection liveness, never set
        /// (§7.5).
        Offline = "offline",
    }
}

/// The availability a user may set themselves: `offline` is derived from
/// their connections, never set (§7.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SetAvailability {
    /// Here.
    Online,
    /// Away.
    Away,
    /// Do not disturb.
    Dnd,
}

impl SetAvailability {
    /// The wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Online => "online",
            Self::Away => "away",
            Self::Dnd => "dnd",
        }
    }

    /// Parse the wire spelling.
    pub fn parse(s: &str) -> Option<Self> {
        [Self::Online, Self::Away, Self::Dnd]
            .into_iter()
            .find(|v| v.as_str() == s)
    }
}

impl From<SetAvailability> for Availability {
    fn from(a: SetAvailability) -> Self {
        match a {
            SetAvailability::Online => Self::Online,
            SetAvailability::Away => Self::Away,
            SetAvailability::Dnd => Self::Dnd,
        }
    }
}

/// `Presence` (§6.4): the `GET /api/users/{userRef}/presence` answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Presence {
    /// Current availability.
    pub availability: Availability,
    /// Free-text status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// When the user was last connected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<Timestamp>,
    /// Extension data (§5.4).
    #[serde(default)]
    pub metadata: Vec<MetadataObject>,
}

/// `PUT /api/me/presence`, and the `presence.set` command (§6.4, §7.5): it
/// replaces the stored presence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PresenceUpdate {
    /// The explicit availability: `online`, `away` or `dnd`.
    pub availability: SetAvailability,
    /// Free-text status; absent clears it.
    #[serde(
        default,
        deserialize_with = "some",
        skip_serializing_if = "Option::is_none"
    )]
    pub status: Option<String>,
    /// Extension data; absent clears it.
    #[serde(default)]
    pub metadata: Vec<MetadataObject>,
}

open_enum! {
    /// Who may see something of a user's, as a provider reports it (§6.1).
    pub enum VisibilityPolicy {
        /// Anyone.
        Public = "public",
        /// Any authenticated user, on any provider.
        Authenticated = "authenticated",
        /// Viewers who share at least one group with the subject.
        SharedGroups = "sharedGroups",
        /// The subject's mutual, accepted contacts (§6.7).
        Contacts = "contacts",
        /// No one but the subject.
        Nobody = "nobody",
    }
}

/// The visibility policy a user may set (§6.1), and the one a provider
/// stores and enforces.
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

impl From<Visibility> for VisibilityPolicy {
    fn from(v: Visibility) -> Self {
        Self::from(v.as_str())
    }
}

/// Privacy settings (§6.6): `GET /api/me/privacy` and the answer to
/// `PUT /api/me/privacy`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivacySettings {
    /// Who may see the subject's presence.
    pub presence_visibility: VisibilityPolicy,
    /// Who may see the subject's profile extras (`bio`).
    pub profile_visibility: VisibilityPolicy,
    /// Who may see the subject's group memberships.
    pub membership_visibility: VisibilityPolicy,
    /// Actors always admitted, whatever the policy. Absent reads as empty.
    #[serde(default)]
    pub allow_list: Vec<Actor>,
    /// Actors always refused, whatever the policy. Absent reads as empty.
    #[serde(default)]
    pub deny_list: Vec<Actor>,
    /// Extension data (§5.4).
    #[serde(default)]
    pub metadata: Vec<MetadataObject>,
}

/// `PUT /api/me/privacy` (§6.6). An absent field is left unchanged
/// (docs/decisions/0009).
///
/// The lists are kept as the strings sent: the provider parses them, and
/// may convert a non-canonical actor to canonical form (§2.2), bounded and
/// with its own error messages.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivacyUpdate {
    /// New presence visibility.
    #[serde(
        default,
        deserialize_with = "some",
        skip_serializing_if = "Option::is_none"
    )]
    pub presence_visibility: Option<Visibility>,
    /// New profile-extras visibility.
    #[serde(
        default,
        deserialize_with = "some",
        skip_serializing_if = "Option::is_none"
    )]
    pub profile_visibility: Option<Visibility>,
    /// New membership visibility.
    #[serde(
        default,
        deserialize_with = "some",
        skip_serializing_if = "Option::is_none"
    )]
    pub membership_visibility: Option<Visibility>,
    /// A new allow list, replacing the old one. Entries are actors.
    #[serde(
        default,
        deserialize_with = "some",
        skip_serializing_if = "Option::is_none"
    )]
    pub allow_list: Option<Vec<String>>,
    /// A new deny list, replacing the old one. Entries are actors.
    #[serde(
        default,
        deserialize_with = "some",
        skip_serializing_if = "Option::is_none"
    )]
    pub deny_list: Option<Vec<String>>,
    /// New extension data, replacing the old list.
    #[serde(
        default,
        deserialize_with = "some",
        skip_serializing_if = "Option::is_none"
    )]
    pub metadata: Option<Vec<MetadataObject>>,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn unknown_fields_are_ignored() {
        let p: PrivacyUpdate = serde_json::from_value(json!({"x": true})).unwrap();
        assert_eq!(p, PrivacyUpdate::default());
    }

    #[test]
    fn null_is_refused_where_it_means_nothing() {
        assert!(serde_json::from_value::<PrivacyUpdate>(json!({"allowList": null})).is_err());
        let away_null = json!({"availability": "away", "status": null});
        assert!(serde_json::from_value::<PresenceUpdate>(away_null).is_err());
    }

    #[test]
    fn requests_refuse_values_a_client_cannot_set() {
        let offline = json!({"availability": "offline"});
        assert!(serde_json::from_value::<PresenceUpdate>(offline).is_err());
        let unknown = json!({"presenceVisibility": "friendsOfFriends"});
        assert!(serde_json::from_value::<PrivacyUpdate>(unknown).is_err());
    }

    #[test]
    fn answers_keep_values_this_version_does_not_know() {
        let p: Presence = serde_json::from_value(json!({"availability": "busy"})).unwrap();
        assert_eq!(p.availability, Availability::Other("busy".into()));
    }

    #[test]
    fn closed_and_open_forms_agree_on_spellings() {
        for v in [
            Visibility::Public,
            Visibility::Authenticated,
            Visibility::SharedGroups,
            Visibility::Contacts,
            Visibility::Nobody,
        ] {
            assert_eq!(serde_json::to_value(v).unwrap(), json!(v.as_str()));
            assert_eq!(Visibility::parse(v.as_str()), Some(v));
            assert!(VisibilityPolicy::from(v).is_known());
        }
        assert_eq!(Visibility::parse("shared_groups"), None);
        for a in [
            SetAvailability::Online,
            SetAvailability::Away,
            SetAvailability::Dnd,
        ] {
            assert_eq!(serde_json::to_value(a).unwrap(), json!(a.as_str()));
            assert_eq!(SetAvailability::parse(a.as_str()), Some(a));
            assert_eq!(Availability::from(a).as_str(), a.as_str());
        }
    }
}
