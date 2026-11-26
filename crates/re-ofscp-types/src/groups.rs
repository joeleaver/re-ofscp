//! Group and channel payloads (spec §5.2, §5.5, §11).
//!
//! Field names are camelCase (§2.5). Request fields are all optional except
//! where the spec requires them, and an explicit `null` is refused rather
//! than read as "absent": the schemas give every field a non-null type, and a
//! PATCH must not confuse "leave unchanged" with "clear".

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

/// An action → roles map (§5.2 `permissions`, §5.2.1 channel `permissions`).
/// A role may perform an action iff it is listed; there is no inheritance.
pub type PermissionMap = BTreeMap<String, Vec<String>>;

/// A metadata object (§5.4): `{ schema, version, data }`, kept as JSON so
/// unknown members survive a round trip. The server validates its shape.
pub type MetadataObject = Map<String, Value>;

/// An access/discoverability tier (§11). These are the canonical tiers;
/// this provider defines no others, so a request naming any other tier is
/// refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    /// Members only; joining is by invite only, whatever `joinPolicy` says.
    Private,
    /// Members only; joining follows `joinPolicy`.
    Group,
    /// Anyone may read, including unauthenticated callers.
    Public,
    /// As `public`, and may be surfaced by recommendations (§11.2).
    Discoverable,
}

impl Tier {
    /// Every tier, in the order `GET /api/tiers` lists them.
    pub const ALL: [Tier; 4] = [Tier::Private, Tier::Group, Tier::Public, Tier::Discoverable];

    /// The wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Private => "private",
            Tier::Group => "group",
            Tier::Public => "public",
            Tier::Discoverable => "discoverable",
        }
    }

    /// The tier spelled `s`, if it is one this provider defines.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.as_str() == s)
    }
}

/// Who may join a group (§5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JoinPolicy {
    /// Anyone may join.
    Open,
    /// Joining needs approval.
    Request,
    /// Invitation only.
    Invite,
}

impl JoinPolicy {
    /// The wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            JoinPolicy::Open => "open",
            JoinPolicy::Request => "request",
            JoinPolicy::Invite => "invite",
        }
    }

    /// The policy spelled `s`.
    pub fn parse(s: &str) -> Option<Self> {
        [JoinPolicy::Open, JoinPolicy::Request, JoinPolicy::Invite]
            .into_iter()
            .find(|p| p.as_str() == s)
    }
}

/// A channel's type (§5.2). Immutable after creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChannelType {
    /// Text messaging.
    Text,
    /// Real-time calls (§9).
    Call,
}

impl ChannelType {
    /// The wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            ChannelType::Text => "text",
            ChannelType::Call => "call",
        }
    }

    /// The type spelled `s`.
    pub fn parse(s: &str) -> Option<Self> {
        [ChannelType::Text, ChannelType::Call]
            .into_iter()
            .find(|t| t.as_str() == s)
    }
}

/// A role a group declares (§5.2 `roles`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleDefinition {
    /// The role's name.
    pub name: String,
    /// Display name; defaults to `name`.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub label: Option<String>,
    /// UI hint, e.g. a hex colour.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub color: Option<String>,
}

/// The canonical `Group` object (§5.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Group {
    /// Local id (§2.2).
    pub id: String,
    /// Name.
    pub name: String,
    /// Description, when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The owner, as a canonical actor.
    pub owner: String,
    /// The stored join policy. A `private` group is invite-only whatever
    /// this says (§11).
    pub join_policy: JoinPolicy,
    /// Tier.
    pub tier: Tier,
    /// The effective permission map, defaults filled in (§5.2).
    pub permissions: PermissionMap,
    /// The role catalogue, when the group declares one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<RoleDefinition>>,
    /// RFC 3339 creation time.
    pub created_at: String,
    /// RFC 3339 time of the last change.
    pub updated_at: String,
    /// Metadata objects (§5.4).
    pub metadata: Vec<MetadataObject>,
}

/// The canonical `Channel` object (§5.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Channel {
    /// Local id (§2.2).
    pub id: String,
    /// The parent group's local id.
    pub group_id: String,
    /// Name, when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Type; immutable.
    #[serde(rename = "type")]
    pub kind: ChannelType,
    /// Tier. It can narrow, never widen, the group's (§11.3).
    pub tier: Tier,
    /// Topic, when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    /// Tags, when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    /// Per-channel permissions (§5.2.1), when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<PermissionMap>,
    /// RFC 3339 creation time.
    pub created_at: String,
    /// RFC 3339 time of the last change.
    pub updated_at: String,
    /// Metadata objects (§5.4).
    pub metadata: Vec<MetadataObject>,
}

/// `GET /api/groups/{groupId}/channels` response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelList {
    /// The channels the caller may read.
    pub items: Vec<Channel>,
}

/// `POST /api/groups` request (§5.5).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupCreateRequest {
    /// Name (required).
    pub name: String,
    /// Description.
    #[serde(default, deserialize_with = "present")]
    pub description: Option<String>,
    /// Tier (default `private`).
    #[serde(default, deserialize_with = "present")]
    pub tier: Option<Tier>,
    /// Join policy (default `invite`).
    #[serde(default, deserialize_with = "present")]
    pub join_policy: Option<JoinPolicy>,
    /// Permissions; missing canonical actions take the defaults.
    #[serde(default, deserialize_with = "present")]
    pub permissions: Option<PermissionMap>,
    /// Role catalogue.
    #[serde(default, deserialize_with = "present")]
    pub roles: Option<Vec<RoleDefinition>>,
    /// Metadata objects.
    #[serde(default, deserialize_with = "present")]
    pub metadata: Option<Vec<MetadataObject>>,
}

/// `PATCH /api/groups/{groupId}` request (§5.5): omitted fields are
/// unchanged.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupUpdateRequest {
    /// New name.
    #[serde(default, deserialize_with = "present")]
    pub name: Option<String>,
    /// New description.
    #[serde(default, deserialize_with = "present")]
    pub description: Option<String>,
    /// New tier.
    #[serde(default, deserialize_with = "present")]
    pub tier: Option<Tier>,
    /// New join policy.
    #[serde(default, deserialize_with = "present")]
    pub join_policy: Option<JoinPolicy>,
    /// New permission map (replaces the old one; defaults fill gaps).
    #[serde(default, deserialize_with = "present")]
    pub permissions: Option<PermissionMap>,
    /// New role catalogue.
    #[serde(default, deserialize_with = "present")]
    pub roles: Option<Vec<RoleDefinition>>,
    /// New metadata.
    #[serde(default, deserialize_with = "present")]
    pub metadata: Option<Vec<MetadataObject>>,
}

/// `POST /api/groups/{groupId}/channels` request (§5.5).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelCreateRequest {
    /// Name.
    #[serde(default, deserialize_with = "present")]
    pub name: Option<String>,
    /// Type (required, immutable).
    #[serde(rename = "type")]
    pub kind: ChannelType,
    /// Tier (default `private`).
    #[serde(default, deserialize_with = "present")]
    pub tier: Option<Tier>,
    /// Topic.
    #[serde(default, deserialize_with = "present")]
    pub topic: Option<String>,
    /// Tags.
    #[serde(default, deserialize_with = "present")]
    pub tags: Option<Vec<String>>,
    /// Per-channel permissions (§5.2.1).
    #[serde(default, deserialize_with = "present")]
    pub permissions: Option<PermissionMap>,
    /// Metadata objects.
    #[serde(default, deserialize_with = "present")]
    pub metadata: Option<Vec<MetadataObject>>,
}

/// `PATCH /api/groups/{groupId}/channels/{channelId}` request (§5.5).
/// `type` may be repeated unchanged; any other value is refused.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelUpdateRequest {
    /// New name.
    #[serde(default, deserialize_with = "present")]
    pub name: Option<String>,
    /// The channel's type, if the client repeats it.
    #[serde(rename = "type", default, deserialize_with = "present")]
    pub kind: Option<ChannelType>,
    /// New tier.
    #[serde(default, deserialize_with = "present")]
    pub tier: Option<Tier>,
    /// New topic.
    #[serde(default, deserialize_with = "present")]
    pub topic: Option<String>,
    /// New tags.
    #[serde(default, deserialize_with = "present")]
    pub tags: Option<Vec<String>>,
    /// New per-channel permissions (replace the old ones).
    #[serde(default, deserialize_with = "present")]
    pub permissions: Option<PermissionMap>,
    /// New metadata.
    #[serde(default, deserialize_with = "present")]
    pub metadata: Option<Vec<MetadataObject>>,
}

/// One entry of `GET /api/tiers` (§11.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierInfo {
    /// The tier id, as `tier` fields spell it.
    pub id: String,
    /// Display name.
    pub name: String,
    /// What the tier means.
    pub description: String,
}

/// `GET /api/tiers` response (§11.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TiersResponse {
    /// The tiers this provider supports.
    pub tiers: Vec<TierInfo>,
}

/// Deserialize a field that may be absent (`#[serde(default)]` gives
/// `None`) but, when present, must hold a value: `null` is refused.
fn present<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(d).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn absent_fields_are_none_and_null_is_refused() {
        let r: GroupUpdateRequest = serde_json::from_value(json!({})).unwrap();
        assert_eq!(r, GroupUpdateRequest::default());
        let r: GroupUpdateRequest =
            serde_json::from_value(json!({"description": "d", "tier": "public"})).unwrap();
        assert_eq!(r.description.as_deref(), Some("d"));
        assert_eq!(r.tier, Some(Tier::Public));
        assert!(
            serde_json::from_value::<GroupUpdateRequest>(json!({"description": null})).is_err()
        );
        assert!(serde_json::from_value::<GroupUpdateRequest>(json!({"tier": "secret"})).is_err());
    }

    #[test]
    fn channel_type_is_required_on_create() {
        assert!(serde_json::from_value::<ChannelCreateRequest>(json!({"name": "x"})).is_err());
        let r: ChannelCreateRequest = serde_json::from_value(json!({"type": "call"})).unwrap();
        assert_eq!(r.kind, ChannelType::Call);
    }

    #[test]
    fn spellings_round_trip() {
        for t in Tier::ALL {
            assert_eq!(Tier::parse(t.as_str()), Some(t));
        }
        for p in [JoinPolicy::Open, JoinPolicy::Request, JoinPolicy::Invite] {
            assert_eq!(JoinPolicy::parse(p.as_str()), Some(p));
        }
        for c in [ChannelType::Text, ChannelType::Call] {
            assert_eq!(ChannelType::parse(c.as_str()), Some(c));
        }
        assert_eq!(Tier::parse("Private"), None);
    }

    #[test]
    fn group_serializes_camel_case() {
        let g = Group {
            id: "grp_1".into(),
            name: "n".into(),
            description: None,
            owner: "a@b.c".into(),
            join_policy: JoinPolicy::Invite,
            tier: Tier::Private,
            permissions: PermissionMap::new(),
            roles: None,
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
            metadata: vec![],
        };
        let v = serde_json::to_value(&g).unwrap();
        assert_eq!(v["joinPolicy"], "invite");
        assert!(v.get("description").is_none());
        assert_eq!(v["createdAt"], "2026-01-01T00:00:00Z");
    }
}
