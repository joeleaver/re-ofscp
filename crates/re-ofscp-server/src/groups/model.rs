//! Groups and channels as this provider stores them, and how requests turn
//! into stored state (§5.2, §5.5).
//!
//! Scalar fields the server queries or decides on (`tier`, `join_policy`,
//! `owner`, `kind`) are their own columns; the rest of each object (its
//! description or topic, permission map, role catalogue, tags, metadata) is
//! one JSON document column, written and read whole (docs/decisions/0014).

use re_ofscp_types::Actor;
use re_ofscp_types::groups::{
    Channel, ChannelCreateRequest, ChannelType, ChannelUpdateRequest, Group, GroupCreateRequest,
    GroupUpdateRequest, JoinPolicy, MetadataObject, PermissionMap, RoleDefinition, Tier,
};
use serde::{Deserialize, Serialize};

use super::access::{ChannelPolicy, GroupPolicy, effective_permissions};
use super::validate::{self, Invalid};

/// The tier of a group created without one (§5.5 RECOMMENDED).
pub const DEFAULT_GROUP_TIER: Tier = Tier::Private;
/// The join policy of a group created without one (§5.5 RECOMMENDED).
pub const DEFAULT_JOIN_POLICY: JoinPolicy = JoinPolicy::Invite;
/// The tier of a channel created without one: members only, the
/// conservative choice (docs/decisions/0014).
pub const DEFAULT_CHANNEL_TIER: Tier = Tier::Private;

/// The group fields kept in its JSON document column.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct GroupDoc {
    /// Description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The permission map as the owner or a manager set it; the effective
    /// map (defaults filled in) is derived on every read.
    #[serde(default)]
    pub permissions: PermissionMap,
    /// Role catalogue.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<RoleDefinition>>,
    /// Metadata objects.
    #[serde(default)]
    pub metadata: Vec<MetadataObject>,
}

/// A group, as stored.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredGroup {
    /// Local id (`grp_…`).
    pub id: String,
    /// The owner.
    pub owner: Actor,
    /// Name.
    pub name: String,
    /// Tier.
    pub tier: Tier,
    /// Stored join policy.
    pub join_policy: JoinPolicy,
    /// Optimistic-concurrency revision, bumped by every update.
    pub revision: i64,
    /// The JSON-document fields.
    pub doc: GroupDoc,
    /// RFC 3339 creation time.
    pub created_at: String,
    /// RFC 3339 time of the last change.
    pub updated_at: String,
}

impl StoredGroup {
    /// What access decisions need.
    pub fn policy(&self) -> GroupPolicy {
        GroupPolicy::new(
            self.tier,
            self.join_policy,
            self.doc.permissions.clone(),
            self.doc.roles.as_deref(),
        )
    }

    /// The canonical `Group` object (§5.2).
    pub fn to_wire(&self) -> Group {
        Group {
            id: self.id.clone(),
            name: self.name.clone(),
            description: self.doc.description.clone(),
            owner: self.owner.to_string(),
            join_policy: self.join_policy,
            tier: self.tier,
            permissions: effective_permissions(self.doc.permissions.clone()),
            roles: self.doc.roles.clone(),
            created_at: self.created_at.clone(),
            updated_at: self.updated_at.clone(),
            metadata: self.doc.metadata.clone(),
        }
    }
}

/// The scalar and document fields of a group about to be written.
#[derive(Debug, Clone, PartialEq)]
pub struct GroupFields {
    /// Name.
    pub name: String,
    /// Tier.
    pub tier: Tier,
    /// Join policy.
    pub join_policy: JoinPolicy,
    /// Document fields.
    pub doc: GroupDoc,
}

fn check_group_doc(doc: &GroupDoc) -> Result<(), Invalid> {
    if let Some(d) = &doc.description {
        validate::description(d)?;
    }
    validate::group_permissions(&doc.permissions)?;
    if let Some(r) = &doc.roles {
        validate::roles(r)?;
    }
    validate::metadata(&doc.metadata)
}

/// A new group's fields, defaults applied (§5.5).
pub fn new_group(req: GroupCreateRequest) -> Result<GroupFields, Invalid> {
    validate::name(&req.name)?;
    let doc = GroupDoc {
        description: req.description,
        permissions: req.permissions.unwrap_or_default(),
        roles: req.roles,
        metadata: req.metadata.unwrap_or_default(),
    };
    check_group_doc(&doc)?;
    Ok(GroupFields {
        name: req.name,
        tier: req.tier.unwrap_or(DEFAULT_GROUP_TIER),
        join_policy: req.join_policy.unwrap_or(DEFAULT_JOIN_POLICY),
        doc,
    })
}

/// `group` with `patch` applied, or `None` when the patch changes nothing.
/// Omitted fields are unchanged (§5.5).
pub fn patch_group(
    group: &StoredGroup,
    patch: &GroupUpdateRequest,
) -> Result<Option<GroupFields>, Invalid> {
    let mut next = GroupFields {
        name: group.name.clone(),
        tier: group.tier,
        join_policy: group.join_policy,
        doc: group.doc.clone(),
    };
    if let Some(name) = &patch.name {
        validate::name(name)?;
        next.name = name.clone();
    }
    if let Some(d) = &patch.description {
        next.doc.description = Some(d.clone());
    }
    if let Some(t) = patch.tier {
        next.tier = t;
    }
    if let Some(p) = patch.join_policy {
        next.join_policy = p;
    }
    if let Some(p) = &patch.permissions {
        next.doc.permissions = p.clone();
    }
    if let Some(r) = &patch.roles {
        next.doc.roles = Some(r.clone());
    }
    if let Some(m) = &patch.metadata {
        next.doc.metadata = m.clone();
    }
    check_group_doc(&next.doc)?;
    let unchanged = next.name == group.name
        && next.tier == group.tier
        && next.join_policy == group.join_policy
        && next.doc == group.doc;
    Ok((!unchanged).then_some(next))
}

/// The channel fields kept in its JSON document column.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ChannelDoc {
    /// Name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Topic.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    /// Tags.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    /// Per-channel permissions (§5.2.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<PermissionMap>,
    /// Metadata objects.
    #[serde(default)]
    pub metadata: Vec<MetadataObject>,
}

/// A channel, as stored.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredChannel {
    /// Local id (`chn_…`).
    pub id: String,
    /// The parent group's local id.
    pub group_id: String,
    /// Type; immutable.
    pub kind: ChannelType,
    /// Tier.
    pub tier: Tier,
    /// Optimistic-concurrency revision.
    pub revision: i64,
    /// The JSON-document fields.
    pub doc: ChannelDoc,
    /// RFC 3339 creation time.
    pub created_at: String,
    /// RFC 3339 time of the last change.
    pub updated_at: String,
}

impl StoredChannel {
    /// What access decisions need.
    pub fn policy(&self) -> ChannelPolicy {
        ChannelPolicy {
            tier: self.tier,
            permissions: self.doc.permissions.clone(),
        }
    }

    /// The canonical `Channel` object (§5.2).
    pub fn to_wire(&self) -> Channel {
        Channel {
            id: self.id.clone(),
            group_id: self.group_id.clone(),
            name: self.doc.name.clone(),
            kind: self.kind,
            tier: self.tier,
            topic: self.doc.topic.clone(),
            tags: self.doc.tags.clone(),
            permissions: self.doc.permissions.clone(),
            created_at: self.created_at.clone(),
            updated_at: self.updated_at.clone(),
            metadata: self.doc.metadata.clone(),
        }
    }
}

/// The scalar and document fields of a channel about to be written.
#[derive(Debug, Clone, PartialEq)]
pub struct ChannelFields {
    /// Tier.
    pub tier: Tier,
    /// Document fields.
    pub doc: ChannelDoc,
}

fn check_channel_doc(doc: &ChannelDoc) -> Result<(), Invalid> {
    if let Some(n) = &doc.name {
        validate::name(n)?;
    }
    if let Some(t) = &doc.topic {
        validate::topic(t)?;
    }
    if let Some(t) = &doc.tags {
        validate::tags(t)?;
    }
    if let Some(p) = &doc.permissions {
        validate::channel_permissions(p)?;
    }
    validate::metadata(&doc.metadata)
}

/// A new channel's type and fields, defaults applied.
pub fn new_channel(req: ChannelCreateRequest) -> Result<(ChannelType, ChannelFields), Invalid> {
    let doc = ChannelDoc {
        name: req.name,
        topic: req.topic,
        tags: req.tags,
        permissions: req.permissions,
        metadata: req.metadata.unwrap_or_default(),
    };
    check_channel_doc(&doc)?;
    Ok((
        req.kind,
        ChannelFields {
            tier: req.tier.unwrap_or(DEFAULT_CHANNEL_TIER),
            doc,
        },
    ))
}

/// `channel` with `patch` applied, or `None` when it changes nothing.
/// `type` may be repeated unchanged; a different one is refused (§5.2).
pub fn patch_channel(
    channel: &StoredChannel,
    patch: &ChannelUpdateRequest,
) -> Result<Option<ChannelFields>, Invalid> {
    if patch.kind.is_some_and(|k| k != channel.kind) {
        return Err(Invalid("a channel's `type` cannot be changed".to_owned()));
    }
    let mut next = ChannelFields {
        tier: channel.tier,
        doc: channel.doc.clone(),
    };
    if let Some(n) = &patch.name {
        next.doc.name = Some(n.clone());
    }
    if let Some(t) = patch.tier {
        next.tier = t;
    }
    if let Some(t) = &patch.topic {
        next.doc.topic = Some(t.clone());
    }
    if let Some(t) = &patch.tags {
        next.doc.tags = Some(t.clone());
    }
    if let Some(p) = &patch.permissions {
        next.doc.permissions = Some(p.clone());
    }
    if let Some(m) = &patch.metadata {
        next.doc.metadata = m.clone();
    }
    check_channel_doc(&next.doc)?;
    let unchanged = next.tier == channel.tier && next.doc == channel.doc;
    Ok((!unchanged).then_some(next))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored() -> StoredGroup {
        let f = new_group(GroupCreateRequest {
            name: "Dev Guild".into(),
            ..Default::default()
        })
        .unwrap();
        StoredGroup {
            id: "grp_x".into(),
            owner: Actor::parse_canonical("alice@providera.com").unwrap(),
            name: f.name,
            tier: f.tier,
            join_policy: f.join_policy,
            revision: 0,
            doc: f.doc,
            created_at: "2026-01-01T12:00:00Z".into(),
            updated_at: "2026-01-01T12:00:00Z".into(),
        }
    }

    #[test]
    fn defaults_are_private_and_invite_with_effective_permissions() {
        let g = stored().to_wire();
        assert_eq!(g.tier, Tier::Private);
        assert_eq!(g.join_policy, JoinPolicy::Invite);
        assert_eq!(g.permissions["post"], vec!["admin", "member"]);
        assert_eq!(g.permissions["manage"], vec!["admin"]);
        assert!(g.description.is_none());
    }

    #[test]
    fn patches_change_only_what_they_name() {
        let g = stored();
        assert_eq!(patch_group(&g, &GroupUpdateRequest::default()), Ok(None));
        let same = GroupUpdateRequest {
            name: Some("Dev Guild".into()),
            ..Default::default()
        };
        assert_eq!(patch_group(&g, &same), Ok(None));
        let p = GroupUpdateRequest {
            tier: Some(Tier::Public),
            description: Some("d".into()),
            ..Default::default()
        };
        let next = patch_group(&g, &p).unwrap().unwrap();
        assert_eq!(next.tier, Tier::Public);
        assert_eq!(next.name, "Dev Guild");
        assert_eq!(next.join_policy, JoinPolicy::Invite);
        assert_eq!(next.doc.description.as_deref(), Some("d"));
        let blank = GroupUpdateRequest {
            name: Some(" ".into()),
            ..Default::default()
        };
        assert!(patch_group(&g, &blank).is_err());
    }

    #[test]
    fn a_channel_type_is_immutable() {
        let (kind, f) = new_channel(ChannelCreateRequest {
            name: Some("general".into()),
            kind: ChannelType::Text,
            tier: None,
            topic: None,
            tags: None,
            permissions: None,
            metadata: None,
        })
        .unwrap();
        assert_eq!(f.tier, DEFAULT_CHANNEL_TIER);
        let c = StoredChannel {
            id: "chn_x".into(),
            group_id: "grp_x".into(),
            kind,
            tier: f.tier,
            revision: 0,
            doc: f.doc,
            created_at: String::new(),
            updated_at: String::new(),
        };
        let same = ChannelUpdateRequest {
            kind: Some(ChannelType::Text),
            ..Default::default()
        };
        assert_eq!(patch_channel(&c, &same), Ok(None));
        let other = ChannelUpdateRequest {
            kind: Some(ChannelType::Call),
            ..Default::default()
        };
        assert!(patch_channel(&c, &other).is_err());
    }
}
