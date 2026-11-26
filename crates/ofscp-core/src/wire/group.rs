//! Groups, channels, roles and permissions (spec §5.2, §5.5).

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use super::{Membership, MessageType, MetadataObject, Tier, Timestamp, open_enum};
use crate::{Actor, LocalId};

/// A role's name within a group, such as `owner`, `admin`, `member`,
/// `moderator` or `guest`. Groups may define their own (§5.2).
pub type Role = String;

open_enum! {
    /// How people join a group (§5.7). A private group is invite-only,
    /// whatever this says (§5.2).
    pub enum JoinPolicy {
        /// Anyone who can see it may join.
        Open = "open",
        /// People ask, and a manager approves.
        Request = "request",
        /// Only with an invite.
        Invite = "invite",
    }
}

open_enum! {
    /// A channel's kind. Forums and blogs are text channels with
    /// particular permissions, not kinds of their own (§5.2).
    pub enum ChannelType {
        /// Messages, memos and articles.
        Text = "text",
        /// A voice or video call (§9).
        Call = "call",
    }
}

/// A role the group defines, with how to show it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleDefinition {
    /// The role's name.
    pub name: Role,
    /// A label to show instead of the name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// A colour to show it in, such as `#9837be`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
}

/// The extra entries of a permission map: each kept if it is a list of role
/// names, ignored otherwise, so one entry a newer provider shapes
/// differently cannot make the group or channel unreadable (§2.3).
fn role_lists<'de, D: Deserializer<'de>>(d: D) -> Result<BTreeMap<String, Vec<Role>>, D::Error> {
    let entries = BTreeMap::<String, Value>::deserialize(d)?;
    Ok(entries
        .into_iter()
        .filter_map(|(action, roles)| Some((action, serde_json::from_value(roles).ok()?)))
        .collect())
}

/// Which roles may do what across a group (§5.2).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupPermissions {
    /// Who may post.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post: Option<Vec<Role>>,
    /// Who may moderate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub moderate: Option<Vec<Role>>,
    /// Who may manage the group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manage: Option<Vec<Role>>,
    /// Other actions, by name. An entry whose value is not a list of role
    /// names is dropped (§2.3), never the whole object.
    #[serde(flatten, deserialize_with = "role_lists")]
    pub other: BTreeMap<String, Vec<Role>>,
}

/// Which roles may do what in one channel (§5.2.1).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelPermissions {
    /// Who may read it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view: Option<Vec<Role>>,
    /// Who may post chat messages.
    #[serde(
        default,
        rename = "post:message",
        skip_serializing_if = "Option::is_none"
    )]
    pub post_message: Option<Vec<Role>>,
    /// Who may post memos.
    #[serde(default, rename = "post:memo", skip_serializing_if = "Option::is_none")]
    pub post_memo: Option<Vec<Role>>,
    /// Who may post articles.
    #[serde(
        default,
        rename = "post:article",
        skip_serializing_if = "Option::is_none"
    )]
    pub post_article: Option<Vec<Role>>,
    /// Who may react.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub react: Option<Vec<Role>>,
    /// Roles that may only reply.
    #[serde(default, rename = "replyOnly", skip_serializing_if = "Option::is_none")]
    pub reply_only: Option<Vec<Role>>,
    /// The message types reply-only roles may reply to.
    #[serde(
        default,
        rename = "replyOnlyTo",
        skip_serializing_if = "Option::is_none"
    )]
    pub reply_only_to: Option<Vec<MessageType>>,
    /// Other actions, by name. An entry whose value is not a list of role
    /// names is dropped (§2.3), never the whole object.
    #[serde(flatten, deserialize_with = "role_lists")]
    pub other: BTreeMap<String, Vec<Role>>,
}

/// A group (§5.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Group {
    /// The group's local id.
    pub id: LocalId,
    /// Its name.
    pub name: String,
    /// What it is for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Who owns it.
    pub owner: Actor,
    /// How people join.
    pub join_policy: JoinPolicy,
    /// Who may see it.
    pub tier: Tier,
    /// Which roles may do what.
    pub permissions: GroupPermissions,
    /// The roles it defines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<RoleDefinition>>,
    /// The caller's own membership, in an answer to a signed member only
    /// (§5.5). Such an answer must not be publicly cacheable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership: Option<Membership>,
    /// When it was made.
    pub created_at: Timestamp,
    /// When it last changed.
    pub updated_at: Timestamp,
    /// Extension data.
    #[serde(default)]
    pub metadata: Vec<MetadataObject>,
}

/// `POST /api/groups` (§5.5).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupCreateRequest {
    /// Its name.
    pub name: String,
    /// What it is for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Who may see it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<Tier>,
    /// How people join.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub join_policy: Option<JoinPolicy>,
    /// Which roles may do what.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<GroupPermissions>,
    /// The roles it defines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<RoleDefinition>>,
    /// Extension data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Vec<MetadataObject>>,
}

/// `PATCH /api/groups/{groupId}` (§5.5). Fields left `None` are unchanged.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupUpdateRequest {
    /// Its name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// What it is for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Who may see it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<Tier>,
    /// How people join.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub join_policy: Option<JoinPolicy>,
    /// Which roles may do what.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<GroupPermissions>,
    /// The roles it defines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<RoleDefinition>>,
    /// Extension data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Vec<MetadataObject>>,
}

/// Whether a call channel has a call going (§9.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallSummary {
    /// Whether a call is active.
    pub active: bool,
    /// Who is in it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub participants: Option<Vec<Actor>>,
}

/// A channel in a group (§5.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Channel {
    /// The channel's local id.
    pub id: LocalId,
    /// Its group's local id.
    pub group_id: LocalId,
    /// Its name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Its kind.
    #[serde(rename = "type")]
    pub kind: ChannelType,
    /// Who may see it.
    pub tier: Tier,
    /// What it is about.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    /// Tags.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    /// Which roles may do what here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<ChannelPermissions>,
    /// The call, for a call channel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call: Option<CallSummary>,
    /// When it was made.
    pub created_at: Timestamp,
    /// When it last changed.
    pub updated_at: Timestamp,
    /// Extension data.
    #[serde(default)]
    pub metadata: Vec<MetadataObject>,
}

/// `POST /api/groups/{groupId}/channels` (§5.5).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelCreateRequest {
    /// Its name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Its kind.
    #[serde(rename = "type")]
    pub kind: ChannelType,
    /// Who may see it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<Tier>,
    /// What it is about.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    /// Tags.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    /// Which roles may do what here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<ChannelPermissions>,
    /// Extension data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Vec<MetadataObject>>,
}

/// `PATCH /api/groups/{groupId}/channels/{channelId}` (§5.5). Fields left
/// `None` are unchanged; a channel's kind cannot change.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ChannelUpdateRequest {
    /// Its name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Who may see it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<Tier>,
    /// What it is about.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    /// Tags.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    /// Which roles may do what here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<ChannelPermissions>,
    /// Extension data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Vec<MetadataObject>>,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn ill_typed_extra_permissions_are_ignored_not_fatal() {
        let p: GroupPermissions = serde_json::from_value(json!({
            "post": ["member"],
            "invite": ["admin"],
            "future": {"roles": ["admin"]},
            "count": 3
        }))
        .unwrap();
        assert_eq!(p.post, Some(vec!["member".to_owned()]));
        assert_eq!(p.other.len(), 1);
        assert_eq!(p.other["invite"], vec!["admin".to_owned()]);

        let c: ChannelPermissions = serde_json::from_value(json!({
            "view": ["member"],
            "post:message": ["member"],
            "pin": ["moderator"],
            "slowMode": 30
        }))
        .unwrap();
        assert_eq!(c.view, Some(vec!["member".to_owned()]));
        assert_eq!(c.post_message, Some(vec!["member".to_owned()]));
        assert_eq!(c.other.keys().collect::<Vec<_>>(), ["pin"]);
    }
}
