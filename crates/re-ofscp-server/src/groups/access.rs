//! The one authorization rule for groups and channels (spec §5.2, §5.2.1,
//! §11, §11.3; security requirements 5 and 6).
//!
//! Every surface that exposes a group, a channel, or anything inside a
//! channel decides access here, and only here: channel listing and `GET`
//! (§5.5) today; history, replies, live subscriptions, follows, read
//! markers, notifications and discovery samples as they are built. The
//! functions are pure: they take the caller's [`Standing`] and the group's
//! and channel's [`GroupPolicy`]/[`ChannelPolicy`] as they are *now*, so a
//! live subscription re-checks access by calling [`can_read_channel`] again
//! whenever [`super::AccessChange`] reports that one of them changed, and
//! ends with `unsubscribed {reason:"access_revoked"}` when it turns false
//! (§7.1 *Losing access*).

use std::collections::BTreeSet;

use re_ofscp_types::groups::{JoinPolicy, PermissionMap, RoleDefinition, Tier};

/// The canonical roles (§5.7). They always exist, whether or not a group's
/// `roles` catalogue lists them.
pub const CANONICAL_ROLES: [&str; 4] = [roles::OWNER, roles::ADMIN, roles::MEMBER, roles::GUEST];

/// Canonical role names.
pub mod roles {
    /// The super-role: holds every permission, is never reply-restricted.
    pub const OWNER: &str = "owner";
    /// Canonical administrator role.
    pub const ADMIN: &str = "admin";
    /// Canonical member role (the default on joining).
    pub const MEMBER: &str = "member";
    /// Canonical guest role (§4.8).
    pub const GUEST: &str = "guest";
}

/// Canonical group actions (§5.2).
pub mod actions {
    /// Post messages (channel `post:<type>` falls back to it).
    pub const POST: &str = "post";
    /// Moderate (kick members, §5.7).
    pub const MODERATE: &str = "moderate";
    /// Manage the group and its channels (§5.5).
    pub const MANAGE: &str = "manage";
    /// Channel action: read the channel (§5.2.1).
    pub const VIEW: &str = "view";
    /// Channel action: add reactions (§5.2.1).
    pub const REACT: &str = "react";
    /// Channel restriction: listed roles may post replies only (§5.2.1).
    pub const REPLY_ONLY: &str = "replyOnly";
    /// Channel restriction: the message types a reply-restricted actor may
    /// reply to (§5.2.1). Its list holds message types, not roles.
    pub const REPLY_ONLY_TO: &str = "replyOnlyTo";
    /// The channel grant action for posting a message of `kind` (§5.2.1).
    pub fn post_kind(kind: &str) -> String {
        format!("post:{kind}")
    }

    /// Set another member's nickname (§5.7). No default grant: only the
    /// owner holds it unless the group lists other roles.
    pub const SET_NICKNAME: &str = "members.set-nickname";
}

/// The defaults the provider MUST use for a missing canonical action (§5.2).
pub fn default_permissions() -> [(&'static str, &'static [&'static str]); 3] {
    [
        (actions::POST, &[roles::ADMIN, roles::MEMBER]),
        (actions::MODERATE, &[roles::ADMIN]),
        (actions::MANAGE, &[roles::ADMIN]),
    ]
}

/// `permissions` with every missing canonical action given its default:
/// the effective map the `Group` object carries (§5.2).
pub fn effective_permissions(mut permissions: PermissionMap) -> PermissionMap {
    for (action, granted) in default_permissions() {
        permissions
            .entry(action.to_owned())
            .or_insert_with(|| granted.iter().map(|r| (*r).to_owned()).collect());
    }
    permissions
}

/// Where the caller stands with a group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Standing {
    /// Not a member: an unsigned request, a provider signature, or an actor
    /// without a membership.
    Outsider,
    /// A member holding `role` (never [`roles::OWNER`]: ownership is
    /// [`Standing::Owner`]).
    Member(String),
    /// The group's owner.
    Owner,
}

impl Standing {
    /// Whether the caller belongs to the group (owner included).
    pub fn is_member(&self) -> bool {
        !matches!(self, Standing::Outsider)
    }
}

/// What access decisions need to know about a group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupPolicy {
    /// The group's tier.
    pub tier: Tier,
    /// The stored join policy.
    pub join_policy: JoinPolicy,
    /// The effective permission map (defaults filled in).
    pub permissions: PermissionMap,
    /// The custom roles the group declares (canonical roles always exist).
    pub catalogue: Vec<String>,
}

impl GroupPolicy {
    /// A policy from the group's stored fields.
    pub fn new(
        tier: Tier,
        join_policy: JoinPolicy,
        permissions: PermissionMap,
        roles: Option<&[RoleDefinition]>,
    ) -> Self {
        Self {
            tier,
            join_policy,
            permissions: effective_permissions(permissions),
            catalogue: roles
                .unwrap_or_default()
                .iter()
                .map(|r| r.name.clone())
                .collect(),
        }
    }

    /// Whether `role` exists in this group. A role that is neither
    /// canonical nor catalogued holds no permissions (§5.2: it fails
    /// closed).
    pub fn knows_role(&self, role: &str) -> bool {
        CANONICAL_ROLES.contains(&role) || self.catalogue.iter().any(|r| r == role)
    }
}

/// What access decisions need to know about a channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelPolicy {
    /// The channel's tier.
    pub tier: Tier,
    /// Per-channel permissions (§5.2.1), when set.
    pub permissions: Option<PermissionMap>,
}

/// Whether `tier` lets anyone, members or not, read.
fn open_to_anyone(tier: Tier) -> bool {
    match tier {
        Tier::Public | Tier::Discoverable => true,
        Tier::Private | Tier::Group => false,
    }
}

/// Whether a role listed in `listed` grants the caller an exact-membership
/// action (§5.2): the owner always; a member iff their role is listed and
/// known to the group; an outsider never. A membership claiming the role
/// `owner` holds nothing: only [`Standing::Owner`] is the owner (memberships
/// refuse that role, and this keeps a bad row from mattering).
fn granted(standing: &Standing, group: &GroupPolicy, listed: Option<&Vec<String>>) -> bool {
    match standing {
        Standing::Owner => true,
        Standing::Outsider => false,
        Standing::Member(role) => {
            role != roles::OWNER
                && group.knows_role(role)
                && listed.is_some_and(|roles| roles.iter().any(|r| r == role))
        }
    }
}

/// Whether the caller may perform group `action` (§5.2): the owner always,
/// otherwise iff their role is listed for it. Reading never implies
/// posting: outsiders hold no action (§11).
pub fn may(standing: &Standing, group: &GroupPolicy, action: &str) -> bool {
    granted(standing, group, group.permissions.get(action))
}

/// Whether the caller may read the group (§5.5 `GET`, §11.3 rule 1).
pub fn can_read_group(standing: &Standing, group: &GroupPolicy) -> bool {
    open_to_anyone(group.tier) || standing.is_member()
}

/// Effective read access to a channel (§11.3): the group's tier, the
/// channel's tier and, when present, the channel's `view` list must *all*
/// admit the caller. A channel's tier narrows, never widens, its group's.
pub fn can_read_channel(standing: &Standing, group: &GroupPolicy, channel: &ChannelPolicy) -> bool {
    if !can_read_group(standing, group) {
        return false;
    }
    if !(open_to_anyone(channel.tier) || standing.is_member()) {
        return false;
    }
    match channel
        .permissions
        .as_ref()
        .and_then(|p| p.get(actions::VIEW))
    {
        // `view` admits exactly the listed roles (owner always) and so
        // overrides the channel tier (§5.2.1); outsiders hold no role.
        Some(view) => granted(standing, group, Some(view)),
        None => true,
    }
}

/// The channel's own entry for `action`, if its permission map has one.
fn channel_entry<'a>(channel: &'a ChannelPolicy, action: &str) -> Option<&'a Vec<String>> {
    channel.permissions.as_ref().and_then(|p| p.get(action))
}

/// Whether the caller may post a message of type `kind` (`message`, `memo`
/// or `article`) in the channel (§5.2.1): the channel's `post:<kind>` when
/// it lists one, otherwise the group's `post`. It answers only the grant;
/// read access is checked first, and an unreadable channel is `404`, never
/// `403` (§5.2.1).
pub fn may_post(
    standing: &Standing,
    group: &GroupPolicy,
    channel: &ChannelPolicy,
    kind: &str,
) -> bool {
    match channel_entry(channel, &actions::post_kind(kind)) {
        Some(listed) => granted(standing, group, Some(listed)),
        None => may(standing, group, actions::POST),
    }
}

/// Whether the caller holds a `post:<type>` grant for *some* type in the
/// channel, custom types included (§7.1 typing; lost-conn/ofscp#37). Types
/// are open-ended and an unlisted one falls back to the group's `post`
/// ([`may_post`]), so this is the group's `post` or any `post:<type>`
/// entry of the channel that grants. Read access is checked first.
pub fn may_post_any(standing: &Standing, group: &GroupPolicy, channel: &ChannelPolicy) -> bool {
    let prefix = actions::post_kind("");
    may(standing, group, actions::POST)
        || channel
            .permissions
            .iter()
            .flatten()
            .any(|(action, listed)| {
                action.starts_with(&prefix) && granted(standing, group, Some(listed))
            })
}

/// Whether the caller may add reactions in the channel (§5.2.1): the
/// channel's `react` when listed, otherwise anyone who may read the
/// channel (the caller has already passed [`can_read_channel`]).
pub fn may_react(standing: &Standing, group: &GroupPolicy, channel: &ChannelPolicy) -> bool {
    match channel_entry(channel, actions::REACT) {
        Some(listed) => granted(standing, group, Some(listed)),
        None => true,
    }
}

/// What a reply-restricted caller may post (§5.2.1 `replyOnly`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplyRule {
    /// Not restricted: top-level posts and replies alike.
    Free,
    /// Replies only; when `to` is set, only to parents of those types.
    RepliesOnly {
        /// `replyOnlyTo`, when the channel lists it.
        to: Option<Vec<String>>,
    },
}

/// Whether the caller is reply-restricted in the channel: a member whose
/// role (known to the group) is listed in `replyOnly`. The owner never is,
/// and an outsider holds no role (§5.2.1).
pub fn reply_rule(standing: &Standing, group: &GroupPolicy, channel: &ChannelPolicy) -> ReplyRule {
    let restricted = match standing {
        Standing::Member(role) => {
            group.knows_role(role)
                && channel_entry(channel, actions::REPLY_ONLY)
                    .is_some_and(|roles| roles.iter().any(|r| r == role))
        }
        Standing::Owner | Standing::Outsider => false,
    };
    if restricted {
        ReplyRule::RepliesOnly {
            to: channel_entry(channel, actions::REPLY_ONLY_TO).cloned(),
        }
    } else {
        ReplyRule::Free
    }
}

/// A role's permission set (§5.7): the group actions it is listed for, or
/// every permission for the owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Perms {
    /// The owner's: every permission, including any not yet defined.
    All,
    /// Exactly these group actions.
    Only(BTreeSet<String>),
}

impl Perms {
    /// Whether every permission in `self` is also in `other`.
    pub fn is_subset_of(&self, other: &Perms) -> bool {
        match (self, other) {
            (_, Perms::All) => true,
            (Perms::All, Perms::Only(_)) => false,
            (Perms::Only(a), Perms::Only(b)) => a.is_subset(b),
        }
    }
}

/// `perms(role)` (§5.7): the actions of the group's effective permission
/// map that list `role`. `owner` holds every permission. A role neither
/// canonical nor catalogued holds none (§5.2: it fails closed), so acting
/// on it, or granting it, never needs more than the caller has.
pub fn role_perms(role: &str, group: &GroupPolicy) -> Perms {
    if role == roles::OWNER {
        return Perms::All;
    }
    if !group.knows_role(role) {
        return Perms::Only(BTreeSet::new());
    }
    Perms::Only(
        group
            .permissions
            .iter()
            .filter(|(_, listed)| listed.iter().any(|r| r == role))
            .map(|(action, _)| action.clone())
            .collect(),
    )
}

/// The caller's permission set: the owner's is every permission, a
/// member's is their role's, an outsider's is empty. A membership row
/// claiming the role `owner` holds nothing, as in [`may`].
pub fn standing_perms(standing: &Standing, group: &GroupPolicy) -> Perms {
    match standing {
        Standing::Owner => Perms::All,
        Standing::Member(role) if role != roles::OWNER => role_perms(role, group),
        Standing::Member(_) | Standing::Outsider => Perms::Only(BTreeSet::new()),
    }
}

/// The subset (self-protect) rule (§5.7): the caller may act on a member
/// holding `target_role`, or grant that role, only when
/// `perms(target_role) ⊆ perms(caller)`. So the owner may act on anyone,
/// and nobody else may act on the owner.
pub fn may_act_on(caller: &Standing, target_role: &str, group: &GroupPolicy) -> bool {
    role_perms(target_role, group).is_subset_of(&standing_perms(caller, group))
}

/// How a join request is to be treated (§5.7), once membership exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinGate {
    /// The caller becomes a member at once.
    Open,
    /// A pending request is recorded.
    Request,
    /// Refused with `403`: only an invite (§5.6) admits.
    InviteOnly,
}

/// The join gate for a group: its `joinPolicy`, except that a `private`
/// group is invite-only whatever its stored policy (§11, security
/// requirement 6).
pub fn join_gate(group: &GroupPolicy) -> JoinGate {
    if group.tier == Tier::Private {
        return JoinGate::InviteOnly;
    }
    match group.join_policy {
        JoinPolicy::Open => JoinGate::Open,
        JoinPolicy::Request => JoinGate::Request,
        JoinPolicy::Invite => JoinGate::InviteOnly,
    }
}

#[cfg(test)]
#[path = "access_tests.rs"]
mod tests;
