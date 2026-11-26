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
/// known to the group; an outsider never.
fn granted(standing: &Standing, group: &GroupPolicy, listed: Option<&Vec<String>>) -> bool {
    match standing {
        Standing::Owner => true,
        Standing::Outsider => false,
        Standing::Member(role) => {
            group.knows_role(role) && listed.is_some_and(|roles| roles.iter().any(|r| r == role))
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
