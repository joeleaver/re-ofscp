//! The shared visibility policy (spec §6.1) and the relationships it
//! depends on.
//!
//! Every surface that shows presence, profile extras or group memberships
//! asks [`Policy::admits`] whether a [`Viewer`] may see a subject's data.
//! Identity is always `(handle, domain)` (security requirement 1): a remote
//! `alice@b.com` never matches local `alice`, in the allow and deny lists
//! as in every tier. Settled in lost-conn/ofscp#26: anonymous viewers
//! satisfy only `public`, `allowList` overrides even `nobody`, `denyList`
//! even `public`, and the lists never match an anonymous viewer.
//!
//! The `sharedGroups` and `contacts` tiers depend on state other modules
//! own, reached through two seams, [`GroupMemberships`] and [`Contacts`].
//! The app answers group memberships from its groups (`groups::Groups`,
//! docs/decisions/0014). Until contacts (§6.7) exist on this provider, the
//! contacts seam is [`NoContacts`]: it answers truthfully that no one is a
//! contact, so that tier admits only the subject and the allow list
//! (docs/decisions/0009). [`NoGroupsHosted`] stays the default of a bare
//! [`Relationships`].

pub mod seams;

use re_ofscp_types::profile::Visibility;
use re_ofscp_types::{Actor, Authority};

use crate::signing::{Signer, Verified};

pub use seams::{
    Contacts, GroupMemberships, Liveness, NoConnections, NoContacts, NoGroupsHosted, RelError,
    Relationships,
};

/// Who is asking to see a subject's data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Viewer {
    /// An unsigned request: satisfies only `public`.
    Anonymous,
    /// A provider signature (§8.1). Authenticated, but not a user, so it
    /// satisfies only `public`.
    Provider(Authority),
    /// A user, local or remote, by `(handle, domain)`.
    Actor(Actor),
}

impl Viewer {
    /// The viewer behind a verified request, or [`Viewer::Anonymous`].
    pub fn from_verified(verified: Option<&Verified>) -> Self {
        match verified.map(|v| &v.signer) {
            None => Self::Anonymous,
            Some(Signer::Provider(p)) => Self::Provider(p.clone()),
            Some(Signer::Actor(a)) => Self::Actor(a.clone()),
        }
    }

    /// The viewing user, if a user is viewing.
    pub fn actor(&self) -> Option<&Actor> {
        match self {
            Self::Actor(a) => Some(a),
            Self::Anonymous | Self::Provider(_) => None,
        }
    }
}

/// One of a subject's visibility settings, with the allow and deny lists
/// that override it (§6.1, §6.6).
#[derive(Debug, Clone, Copy)]
pub struct Policy<'a> {
    /// The tier.
    pub visibility: Visibility,
    /// Actors always admitted.
    pub allow: &'a [Actor],
    /// Actors always refused. Checked before the allow list.
    pub deny: &'a [Actor],
}

impl Policy<'_> {
    /// Whether `viewer` may see `subject`'s data under this policy.
    ///
    /// In order: the subject always sees their own data (even under
    /// `nobody`); then the deny list refuses and the allow list admits; then
    /// the tier decides. Lists match users only, so they never apply to
    /// anonymous or provider viewers. A relationship lookup that fails is an
    /// error, never an admission (fail closed).
    pub async fn admits(
        &self,
        subject: &Actor,
        viewer: &Viewer,
        rel: &Relationships,
    ) -> Result<bool, RelError> {
        let user = viewer.actor();
        if user == Some(subject) {
            return Ok(true);
        }
        if let Some(user) = user {
            if self.deny.contains(user) {
                return Ok(false);
            }
            if self.allow.contains(user) {
                return Ok(true);
            }
        }
        match (self.visibility, user) {
            (Visibility::Public, _) => Ok(true),
            (Visibility::Authenticated, Some(_)) => Ok(true),
            (Visibility::SharedGroups, Some(user)) => rel.groups.share_a_group(subject, user).await,
            (Visibility::Contacts, Some(user)) => rel.contacts.are_contacts(subject, user).await,
            (Visibility::Nobody, _)
            | (Visibility::Authenticated | Visibility::SharedGroups | Visibility::Contacts, None) => {
                Ok(false)
            }
        }
    }
}

#[cfg(test)]
mod tests;
