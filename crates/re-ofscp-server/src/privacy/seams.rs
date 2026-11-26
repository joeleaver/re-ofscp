//! What the visibility policy needs to know from other parts of the
//! provider: group memberships (§5.7), contacts (§6.7) and connection
//! liveness (§7.5). Each is a trait object in [`Relationships`], so the
//! module that owns the state plugs in its implementation with one line in
//! `AppStateBuilder::build`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use re_ofscp_types::Actor;

use super::Viewer;

/// A relationship lookup failed (the database, typically). Callers fail
/// closed: the data stays hidden and the request gets `500`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("relationship lookup failed: {0}")]
pub struct RelError(pub String);

/// Boxed future returned by the relationship seams.
pub type RelFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, RelError>> + Send + 'a>>;

/// Group memberships on this provider, for the `sharedGroups` tier (§6.1)
/// and the membership listing (§6.5).
///
/// Only groups this provider hosts are known here (their members may be
/// local or remote). A subject's memberships in groups hosted elsewhere are
/// stored by those providers and are not listed or matched here.
pub trait GroupMemberships: Send + Sync {
    /// Whether `a` and `b` are both current members of at least one group
    /// this provider hosts.
    fn share_a_group<'a>(&'a self, a: &'a Actor, b: &'a Actor) -> RelFuture<'a, bool>;

    /// The object URIs (§2.2) of the groups hosted here that `subject`
    /// belongs to and that `viewer` may see: a group whose existence the
    /// viewer may not learn (a private group they are not in) is left out.
    fn groups_visible_to<'a>(
        &'a self,
        subject: &'a Actor,
        viewer: &'a Viewer,
    ) -> RelFuture<'a, Vec<String>>;
}

/// Mutual, accepted contacts (§6.7), for the `contacts` tier (§6.1).
pub trait Contacts: Send + Sync {
    /// Whether `a` and `b` hold a mutual accepted contact relationship.
    fn are_contacts<'a>(&'a self, a: &'a Actor, b: &'a Actor) -> RelFuture<'a, bool>;
}

/// Live real-time connections (§7.1), from which presence derives
/// online/offline (§7.5).
pub trait Liveness: Send + Sync {
    /// Whether `actor` has at least one live, authenticated connection.
    fn is_connected(&self, actor: &Actor) -> bool;
}

/// The relationships the visibility policy consults.
#[derive(Clone)]
pub struct Relationships {
    /// Group memberships.
    pub groups: Arc<dyn GroupMemberships>,
    /// Contacts.
    pub contacts: Arc<dyn Contacts>,
}

impl Default for Relationships {
    /// No groups hosted and no contacts stored. The app replaces the
    /// groups seam with its own groups (`AppStateBuilder::build`).
    fn default() -> Self {
        Self {
            groups: Arc::new(NoGroupsHosted),
            contacts: Arc::new(NoContacts),
        }
    }
}

/// [`GroupMemberships`] for a provider that hosts no groups: nobody shares
/// one and nobody belongs to one. The app answers from its own groups
/// (`groups::Groups`); this is the default of a bare [`Relationships`].
#[derive(Debug, Clone, Copy, Default)]
pub struct NoGroupsHosted;

impl GroupMemberships for NoGroupsHosted {
    fn share_a_group<'a>(&'a self, _: &'a Actor, _: &'a Actor) -> RelFuture<'a, bool> {
        Box::pin(async { Ok(false) })
    }

    fn groups_visible_to<'a>(&'a self, _: &'a Actor, _: &'a Viewer) -> RelFuture<'a, Vec<String>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

/// [`Contacts`] for a provider that stores no contacts: nobody is anyone's
/// contact. Replaced when contacts (§6.7) land.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoContacts;

impl Contacts for NoContacts {
    fn are_contacts<'a>(&'a self, _: &'a Actor, _: &'a Actor) -> RelFuture<'a, bool> {
        Box::pin(async { Ok(false) })
    }
}

/// [`Liveness`] for a provider without the WebSocket endpoint: nobody is
/// connected, so everyone's presence reads `offline` (§7.5). Replaced when
/// the WebSocket (§7.1) lands.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoConnections;

impl Liveness for NoConnections {
    fn is_connected(&self, _: &Actor) -> bool {
        false
    }
}
