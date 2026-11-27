//! `groups.updated` (spec §5.7, *My groups*; docs/decisions/0018).
//!
//! Pointer writes send their event from the request that made them
//! ([`send`]). Hosted memberships change in `Groups`, which tells its
//! [`MembershipListener`]s of every change synchronously, from the write
//! that made it; [`follow`] registers one. It never reads the bounded
//! `AccessChange` broadcast, so nothing it needs can lag away: a group's
//! deletion names every member, however many (`groups/ending.rs`).
//!
//! The listener does no I/O. It keeps a change only for a local actor
//! with a live connection (a remote member's list lives at their own home
//! provider, and an actor who connects later reads the committed change),
//! as a `(group, actor)` key in a coalescing set. A second task resolves
//! each key by reading the actor's entry afresh ([`Groups::hosted_entry`])
//! and sending it as changed, or as removed when there is none. A fresh
//! read makes ordering and duplicates harmless.
//!
//! An event that cannot be produced is never dropped quietly; the one
//! actor it concerns loses their connections, never anyone else
//! ([`Loss`]): a full set is an outbound overflow (`1013`), an entry that
//! cannot be read or encoded an internal error (`1011`). A client
//! reconnects and re-reads its list, since nothing missed while
//! disconnected is replayed.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, PoisonError, Weak};

use re_ofscp_types::wire::GroupPointer;
use re_ofscp_types::{Actor, Authority};
use tokio::runtime::Handle;
use tokio::sync::Notify;

use super::hosted_pointer;
use super::request::group_uri;
use crate::groups::{Groups, MembershipListener};
use crate::ws::Hub;
use crate::ws::protocol::Close;
use crate::ws::wire::{WsError, close};
use ofscp_core::ObjectUri;
use ofscp_core::ws::GroupsUpdated;

/// The event type.
pub const GROUPS_UPDATED: &str = "groups.updated";
/// The default bound on distinct `(group, actor)` changes waiting to be
/// resolved ([`crate::AppStateBuilder::group_list_backlog`]).
pub const PENDING_MAX: usize = 65_536;
/// `details.retryAfter` (seconds) when an actor's changes overflowed: the
/// backlog drains at database speed, so a reconnect shortly after finds it
/// smaller.
const OVERFLOW_RETRY_SECS: u64 = 5;

/// Send `groups.updated` to every connection of `actor`. Both lists empty
/// sends nothing (§5.7: not both).
pub fn send(hub: &Hub, actor: &Actor, groups: Vec<GroupPointer>, removed: Vec<ObjectUri>) {
    if groups.is_empty() && removed.is_empty() {
        return;
    }
    match serde_json::to_value(GroupsUpdated { groups, removed }) {
        Ok(data) => hub.send_to_actor(actor, GROUPS_UPDATED, data),
        Err(e) => {
            tracing::error!(error = %e, "encoding groups.updated failed");
            lose(hub, actor, Loss::Internal);
        }
    }
}

/// Why changes to one actor's group list could not be delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Loss {
    /// Too many changes were waiting: the outbound overflow of §7.1
    /// *Close codes*, `too_many_requests` then `1013`.
    Overflow,
    /// The entry could not be read or encoded: `internal_error` then
    /// `1011`. Not the client's doing, so not a slow-consumer close.
    Internal,
}

impl Loss {
    /// The `error` the actor's connections get first.
    fn error(self) -> WsError {
        match self {
            Self::Overflow => WsError::too_many_requests(
                "too many changes to your group list are waiting; reconnect and read GET /api/me/groups",
                OVERFLOW_RETRY_SECS,
            ),
            Self::Internal => WsError::internal(
                "a change to your group list could not be delivered; reconnect and read GET /api/me/groups",
            ),
        }
    }

    /// The close that follows it.
    fn close(self) -> Close {
        match self {
            Self::Overflow => Close::new(close::TRY_AGAIN, "group list changes overflowed"),
            Self::Internal => Close::new(close::INTERNAL, "group list changes were lost"),
        }
    }
}

/// Tell `actor`'s connections that changes to their group list were lost,
/// and close them so they reconnect and read it again.
fn lose(hub: &Hub, actor: &Actor, loss: Loss) {
    match serde_json::to_value(loss.error()) {
        Ok(data) => hub.send_to_actor(actor, "error", data),
        Err(e) => tracing::error!(error = %e, "encoding an error event failed"),
    }
    hub.registry().close_actor(actor, None, loss.close());
}

/// A change waiting to be resolved: a group and a member.
type Key = (String, Actor);

#[derive(Debug, Default)]
struct Queue {
    keys: BTreeSet<Key>,
    /// The listener is gone: `Groups` is.
    closed: bool,
}

#[derive(Debug, Default)]
struct Pending {
    queue: Mutex<Queue>,
    ready: Notify,
}

impl Pending {
    fn with<T>(&self, f: impl FnOnce(&mut Queue) -> T) -> T {
        let mut q = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        let out = f(&mut q);
        drop(q);
        self.ready.notify_one();
        out
    }

    /// Queue `key` unless `max` others are waiting. `false` if it did not
    /// fit (a key already waiting always does: it coalesces).
    fn push(&self, key: Key, max: usize) -> bool {
        self.with(|q| {
            if q.keys.len() >= max && !q.keys.contains(&key) {
                return false;
            }
            q.keys.insert(key);
            true
        })
    }

    fn take(&self) -> Queue {
        std::mem::take(&mut *self.queue.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

/// The [`MembershipListener`] [`follow`] registers.
struct Listener {
    home: Authority,
    hub: Weak<Hub>,
    pending: Arc<Pending>,
    max: usize,
}

impl MembershipListener for Listener {
    fn membership_changed(&self, group_id: &str, actor: &Actor) {
        // Remote members keep their list at their own home provider.
        if !actor.is_local_to(&self.home) {
            return;
        }
        let Some(hub) = self.hub.upgrade() else {
            return;
        };
        // Not connected: nothing to tell. The change committed before it
        // was announced, so a client that connects later reads it.
        if !hub.registry().is_connected(actor) {
            return;
        }
        if !self
            .pending
            .push((group_id.to_owned(), actor.clone()), self.max)
        {
            tracing::warn!(
                group_id,
                "too many group list changes pending; closing the member's connections"
            );
            lose(&hub, actor, Loss::Overflow);
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        // `Groups` dropped its listeners: nothing more will come.
        self.pending.with(|q| q.closed = true);
    }
}

/// Start turning `groups`' membership changes into `groups.updated` on
/// `hub`, holding at most `max_pending` distinct changes. The resolving
/// task ends once `groups` or `hub` is dropped.
pub(crate) fn follow(runtime: &Handle, hub: &Arc<Hub>, groups: &Arc<Groups>, max_pending: usize) {
    let pending = Arc::new(Pending::default());
    groups.on_membership(Arc::new(Listener {
        home: groups.home().clone(),
        hub: Arc::downgrade(hub),
        pending: pending.clone(),
        max: max_pending,
    }));
    runtime.spawn(resolve(
        pending,
        Arc::downgrade(hub),
        Arc::downgrade(groups),
    ));
}

async fn resolve(pending: Arc<Pending>, hub: Weak<Hub>, groups: Weak<Groups>) {
    loop {
        let batch = pending.take();
        if batch.keys.is_empty() {
            if batch.closed {
                return;
            }
            pending.ready.notified().await;
            continue;
        }
        let (Some(hub), Some(groups)) = (hub.upgrade(), groups.upgrade()) else {
            return;
        };
        for (group_id, actor) in batch.keys {
            entry_changed(&hub, &groups, &group_id, &actor).await;
        }
        if batch.closed {
            return;
        }
    }
}

/// Send `actor` their entry for `group_id` as it is now.
async fn entry_changed(hub: &Hub, groups: &Groups, group_id: &str, actor: &Actor) {
    // Disconnected meanwhile: nothing to tell.
    if !hub.registry().is_connected(actor) {
        return;
    }
    let entry = match groups.hosted_entry(actor, group_id).await {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error = %e, group_id, "reading a group list entry failed; closing the member's connections");
            lose(hub, actor, Loss::Internal);
            return;
        }
    };
    let home = groups.home();
    match entry {
        Some(e) => match hosted_pointer(home, &e) {
            Ok(p) => send(hub, actor, vec![p], Vec::new()),
            Err(e) => {
                tracing::error!(error = %e, group_id, "a hosted group list entry did not decode");
                lose(hub, actor, Loss::Internal);
            }
        },
        None => match ObjectUri::parse(&group_uri(home, group_id)) {
            Ok(uri) => send(hub, actor, Vec::new(), vec![uri]),
            Err(e) => {
                tracing::error!(error = %e, group_id, "a hosted group URI did not parse");
                lose(hub, actor, Loss::Internal);
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn actor(s: &str) -> Actor {
        Actor::parse_canonical(s).unwrap()
    }

    fn key(group: &str, who: &str) -> Key {
        (group.to_owned(), actor(who))
    }

    #[test]
    fn an_overflow_is_a_slow_consumer_close_with_a_retry_hint() {
        let e = Loss::Overflow.error();
        assert_eq!((e.code.as_str(), e.status), ("too_many_requests", 429));
        assert_eq!(
            e.details,
            Some(json!({ "retryAfter": OVERFLOW_RETRY_SECS }))
        );
        let c = Loss::Overflow.close();
        assert_eq!(c.code, close::TRY_AGAIN);
        assert!(c.flush, "the error must reach the client before the close");
    }

    #[test]
    fn a_lost_entry_is_an_internal_error_close() {
        let e = Loss::Internal.error();
        assert_eq!((e.code.as_str(), e.status), ("internal_error", 500));
        assert_eq!(e.details, None);
        let c = Loss::Internal.close();
        assert_eq!(c.code, close::INTERNAL);
        assert!(c.flush);
    }

    #[test]
    fn the_backlog_is_bounded_but_coalesces() {
        let pending = Pending::default();
        assert!(pending.push(key("g1", "alice@a.example"), 2));
        assert!(pending.push(key("g2", "alice@a.example"), 2));
        assert!(!pending.push(key("g3", "alice@a.example"), 2));
        // A change already waiting needs no room of its own.
        assert!(pending.push(key("g1", "alice@a.example"), 2));
        assert_eq!(pending.take().keys.len(), 2);
        assert!(!pending.push(key("g1", "alice@a.example"), 0));
    }

    #[test]
    fn dropping_the_listener_ends_the_resolver() {
        let pending = Arc::new(Pending::default());
        let listener = Listener {
            home: Authority::parse_canonical("a.example").unwrap(),
            hub: Weak::new(),
            pending: pending.clone(),
            max: 8,
        };
        // No hub: nothing is queued.
        listener.membership_changed("g1", &actor("alice@a.example"));
        drop(listener);
        let q = pending.take();
        assert!(q.closed && q.keys.is_empty());
    }
}
