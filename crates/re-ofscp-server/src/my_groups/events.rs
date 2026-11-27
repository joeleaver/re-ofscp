//! `groups.updated` (spec §5.7, *My groups*; docs/decisions/0018).
//!
//! Pointer writes send their event from the request that made them
//! ([`send`]). Hosted memberships change in `Groups`, which announces every
//! change as a [`GroupChange`]; [`follow`] turns those into events:
//!
//! - `Member { group, actor }` for a local actor: the actor's entry for the
//!   group is read afresh ([`Groups::hosted_entry`]) and sent as changed,
//!   or as removed when there is none.
//! - `Group { group }` for a group no longer active: every member still
//!   recorded, and the owner, is handled as above. (`delete_group` already
//!   names each member before it purges them; this covers a purge left to
//!   the sweeper.) A change to an active group's settings leaves every
//!   entry as it was.
//!
//! Changes are collected into a set by one task, which does no I/O, and
//! resolved by another, so a burst coalesces instead of overflowing the
//! broadcast. An event that cannot be produced is never dropped quietly:
//! when the broadcast lags, the set overflows, or an entry cannot be read,
//! the affected connections (all local ones, when the lost change cannot be
//! named) get a `too_many_requests` error and close `1013`, as for a slow
//! consumer (§7.1 *Close codes*). A client reconnects, and re-reads its list,
//! since nothing it missed while disconnected is replayed.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, PoisonError, Weak};

use re_ofscp_types::wire::GroupPointer;
use re_ofscp_types::{Actor, Authority};
use tokio::runtime::Handle;
use tokio::sync::Notify;
use tokio::sync::broadcast::{self, error::RecvError};

use super::hosted_pointer;
use super::request::group_uri;
use crate::groups::{AccessChange as GroupChange, Groups};
use crate::ws::Hub;
use crate::ws::protocol::Close;
use crate::ws::wire::{WsError, close};
use ofscp_core::ObjectUri;
use ofscp_core::ws::GroupsUpdated;

/// The event type.
pub const GROUPS_UPDATED: &str = "groups.updated";
/// Most distinct changes waiting to be resolved before they count as lost.
const PENDING_MAX: usize = 65_536;

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
            resync(hub, actor);
        }
    }
}

/// Tell `actor`'s connections that changes to their group list were lost,
/// and close them (`1013`) so they reconnect and read it again.
fn resync(hub: &Hub, actor: &Actor) {
    let error = WsError::new(
        "too_many_requests",
        429,
        "changes to your group list could not be delivered; reconnect and read GET /api/me/groups",
    );
    match serde_json::to_value(error) {
        Ok(data) => hub.send_to_actor(actor, "error", data),
        Err(e) => tracing::error!(error = %e, "encoding an error event failed"),
    }
    hub.registry().close_actor(
        actor,
        None,
        Close::new(close::TRY_AGAIN, "group list changes were lost"),
    );
}

/// [`resync`] every local connection.
fn resync_all(hub: &Hub) {
    for actor in hub.registry().local_actors() {
        resync(hub, &actor);
    }
}

/// A change waiting to be resolved.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    Member(String, Actor),
    Group(String),
}

#[derive(Debug, Default)]
struct Queue {
    keys: BTreeSet<Key>,
    /// Changes were lost since the last batch.
    lost: bool,
    /// The broadcast closed: `Groups` is gone.
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

    fn take(&self) -> Queue {
        std::mem::take(&mut *self.queue.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

/// Start turning `groups`' membership changes into `groups.updated` on
/// `hub`. Both tasks end once `groups` or `hub` is dropped.
pub(crate) fn follow(runtime: &Handle, hub: &Arc<Hub>, groups: &Arc<Groups>) {
    let pending = Arc::new(Pending::default());
    runtime.spawn(collect(
        groups.subscribe_changes(),
        groups.home().clone(),
        pending.clone(),
    ));
    runtime.spawn(resolve(
        pending,
        Arc::downgrade(hub),
        Arc::downgrade(groups),
    ));
}

async fn collect(
    mut changes: broadcast::Receiver<GroupChange>,
    home: Authority,
    pending: Arc<Pending>,
) {
    loop {
        let key = match changes.recv().await {
            // Remote members keep their list at their own home provider.
            Ok(GroupChange::Member { group_id, actor }) if actor.is_local_to(&home) => {
                Key::Member(group_id, actor)
            }
            Ok(GroupChange::Group { group_id }) => Key::Group(group_id),
            Ok(_) => continue,
            Err(RecvError::Lagged(missed)) => {
                tracing::warn!(
                    missed,
                    "group list changes lagged; closing local connections"
                );
                pending.with(|q| {
                    q.keys.clear();
                    q.lost = true;
                });
                continue;
            }
            Err(RecvError::Closed) => {
                pending.with(|q| q.closed = true);
                return;
            }
        };
        pending.with(|q| {
            if q.keys.len() >= PENDING_MAX {
                tracing::warn!("too many group list changes pending; closing local connections");
                q.keys.clear();
                q.lost = true;
            } else {
                q.keys.insert(key);
            }
        });
    }
}

async fn resolve(pending: Arc<Pending>, hub: Weak<Hub>, groups: Weak<Groups>) {
    loop {
        let batch = pending.take();
        if batch.keys.is_empty() && !batch.lost {
            if batch.closed {
                return;
            }
            pending.ready.notified().await;
            continue;
        }
        let (Some(hub), Some(groups)) = (hub.upgrade(), groups.upgrade()) else {
            return;
        };
        if batch.lost {
            resync_all(&hub);
        }
        let mut members = BTreeSet::new();
        for key in batch.keys {
            match key {
                Key::Member(group_id, actor) => {
                    members.insert((group_id, actor));
                }
                Key::Group(group_id) => {
                    if let Err(e) = ended_group(&groups, &group_id, &mut members).await {
                        tracing::warn!(error = %e, group_id, "reading a deleted group's members failed; closing local connections");
                        resync_all(&hub);
                    }
                }
            }
        }
        let home = groups.home().clone();
        for (group_id, actor) in members {
            if actor.is_local_to(&home) {
                entry_changed(&hub, &groups, &group_id, &actor).await;
            }
        }
        if batch.closed {
            return;
        }
    }
}

/// Add the members and owner of `group_id` to `members` if the group is no
/// longer active.
async fn ended_group(
    groups: &Groups,
    group_id: &str,
    members: &mut BTreeSet<(String, Actor)>,
) -> Result<(), crate::db::DbError> {
    let row = groups.store.group_owner(group_id).await?;
    if row.as_ref().is_some_and(|g| g.active) {
        return Ok(());
    }
    if let Some(g) = row {
        members.insert((group_id.to_owned(), g.owner));
    }
    for actor in groups.store.member_actors(group_id).await? {
        members.insert((group_id.to_owned(), actor));
    }
    Ok(())
}

/// Send `actor` their entry for `group_id` as it is now.
async fn entry_changed(hub: &Hub, groups: &Groups, group_id: &str, actor: &Actor) {
    // Not connected: nothing to tell. The change committed before it was
    // announced, so a client that connects later reads it.
    if !hub.registry().is_connected(actor) {
        return;
    }
    let entry = match groups.hosted_entry(actor, group_id).await {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error = %e, group_id, "reading a group list entry failed; closing the member's connections");
            resync(hub, actor);
            return;
        }
    };
    let home = groups.home();
    match entry {
        Some(e) => match hosted_pointer(home, &e) {
            Ok(p) => send(hub, actor, vec![p], Vec::new()),
            Err(e) => {
                tracing::error!(error = %e, group_id, "a hosted group list entry did not decode");
                resync(hub, actor);
            }
        },
        None => match ObjectUri::parse(&group_uri(home, group_id)) {
            Ok(uri) => send(hub, actor, Vec::new(), vec![uri]),
            Err(e) => {
                tracing::error!(error = %e, group_id, "a hosted group URI did not parse");
                resync(hub, actor);
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn actor(s: &str) -> Actor {
        Actor::parse_canonical(s).unwrap()
    }

    #[tokio::test]
    async fn only_local_members_and_groups_are_queued() {
        let (tx, rx) = broadcast::channel(16);
        let pending = Arc::new(Pending::default());
        let home = Authority::parse_canonical("a.example").unwrap();
        for change in [
            GroupChange::Member {
                group_id: "g1".into(),
                actor: actor("alice@a.example"),
            },
            GroupChange::Member {
                group_id: "g1".into(),
                actor: actor("carol@b.example"),
            },
            GroupChange::Channel {
                group_id: "g1".into(),
                channel_id: "c1".into(),
            },
            GroupChange::Group {
                group_id: "g2".into(),
            },
        ] {
            tx.send(change).unwrap();
        }
        drop(tx);
        collect(rx, home, pending.clone()).await;
        let q = pending.take();
        assert!(q.closed && !q.lost);
        let want: BTreeSet<Key> = [
            Key::Member("g1".into(), actor("alice@a.example")),
            Key::Group("g2".into()),
        ]
        .into();
        assert_eq!(q.keys, want);
    }

    #[tokio::test]
    async fn a_lagged_receiver_marks_changes_lost() {
        let (tx, rx) = broadcast::channel(1);
        let pending = Arc::new(Pending::default());
        for i in 0..3 {
            tx.send(GroupChange::Group {
                group_id: format!("g{i}"),
            })
            .unwrap();
        }
        drop(tx);
        let home = Authority::parse_canonical("a.example").unwrap();
        collect(rx, home, pending.clone()).await;
        let q = pending.take();
        assert!(q.lost, "the missed changes must not vanish quietly");
        assert_eq!(q.keys, [Key::Group("g2".into())].into());
    }
}
