//! Channel topics over the groups module (spec §7.1 "Channel
//! subscriptions", "Losing access"; §11.3; security requirement 5;
//! docs/decisions/0010-websocket.md, 0014-groups-and-channels.md).
//!
//! * [`GroupTopics`]: the [`TopicAuthorizer`] the provider runs. A topic is
//!   a channel id; it is readable iff [`Groups::read_channel`] admits the
//!   actor, which applies effective read access (the stricter of the
//!   group's tier and the channel's, narrowed by the channel's `view`).
//! * [`follow_groups`]: turns the groups module's [`GroupChange`]s into
//!   [`Hub::access_changed`] calls, so a subscription whose access is lost
//!   ends at once with `unsubscribed {reason: "access_revoked"}` rather
//!   than at the next periodic sweep. `AppStateBuilder::build` starts it.

use std::future::Future;
use std::sync::{Arc, Weak};

use re_ofscp_types::Actor;
use tokio::runtime::Handle;
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::RecvError;

use super::Hub;
use super::registry::AccessChange;
use super::seams::{AccessFuture, SeamError, TopicAccess, TopicAuthorizer};
use crate::db::DbError;
use crate::groups::ops::GroupError;
use crate::groups::{AccessChange as GroupChange, Caller, Groups};

/// Effective read access to channel topics, from [`Groups`].
#[derive(Debug, Clone)]
pub struct GroupTopics {
    groups: Arc<Groups>,
}

impl GroupTopics {
    /// Topics answered from `groups`.
    pub fn new(groups: Arc<Groups>) -> Self {
        Self { groups }
    }

    async fn access(&self, actor: &Actor, channel_id: &str) -> Result<TopicAccess, SeamError> {
        let group_id = match self.groups.channel_group(channel_id).await {
            Ok(Some(group_id)) => group_id,
            // No such active channel, or its group is being deleted.
            Ok(None) => return Ok(TopicAccess::Unreadable),
            Err(e) => return verdict(Err(e)),
        };
        let caller = Caller::Actor(actor.clone());
        verdict(
            self.groups
                .read_channel(&caller, &group_id, channel_id)
                .await
                .map(|_| ()),
        )
    }
}

impl TopicAuthorizer for GroupTopics {
    fn check<'a>(&'a self, actor: &'a Actor, topic: &'a str) -> AccessFuture<'a> {
        Box::pin(self.access(actor, topic))
    }
}

/// What a groups lookup means for a subscription. Unreadable and missing
/// are one answer (§7.1: `not_found` either way). A row deleted under the
/// read ([`DbError::Vanished`]) is gone, so unreadable. Any other failure
/// cannot vouch for access either way: the subscribe answers
/// `service_unavailable`, and a re-check retries and then fails closed.
fn verdict(result: Result<(), GroupError>) -> Result<TopicAccess, SeamError> {
    match result {
        Ok(()) => Ok(TopicAccess::Readable),
        Err(GroupError::NotFound(_) | GroupError::Forbidden(_)) => Ok(TopicAccess::Unreadable),
        Err(GroupError::Db(DbError::Vanished(_))) => Ok(TopicAccess::Unreadable),
        Err(e) => Err(SeamError(e.to_string())),
    }
}

/// Start feeding every change `groups` announces from now on into `hub`'s
/// re-checks, on `runtime`, until `groups` or `hub` is dropped (the task
/// holds neither alive). [`crate::AppStateBuilder::build`] calls this
/// where it assembles both, so no state it builds can lose immediate
/// revocation. The receiver is taken before this returns, so nothing
/// announced after the call is missed.
pub(crate) fn follow_groups(runtime: &Handle, hub: &Arc<Hub>, groups: &Arc<Groups>) {
    let changes = groups.subscribe_changes();
    let groups: Weak<Groups> = Arc::downgrade(groups);
    let hub: Weak<Hub> = Arc::downgrade(hub);
    runtime.spawn(follow(
        changes,
        move |change| {
            let groups = groups.clone();
            async move {
                let groups = groups.upgrade()?;
                Some(topics_for(&groups, change).await)
            }
        },
        move |change| match hub.upgrade() {
            Some(hub) => {
                hub.access_changed(change);
                true
            }
            None => false,
        },
    ));
}

/// The follower's loop: each change `changes` receives is `resolve`d to
/// the subscriptions it concerns and `deliver`ed, until the channel
/// closes, `resolve` answers `None` or `deliver` answers `false` (whatever
/// they stand for is gone).
///
/// A receiver that lagged lost changes it cannot name: it delivers a full
/// re-check ([`AccessChange::All`]).
async fn follow<F>(
    mut changes: broadcast::Receiver<GroupChange>,
    mut resolve: impl FnMut(GroupChange) -> F,
    mut deliver: impl FnMut(AccessChange) -> bool,
) where
    F: Future<Output = Option<AccessChange>>,
{
    loop {
        let change = match changes.recv().await {
            Ok(change) => match resolve(change).await {
                Some(change) => change,
                None => return,
            },
            Err(RecvError::Lagged(missed)) => {
                tracing::warn!(
                    missed,
                    "group access changes lagged; re-checking every subscription"
                );
                AccessChange::All
            }
            Err(RecvError::Closed) => return,
        };
        if !deliver(change) {
            return;
        }
    }
}

/// The subscriptions a group change concerns.
async fn topics_for(groups: &Groups, change: GroupChange) -> AccessChange {
    match change {
        GroupChange::Channel { channel_id, .. } => AccessChange::Topics(vec![channel_id]),
        GroupChange::Member { actor, .. } => AccessChange::Actor(actor),
        // Every channel of the group, read now. A deletion has already
        // named each of its channels on its own (it purges the rows).
        GroupChange::Group { group_id } => match groups.store.channel_ids(&group_id).await {
            Ok(ids) => AccessChange::Topics(ids),
            Err(e) => {
                tracing::warn!(error = %e, group_id, "listing a changed group's channels failed; re-checking every subscription");
                AccessChange::All
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::validate::Invalid;

    fn actor(s: &str) -> Actor {
        Actor::parse_canonical(s).unwrap()
    }

    fn member(s: &str) -> GroupChange {
        GroupChange::Member {
            group_id: "grp_1".into(),
            actor: actor(s),
        }
    }

    /// Resolve only `Member` changes, as `topics_for` does.
    async fn by_actor(change: GroupChange) -> Option<AccessChange> {
        match change {
            GroupChange::Member { actor, .. } => Some(AccessChange::Actor(actor)),
            other => panic!("unexpected change {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_lagged_follower_rechecks_everything_then_goes_on() {
        let (tx, rx) = broadcast::channel(1);
        // Capacity 1: the second send pushes the first out unread.
        tx.send(member("alice@providera.com")).unwrap();
        tx.send(member("bob@providera.com")).unwrap();
        drop(tx);
        let mut delivered = Vec::new();
        follow(rx, by_actor, |c| {
            delivered.push(c);
            true
        })
        .await;
        assert_eq!(
            delivered,
            [
                AccessChange::All,
                AccessChange::Actor(actor("bob@providera.com"))
            ]
        );
    }

    #[tokio::test]
    async fn the_follower_stops_once_the_hub_is_gone() {
        let (tx, rx) = broadcast::channel(4);
        tx.send(member("alice@providera.com")).unwrap();
        tx.send(member("bob@providera.com")).unwrap();
        let mut delivered = 0;
        // The sender is still open: only `deliver`'s `false` ends it.
        follow(rx, by_actor, |_| {
            delivered += 1;
            false
        })
        .await;
        assert_eq!(delivered, 1);
        drop(tx);
    }

    #[tokio::test]
    async fn the_follower_stops_once_the_groups_are_gone() {
        let (tx, rx) = broadcast::channel(4);
        tx.send(member("alice@providera.com")).unwrap();
        let mut delivered = 0;
        follow(
            rx,
            |_| async { None },
            |_| {
                delivered += 1;
                true
            },
        )
        .await;
        assert_eq!(delivered, 0);
        drop(tx);
    }

    #[test]
    fn hidden_missing_and_vanished_are_unreadable() {
        assert_eq!(verdict(Ok(())), Ok(TopicAccess::Readable));
        for e in [
            GroupError::NotFound("no such channel"),
            GroupError::Forbidden("hidden"),
            GroupError::Db(DbError::Vanished("channel".into())),
        ] {
            assert_eq!(verdict(Err(e)), Ok(TopicAccess::Unreadable));
        }
    }

    #[test]
    fn other_failures_cannot_vouch_for_access() {
        for e in [
            GroupError::Db(DbError::Unavailable("down".into())),
            GroupError::Db(DbError::Decode("bad row".into())),
            GroupError::Db(DbError::Contended("raced".into())),
            GroupError::Conflict("kept changing"),
            GroupError::Invalid(Invalid("bad".into())),
        ] {
            assert!(verdict(Err(e)).is_err());
        }
    }
}
