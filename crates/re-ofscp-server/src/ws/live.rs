//! Live delivery of channel events with access checked at publish time
//! (§7.1, §11.3; decision 0010 "The window between a commit and its
//! hold").
//!
//! A subscription that a just-committed change revoked stays registered
//! until the group follower holds and re-checks it. Publishing through
//! [`super::Hub::publish`] would deliver to it in that window.
//! [`Hub::publish_to_readers`] instead reads the channel's group, channel
//! and the subscribers' memberships afresh, after the event's own commit,
//! and delivers only to those who can read the channel now. Any change
//! committed before that read is therefore seen, whether or not its
//! follower has run. If the read fails, the event goes to no subscriber
//! (fail closed); they backfill through history.
//!
//! Every channel-event publisher uses it: message events through
//! [`HubFanout`] (decision 0017, which publishes under the channel's
//! lock) and `member.updated` (`super::members`, decision 0020).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock, Weak};

use re_ofscp_types::Actor;

use super::{ConnId, Hub, protocol};
use crate::db::DbError;
use crate::groups::Groups;
use crate::groups::access::{self, Standing};
use crate::messages::fanout::{Fanout, FanoutFuture, Live, Origin};

/// [`Fanout`] into a [`Hub`], over the provider's groups.
///
/// The hub owns (through its [`super::Seams`]) the messages that own this,
/// so this holds it weakly, and is attached to it once the hub is built
/// ([`HubFanout::attach`]). Until then, and after the hub is gone, an
/// event goes nowhere; no connection can exist then to miss it.
#[derive(Debug)]
pub struct HubFanout {
    hub: OnceLock<Weak<Hub>>,
    groups: Arc<Groups>,
}

impl HubFanout {
    /// Fan-out checking access against `groups`, attached to no hub yet.
    pub fn new(groups: Arc<Groups>) -> Self {
        Self {
            hub: OnceLock::new(),
            groups,
        }
    }

    /// Deliver through `hub` from now on. A fan-out is attached once; a
    /// later call changes nothing.
    pub fn attach(&self, hub: &Arc<Hub>) {
        if self.hub.set(Arc::downgrade(hub)).is_err() {
            tracing::warn!("live delivery is already attached to a hub; ignoring another");
        }
    }

    async fn deliver_now(
        &self,
        group_id: &str,
        channel_id: &str,
        live: Live,
        origin: Option<&Origin>,
    ) {
        let Some(hub) = self.hub.get().and_then(Weak::upgrade) else {
            return;
        };
        let (kind, data, now) = (live.kind(), live.data(), hub.now());
        let text: Arc<str> = protocol::event(kind, None, data.clone(), now).into();
        let own: Option<(ConnId, Arc<str>)> = origin.map(|o| {
            let t: Arc<str> = protocol::event(kind, Some(&o.correlation_id), data, now).into();
            (o.conn, t)
        });
        hub.publish_to_readers(
            &self.groups,
            group_id,
            channel_id,
            kind,
            &text,
            own.as_ref().map(|(id, t)| (*id, t)),
        )
        .await;
    }
}

impl Hub {
    /// Deliver the already-encoded event `text` (of type `kind`) to the
    /// subscribers of channel `channel_id` in group `group_id` who can read
    /// it now, read afresh from `groups` (decision 0010, "The window
    /// between a commit and its hold"). `own`, when given, is the
    /// connection whose command caused the event and the copy it gets
    /// instead (with its `correlationId`), whether or not it subscribes.
    ///
    /// Every publisher of channel events goes through this rather than
    /// [`Hub::publish`]: message events ([`HubFanout`], decision 0017) and
    /// `member.updated` (decision 0020). If the read fails, the event goes
    /// to no subscriber (fail closed, logged).
    pub async fn publish_to_readers(
        &self,
        groups: &Groups,
        group_id: &str,
        channel_id: &str,
        kind: &str,
        text: &Arc<str>,
        own: Option<(ConnId, &Arc<str>)>,
    ) {
        let subscribers = self.registry().subscribers(channel_id);
        let readers = if subscribers.is_empty() {
            HashSet::new()
        } else {
            match readers(groups, group_id, channel_id, &subscribers).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        channel = channel_id,
                        "access check for live delivery failed; delivering to no subscriber"
                    );
                    HashSet::new()
                }
            }
        };
        // `own` still gets its copy, subscribed or not: its command caused
        // the event, after passing that command's own access checks.
        self.registry()
            .publish_to(channel_id, kind, text, |id| readers.contains(&id), own);
    }
}

/// Which of `subscribers` can read channel `channel_id` of `group_id` now.
async fn readers(
    groups: &Groups,
    group_id: &str,
    channel_id: &str,
    subscribers: &[(ConnId, Actor)],
) -> Result<HashSet<ConnId>, DbError> {
    let store = &groups.store;
    let (Some(group), Some(channel)) = (
        store.group(group_id).await?,
        store.channel(group_id, channel_id).await?,
    ) else {
        return Ok(HashSet::new());
    };
    let (policy, cpolicy) = (group.policy(), channel.policy());
    if access::can_read_channel(&Standing::Outsider, &policy, &cpolicy) {
        // Open to anyone, with no `view`: every subscriber reads it.
        return Ok(subscribers.iter().map(|(id, _)| *id).collect());
    }
    let mut actors: Vec<Actor> = subscribers
        .iter()
        .map(|(_, a)| a.clone())
        .filter(|a| *a != group.owner)
        .collect();
    actors.sort();
    actors.dedup();
    let roles: HashMap<Actor, String> = store.roles_of(group_id, &actors).await?;
    Ok(subscribers
        .iter()
        .filter(|(_, actor)| {
            let standing = if *actor == group.owner {
                Standing::Owner
            } else {
                roles
                    .get(actor)
                    .map_or(Standing::Outsider, |r| Standing::Member(r.clone()))
            };
            access::can_read_channel(&standing, &policy, &cpolicy)
        })
        .map(|(id, _)| *id)
        .collect())
}

impl Fanout for HubFanout {
    fn deliver<'a>(
        &'a self,
        group_id: &'a str,
        channel_id: &'a str,
        live: Live,
        origin: Option<&'a Origin>,
    ) -> FanoutFuture<'a> {
        Box::pin(self.deliver_now(group_id, channel_id, live, origin))
    }
}
