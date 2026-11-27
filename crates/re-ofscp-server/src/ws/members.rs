//! Publishing group events to channel subscribers with access checked
//! (closing decision 0010's commit→hold window), and `member.updated`
//! (§5.7).

use std::sync::Arc;

use ofscp_core::LocalId;
use ofscp_core::ws::MemberUpdated;
use re_ofscp_types::wire::Member;
use serde_json::Value;

use super::Hub;
use super::protocol;
use super::registry::AccessChange;
use crate::groups::Groups;

/// The event type (§5.7).
pub const MEMBER_UPDATED: &str = "member.updated";

impl Hub {
    /// Publish an event of type `kind` with `data` to the subscribers of
    /// each of `topics`, delivering it only to those who can still read the
    /// topic (decision 0010, "The window between a commit and its hold").
    ///
    /// Every subscription of the topics is held first, the event is queued
    /// behind the hold, and each is released only once a re-check finds it
    /// readable; one that is not ends with `access_revoked` and its queued
    /// events are dropped. So a change committed just before (whose own
    /// announcement the group follower has not applied yet) cannot leak
    /// this event to someone it revoked.
    pub fn publish_checked(self: &Arc<Self>, topics: &[String], kind: &str, data: Value) {
        if topics.is_empty() {
            return;
        }
        let held = self
            .registry
            .hold_matching(&AccessChange::Topics(topics.to_vec()));
        if held.is_empty() {
            return;
        }
        let text: Arc<str> = protocol::event(kind, None, data, self.now()).into();
        for topic in topics {
            self.registry.publish(topic, kind, &text);
        }
        let hub = self.clone();
        tokio::spawn(async move { hub.recheck(held).await });
    }

    /// Emit `member.updated` for `member` of `group_id` (§5.7): to every
    /// live subscription on the group's channels that can still read its
    /// channel, and to the member's own connections. If the channels cannot
    /// be listed, only the member is told (logged); clients re-fetch member
    /// lists on reconnect anyway.
    pub async fn member_updated(
        self: &Arc<Self>,
        groups: &Groups,
        group_id: &str,
        member: &Member,
    ) {
        let Ok(id) = LocalId::new(group_id) else {
            tracing::warn!(group_id, "member.updated for a malformed group id");
            return;
        };
        let data = match serde_json::to_value(MemberUpdated {
            group_id: id,
            member: member.clone(),
        }) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = %e, "encoding member.updated failed");
                return;
            }
        };
        match groups.store.channel_ids(group_id).await {
            Ok(topics) => self.publish_checked(&topics, MEMBER_UPDATED, data.clone()),
            Err(e) => {
                tracing::warn!(error = %e, group_id, "listing a group's channels for member.updated failed");
            }
        }
        self.send_to_actor(&member.user, MEMBER_UPDATED, data);
    }
}
