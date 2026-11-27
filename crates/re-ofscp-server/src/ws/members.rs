//! `member.updated` (§5.7), delivered with access checked at publish
//! ([`Hub::publish_to_readers`], closing decision 0010's commit→hold
//! window).

use std::sync::Arc;

use ofscp_core::LocalId;
use ofscp_core::ws::MemberUpdated;
use re_ofscp_types::wire::Member;

use super::Hub;
use super::protocol;
use crate::groups::Groups;

/// The event type (§5.7).
pub const MEMBER_UPDATED: &str = "member.updated";

impl Hub {
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
            Ok(channels) => {
                let text: Arc<str> =
                    protocol::event(MEMBER_UPDATED, None, data.clone(), self.now()).into();
                for channel_id in &channels {
                    self.publish_to_readers(
                        groups,
                        group_id,
                        channel_id,
                        MEMBER_UPDATED,
                        &text,
                        None,
                    )
                    .await;
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, group_id, "listing a group's channels for member.updated failed");
            }
        }
        self.send_to_actor(&member.user, MEMBER_UPDATED, data);
    }
}
