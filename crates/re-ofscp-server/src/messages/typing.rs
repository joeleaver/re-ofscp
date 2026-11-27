//! Typing indicators in channels (§7.1 *Typing indicators*): ephemeral,
//! never stored and never replayed. Which connection is typing where, and
//! when a `start` expires, is the WebSocket session's state
//! (`ws::typing`); this side checks access and fans the event out.

use ofscp_core::wire::MessageType;
use ofscp_core::ws::{ChannelTyping, TypingState};
use ofscp_core::{Actor, LocalId};

use super::Messages;
use super::fanout::Live;
use super::ops::MessageError;
use crate::groups::Caller;
use crate::groups::access;

const NO_CHANNEL: &str = "no such channel";
const MAY_NOT_TYPE: &str = "you may not post in this channel";

impl Messages {
    /// The group of channel `channel_id`, if `actor` may type in it.
    /// Typing needs read access, and a channel the actor cannot read is
    /// answered as missing (§11.3). It also needs some `post:<type>`
    /// grant: a reader who may post nothing is `403`. A reply-restricted
    /// poster may type (the oracle's answer to Q5, decision 0017).
    pub async fn typing_target(
        &self,
        actor: &Actor,
        channel_id: &LocalId,
    ) -> Result<String, MessageError> {
        let Some(group_id) = self.groups.channel_group(channel_id.as_str()).await? else {
            return Err(MessageError::NotFound(NO_CHANNEL));
        };
        let caller = Caller::Actor(actor.clone());
        let (g, channel) = self
            .readable(&caller, &group_id, channel_id.as_str())
            .await?;
        let (policy, cpolicy) = (g.group.policy(), channel.policy());
        let may_post_any = [
            MessageType::Message,
            MessageType::Memo,
            MessageType::Article,
        ]
        .iter()
        .any(|kind| access::may_post(&g.standing, &policy, &cpolicy, kind.as_str()));
        if !may_post_any {
            return Err(MessageError::Forbidden(MAY_NOT_TYPE));
        }
        Ok(group_id)
    }

    /// Fan out `channel.typing` for `actor` in the channel, to the
    /// subscribers who can read it now.
    pub async fn typing(
        &self,
        group_id: &str,
        channel_id: &LocalId,
        actor: &Actor,
        state: TypingState,
    ) {
        let live = Live::Typing(ChannelTyping {
            channel_id: channel_id.clone(),
            user: actor.clone(),
            state,
        });
        self.fanout
            .deliver(group_id, channel_id.as_str(), live, None)
            .await;
    }
}
