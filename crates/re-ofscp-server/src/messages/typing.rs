//! Typing indicators in channels (§7.1 *Typing indicators*): ephemeral,
//! never stored and never replayed. Which connection is typing where, and
//! when a `start` expires, is the WebSocket session's state
//! (`ws::typing`); this side checks access and fans the event out.

use ofscp_core::ws::{ChannelTyping, TypingState};
use ofscp_core::{Actor, LocalId};

use super::Messages;
use super::fanout::Live;
use super::ops::MessageError;
use crate::groups::Caller;

const NO_CHANNEL: &str = "no such channel";

impl Messages {
    /// The group of channel `channel_id`, if `actor` can read it: typing
    /// needs read access, and a channel the actor cannot read is answered
    /// as missing (§11.3).
    pub async fn typing_target(
        &self,
        actor: &Actor,
        channel_id: &LocalId,
    ) -> Result<String, MessageError> {
        let Some(group_id) = self.groups.channel_group(channel_id.as_str()).await? else {
            return Err(MessageError::NotFound(NO_CHANNEL));
        };
        let caller = Caller::Actor(actor.clone());
        self.readable(&caller, &group_id, channel_id.as_str())
            .await?;
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
