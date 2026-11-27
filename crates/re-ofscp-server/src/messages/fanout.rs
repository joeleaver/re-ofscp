//! Live delivery of a channel's events (§7.1): what the message operations
//! hand to the WebSocket layer, under the channel's lock, once a change is
//! committed.
//!
//! The implementation (`ws::live`) delivers only to the subscribers who can
//! read the channel at that moment, which closes the window between a
//! revoking commit and the hold its follower places on a subscription
//! (decision 0010).

use std::future::Future;
use std::pin::Pin;

use ofscp_core::ws::{
    ChannelMessage, ChannelTyping, MessageDeleted, ReactionAdded, ReactionRemoved,
};
use serde_json::Value;

use crate::ws::ConnId;

/// One live event of a channel.
#[derive(Debug, Clone, PartialEq)]
pub enum Live {
    /// `message.created`.
    Created(ChannelMessage),
    /// `message.updated`.
    Updated(ChannelMessage),
    /// `message.deleted`.
    Deleted(MessageDeleted),
    /// `reaction.added`.
    ReactionAdded(ReactionAdded),
    /// `reaction.removed`.
    ReactionRemoved(ReactionRemoved),
    /// `channel.typing`.
    Typing(ChannelTyping),
}

impl Live {
    /// The event type.
    pub fn kind(&self) -> &'static str {
        match self {
            Live::Created(_) => "message.created",
            Live::Updated(_) => "message.updated",
            Live::Deleted(_) => "message.deleted",
            Live::ReactionAdded(_) => "reaction.added",
            Live::ReactionRemoved(_) => "reaction.removed",
            Live::Typing(_) => "channel.typing",
        }
    }

    /// The event's `data`.
    pub fn data(&self) -> Value {
        let encoded = match self {
            Live::Created(d) | Live::Updated(d) => serde_json::to_value(d),
            Live::Deleted(d) => serde_json::to_value(d),
            Live::ReactionAdded(d) => serde_json::to_value(d),
            Live::ReactionRemoved(d) => serde_json::to_value(d),
            Live::Typing(d) => serde_json::to_value(d),
        };
        // These are plain data structs: serializing them cannot fail.
        encoded.unwrap_or(Value::Null)
    }
}

/// The WebSocket command that caused an event: its connection gets its
/// own copy carrying the command's `id` as `correlationId` (§7.1), whether
/// or not it is subscribed to the channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    /// The requesting connection.
    pub conn: ConnId,
    /// The command's `id`.
    pub correlation_id: String,
}

/// Boxed future returned by [`Fanout::deliver`].
pub type FanoutFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

/// Delivers a channel's live events.
pub trait Fanout: Send + Sync {
    /// Deliver `live`, an event of channel `channel_id` of `group_id`, to
    /// those of the channel's subscribers who can read it now, and to
    /// `origin`. Called with the channel's lock held, in timeline order.
    fn deliver<'a>(
        &'a self,
        group_id: &'a str,
        channel_id: &'a str,
        live: Live,
        origin: Option<&'a Origin>,
    ) -> FanoutFuture<'a>;
}
