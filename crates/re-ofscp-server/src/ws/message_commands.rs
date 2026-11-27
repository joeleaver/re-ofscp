//! The messaging commands of an authenticated connection (spec §7.1
//! "Sending messages", "Editing & deleting messages", "Reactions",
//! "Typing indicators"), run in order on the connection's command worker
//! after the subscription commands of [`super::commands`].
//!
//! Each runs the same operation as its REST equivalent
//! ([`crate::messages`]), with the same order of checks; a rejection is an
//! `error` with the command's `id` in `correlationId` (§7.3). A success
//! fans out to the channel's readers, and the requesting connection's copy
//! carries the `correlationId`, subscribed or not. A command that changed
//! nothing fans out nothing, and the requester alone gets the answer as it
//! stands, without a `cursor` (it is not a timeline event): the existing
//! message of a repeated `clientMessageId` as `message.created` (§7.1
//! *Idempotency*), an already deleted message as `message.deleted`, a
//! reaction already held as `reaction.added`, and one not held as
//! `reaction.removed` (decision 0017).

use std::sync::Arc;

use ofscp_core::LocalId;
use ofscp_core::wire::ReactionPut;
use ofscp_core::ws::{
    ChannelMessageDelete, ReactionAdd, ReactionAdded, ReactionRemove, ReactionRemoved,
    Typing as TypingCommand,
};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use super::commands::Session;
use super::protocol::{self, Command, WsError};
use super::typing::Typing;
use crate::db::DbError;
use crate::messages::{
    Added, Created, Deleted, Live, MessageError, Messages, Origin, channel_message, message_deleted,
};

/// The commands this module runs.
pub const MESSAGE_COMMANDS: &[&str] = &[
    "message.create",
    "message.update",
    "message.delete",
    "reaction.add",
    "reaction.remove",
    "typing.start",
    "typing.stop",
];

/// The channel a `message.create` names; the rest of its `data` is the
/// `MessageCreate`, checked by [`Messages::create`] in §7.1's order.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChannelTarget {
    group_id: LocalId,
    channel_id: LocalId,
}

/// The message a `message.update` names; the rest of its `data` is the
/// `MessageUpdate`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MessageTarget {
    group_id: LocalId,
    channel_id: LocalId,
    message_id: LocalId,
}

/// The WebSocket answer to a failed message operation (§7.3).
fn ws_error(e: MessageError) -> WsError {
    match e {
        MessageError::NotFound(d) => WsError::not_found(d),
        MessageError::Forbidden(d) => WsError::forbidden(d),
        MessageError::Invalid(i) => WsError::bad_request(i.0),
        MessageError::BadCursor(c) => WsError::bad_request(c.to_string()),
        MessageError::Conflict(d) => WsError::new("conflict", 409, d),
        MessageError::Db(DbError::Unavailable(e)) => {
            tracing::error!(error = %e, "message command: database unavailable");
            WsError::service_unavailable("the provider is unavailable; retry", 1)
        }
        // Other writers kept winning a compare-and-set. A retry is safe
        // even if an edit or delete applied before its event was recorded
        // (a repeated edit changes nothing, a repeated delete is done).
        MessageError::Db(DbError::Contended(e)) => {
            tracing::warn!(error = %e, "message command: contended");
            WsError::service_unavailable("the channel is busy; retry", 1)
        }
        MessageError::Db(e) => {
            tracing::error!(error = %e, "message command failed");
            WsError::internal("internal error")
        }
    }
}

/// `data` as a `T`, or the `bad_request` §7.1 asks for.
fn parse<T: DeserializeOwned>(cmd: &Command) -> Result<T, WsError> {
    serde_json::from_value(cmd.data.clone()).map_err(|e| {
        WsError::bad_request(format!("{} data does not match its schema: {e}", cmd.kind))
    })
}

/// `data` without the fields that name the target, as the body the REST
/// route would receive.
fn body_without(data: &Value, names: &[&str]) -> Value {
    let mut body = data.clone();
    if let Some(object) = body.as_object_mut() {
        for name in names {
            object.remove(*name);
        }
    }
    body
}

impl Session {
    /// Run one of the [`MESSAGE_COMMANDS`]. Without a message log
    /// ([`super::Hub::messages`]) the connection dispatcher answers them
    /// as unsupported before they get here.
    pub(super) async fn message_command(&self, cmd: &Command, typing: Option<&mut Typing>) {
        let (Some(messages), Some(typing)) = (self.hub.messages(), typing) else {
            let e = WsError::bad_request(format!("{} is not supported by this provider", cmd.kind));
            return self.error(&cmd.id, &e);
        };
        let origin = Origin {
            conn: self.id,
            correlation_id: cmd.id.clone(),
        };
        let done = match cmd.kind.as_str() {
            "message.create" => self.create(messages, cmd, &origin).await,
            "message.update" => self.update(messages, cmd, &origin).await,
            "message.delete" => self.delete(messages, cmd, &origin).await,
            "reaction.add" => self.react(messages, cmd, &origin).await,
            "reaction.remove" => self.unreact(messages, cmd, &origin).await,
            "typing.start" => self.typing(messages, cmd, typing, true).await,
            "typing.stop" => self.typing(messages, cmd, typing, false).await,
            _ => Ok(()),
        };
        if let Err(e) = done {
            self.error(&cmd.id, &e);
        }
    }

    /// Answer the requester alone with `live`, correlated with `cmd`.
    fn answer(&self, cmd: &Command, live: &Live) {
        self.send(protocol::event(
            live.kind(),
            Some(&cmd.id),
            live.data(),
            self.hub.now(),
        ));
    }

    async fn create(
        &self,
        messages: &Arc<Messages>,
        cmd: &Command,
        origin: &Origin,
    ) -> Result<(), WsError> {
        let t: ChannelTarget = parse(cmd)?;
        let body = body_without(&cmd.data, &["groupId", "channelId"]);
        let created = messages
            .create(
                &self.actor,
                t.group_id.as_str(),
                t.channel_id.as_str(),
                body,
                Some(origin),
            )
            .await
            .map_err(ws_error)?;
        if let Created::Existing(m) = created {
            self.answer(cmd, &Live::Created(channel_message(&m, None)));
        }
        Ok(())
    }

    async fn update(
        &self,
        messages: &Arc<Messages>,
        cmd: &Command,
        origin: &Origin,
    ) -> Result<(), WsError> {
        let t: MessageTarget = parse(cmd)?;
        let body = body_without(&cmd.data, &["groupId", "channelId", "messageId"]);
        messages
            .edit(
                &self.actor,
                t.group_id.as_str(),
                t.channel_id.as_str(),
                t.message_id.as_str(),
                body,
                Some(origin),
            )
            .await
            .map_err(ws_error)?;
        Ok(())
    }

    async fn delete(
        &self,
        messages: &Arc<Messages>,
        cmd: &Command,
        origin: &Origin,
    ) -> Result<(), WsError> {
        let d: ChannelMessageDelete = parse(cmd)?;
        let deleted = messages
            .delete(
                &self.actor,
                d.group_id.as_str(),
                d.channel_id.as_str(),
                d.message_id.as_str(),
                Some(origin),
            )
            .await
            .map_err(ws_error)?;
        if let Deleted::Already(m) = deleted {
            self.answer(cmd, &Live::Deleted(message_deleted(&m, None)));
        }
        Ok(())
    }

    async fn react(
        &self,
        messages: &Arc<Messages>,
        cmd: &Command,
        origin: &Origin,
    ) -> Result<(), WsError> {
        let r: ReactionAdd = parse(cmd)?;
        let put = ReactionPut {
            unicode: r.unicode,
            image: r.image,
        };
        let added = messages
            .add_reaction(
                &self.actor,
                r.group_id.as_str(),
                r.channel_id.as_str(),
                r.message_id.as_str(),
                &r.key,
                &put,
                Some(origin),
            )
            .await
            .map_err(ws_error)?;
        if let Added::Existing(reaction) = added {
            let live = Live::ReactionAdded(ReactionAdded {
                group_id: r.group_id,
                channel_id: r.channel_id,
                reaction: reaction.to_wire(),
            });
            self.answer(cmd, &live);
        }
        Ok(())
    }

    async fn unreact(
        &self,
        messages: &Arc<Messages>,
        cmd: &Command,
        origin: &Origin,
    ) -> Result<(), WsError> {
        let r: ReactionRemove = parse(cmd)?;
        let removed = messages
            .remove_reaction(
                &self.actor,
                r.group_id.as_str(),
                r.channel_id.as_str(),
                r.message_id.as_str(),
                &r.key,
                Some(origin),
            )
            .await
            .map_err(ws_error)?;
        if !removed {
            let live = Live::ReactionRemoved(ReactionRemoved {
                group_id: r.group_id,
                channel_id: r.channel_id,
                message_id: r.message_id,
                key: r.key,
                author: self.actor.clone(),
            });
            self.answer(cmd, &live);
        }
        Ok(())
    }

    /// `typing.start` / `typing.stop`: no answer on success; the event is
    /// `channel.typing` to the channel's readers. Both need read access,
    /// so a `stop` cannot probe a private channel either.
    async fn typing(
        &self,
        messages: &Arc<Messages>,
        cmd: &Command,
        typing: &mut Typing,
        start: bool,
    ) -> Result<(), WsError> {
        let t: TypingCommand = parse(cmd)?;
        let group_id = messages
            .typing_target(&self.actor, &t.channel_id)
            .await
            .map_err(ws_error)?;
        if start {
            typing.start(group_id, &t.channel_id).await;
        } else {
            typing.stop(&t.channel_id).await;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_target_fields_are_not_part_of_the_body() {
        let data = serde_json::json!({
            "groupId": "g", "channelId": "c", "messageId": "m",
            "content": { "mime": "text/plain", "text": "hi" }
        });
        let body = body_without(&data, &["groupId", "channelId", "messageId"]);
        assert_eq!(
            body,
            serde_json::json!({ "content": { "mime": "text/plain", "text": "hi" } })
        );
    }

    #[test]
    fn message_errors_keep_their_codes() {
        assert_eq!(ws_error(MessageError::NotFound("x")).code, "not_found");
        assert_eq!(ws_error(MessageError::Forbidden("x")).code, "forbidden");
        assert_eq!(ws_error(MessageError::Conflict("x")).code, "conflict");
        let e = ws_error(MessageError::Db(DbError::Unavailable("down".into())));
        assert_eq!(e.code, "service_unavailable");
        let e = ws_error(MessageError::Db(DbError::Contended("busy".into())));
        assert_eq!(e.code, "service_unavailable");
    }
}
