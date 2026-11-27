//! Creating, editing, deleting and reading channel messages (§7.1, §7.2),
//! each with the order of checks §7.1 gives: visibility (`404`), then
//! permissions (`403`), then the body (`400`).

use std::collections::HashMap;

use ofscp_core::Actor;
use ofscp_core::wire::{MessageCreate, MessageUpdate, MessagesPage, ReferenceKind, TimelineItem};
use ofscp_core::ws::{ChannelMessage, MessageDeleted};
use serde_json::Value;

use super::fanout::{Live, Origin};
use super::model::StoredMessage;
use super::pager::{self, BadCursor, CursorKind, PageRequest};
use super::store::{Counter, NewMessage, event_kind};
use super::validate::{self, AttachmentError, Head, Invalid};
use super::{Messages, edit_window, log};
use crate::db::DbError;
use crate::groups::Caller;
use crate::groups::access::{self, ReplyRule, actions};
use crate::groups::model::StoredChannel;
use crate::groups::ops::{GroupError, ReadableGroup};
use crate::timefmt;

/// Why a message operation failed. Each maps to one problem (§7.3).
#[derive(Debug, thiserror::Error)]
pub enum MessageError {
    /// `404`: no such group, channel or message, or a channel the caller
    /// cannot read (§11.3).
    #[error("{0}")]
    NotFound(&'static str),
    /// `403`: the caller may not do this.
    #[error("{0}")]
    Forbidden(&'static str),
    /// `400`: the request is invalid.
    #[error(transparent)]
    Invalid(#[from] Invalid),
    /// `400`: a cursor this endpoint did not issue.
    #[error(transparent)]
    BadCursor(#[from] BadCursor),
    /// `409`: the change could not be applied; retry.
    #[error("{0}")]
    Conflict(&'static str),
    /// The database failed.
    #[error(transparent)]
    Db(#[from] DbError),
}

impl From<GroupError> for MessageError {
    fn from(e: GroupError) -> Self {
        match e {
            GroupError::NotFound(d) => Self::NotFound(d),
            GroupError::Forbidden(d) => Self::Forbidden(d),
            GroupError::Invalid(i) => Self::Invalid(Invalid(i.0)),
            GroupError::Conflict(d) => Self::Conflict(d),
            GroupError::Db(e) => Self::Db(e),
        }
    }
}

impl From<AttachmentError> for MessageError {
    fn from(e: AttachmentError) -> Self {
        match e {
            AttachmentError::Invalid(i) => Self::Invalid(i),
            AttachmentError::Db(e) => Self::Db(e),
        }
    }
}

const NO_CHANNEL: &str = "no such channel";
const NO_MESSAGE: &str = "no such message";
const MAY_NOT_POST: &str = "you may not post messages of this type in this channel";
const REPLIES_ONLY: &str = "you may only reply in this channel";
const REPLY_TYPE: &str = "you may not reply to messages of this type in this channel";
const NOT_AUTHOR: &str = "only the author may edit a message";
const EDIT_CLOSED: &str = "the edit window of this message has closed";
const MAY_NOT_DELETE: &str = "only the author or a moderator may delete a message";

/// How a delete was answered.
#[derive(Debug, Clone, PartialEq)]
pub enum Deleted {
    /// The message is now a tombstone, and `message.deleted` fanned out.
    Now,
    /// It already was one; nothing changed and nothing fanned out.
    Already(Box<StoredMessage>),
}

/// How a create was answered (§7.1).
#[derive(Debug, Clone, PartialEq)]
pub enum Created {
    /// A new message (`201`).
    New(StoredMessage),
    /// The message an earlier create with the same `clientMessageId`
    /// made, as it now stands (`200`).
    Existing(StoredMessage),
}

fn bad(e: serde_json::Error) -> MessageError {
    MessageError::Invalid(Invalid(format!("the body does not match the schema: {e}")))
}

impl Messages {
    /// The channel, if `caller` can read it (`404` otherwise, §11.3).
    pub(super) async fn readable(
        &self,
        caller: &Caller,
        group_id: &str,
        channel_id: &str,
    ) -> Result<(ReadableGroup, StoredChannel), MessageError> {
        Ok(self
            .groups
            .read_channel(caller, group_id, channel_id)
            .await?)
    }

    /// Message `message_id` of the channel: `404` if there is none.
    pub(super) async fn existing(
        &self,
        channel_id: &str,
        message_id: &str,
    ) -> Result<StoredMessage, MessageError> {
        self.store
            .message(channel_id, message_id)
            .await?
            .ok_or(MessageError::NotFound(NO_MESSAGE))
    }

    /// Make sure the channel has an open log, and that a log this call
    /// opened belongs to a channel that still exists: a channel deleted
    /// before its first message never had a log to close (`log.rs`).
    async fn ensure_log(&self, group_id: &str, channel_id: &str) -> Result<(), MessageError> {
        let db = self.store.db();
        match log::read(db, channel_id).await? {
            log::LogState::Open { .. } => return Ok(()),
            log::LogState::Closed => return Err(MessageError::NotFound(NO_CHANNEL)),
            log::LogState::Absent => {}
        }
        if !matches!(
            log::open(db, group_id, channel_id).await?,
            log::LogState::Open { .. }
        ) {
            return Err(MessageError::NotFound(NO_CHANNEL));
        }
        if self.groups.channel_group(channel_id).await?.as_deref() != Some(group_id) {
            log::close_channel(db, group_id, channel_id).await?;
            return Err(MessageError::NotFound(NO_CHANNEL));
        }
        Ok(())
    }

    /// The next position of the channel's timeline: `404` once the channel
    /// is deleted.
    async fn take_position(&self, group_id: &str, channel_id: &str) -> Result<i64, MessageError> {
        self.ensure_log(group_id, channel_id).await?;
        log::take(self.store.db(), channel_id)
            .await?
            .ok_or(MessageError::NotFound(NO_CHANNEL))
    }

    /// `POST …/messages` and `message.create` (§7.1): `body` is the
    /// `MessageCreate` as received.
    pub async fn create(
        &self,
        actor: &Actor,
        group_id: &str,
        channel_id: &str,
        body: Value,
        origin: Option<&Origin>,
    ) -> Result<Created, MessageError> {
        // 1. What the next steps need from the body.
        let head = validate::head(&body)?;
        // 2. Visibility.
        let caller = Caller::Actor(actor.clone());
        let (g, channel) = self.readable(&caller, group_id, channel_id).await?;
        let (policy, cpolicy) = (g.group.policy(), channel.policy());
        // 3. Permissions that depend only on the actor and the request.
        if !access::may_post(&g.standing, &policy, &cpolicy, head.kind.as_str()) {
            return Err(MessageError::Forbidden(MAY_NOT_POST));
        }
        let rule = access::reply_rule(&g.standing, &policy, &cpolicy);
        if matches!(rule, ReplyRule::RepliesOnly { .. }) && !head.has_reference {
            return Err(MessageError::Forbidden(REPLIES_ONLY));
        }
        // 4. Duplicate lookup.
        if let Some(cmid) = &head.client_message_id
            && let Some(m) = self.store.by_client_key(channel_id, actor, cmid).await?
        {
            return Ok(Created::Existing(m));
        }
        // 5. Everything else.
        let req: MessageCreate = serde_json::from_value(body).map_err(bad)?;
        let parent = self.parent(channel_id, &req, &rule).await?;
        let attachments = validate::attachments(
            self.uploads.as_ref(),
            actor,
            actor.is_local_to(&self.home),
            req.attachments.as_deref().unwrap_or_default(),
        )
        .await?;
        let doc = validate::new_doc(&head.kind, &req, attachments)?;
        self.write_new(actor, group_id, channel_id, &head, parent, &doc, origin)
            .await
    }

    /// The parent a create's `reference` names, checked (§7.1, §7.2): a
    /// message of this channel (a tombstone too), of a type `replyOnlyTo`
    /// lists when the author is reply-restricted.
    async fn parent(
        &self,
        channel_id: &str,
        req: &MessageCreate,
        rule: &ReplyRule,
    ) -> Result<Option<StoredMessage>, MessageError> {
        let Some(reference) = &req.reference else {
            return Ok(None);
        };
        if reference.kind != ReferenceKind::Reply {
            return Err(Invalid("reference.type must be \"reply\"".to_owned()).into());
        }
        let parent = self
            .store
            .message(channel_id, reference.id.as_str())
            .await?
            .ok_or_else(|| Invalid("reference.id is not a message in this channel".to_owned()))?;
        if let ReplyRule::RepliesOnly { to: Some(types) } = rule
            && !types.iter().any(|t| t == parent.kind.as_str())
        {
            return Err(MessageError::Forbidden(REPLY_TYPE));
        }
        Ok(Some(parent))
    }

    /// Write a checked new message and fan it out, under the channel lock.
    #[allow(clippy::too_many_arguments)]
    async fn write_new(
        &self,
        actor: &Actor,
        group_id: &str,
        channel_id: &str,
        head: &Head,
        parent: Option<StoredMessage>,
        doc: &super::model::MessageDoc,
        origin: Option<&Origin>,
    ) -> Result<Created, MessageError> {
        let _turn = self.locks.lock(channel_id).await;
        let seq = self.take_position(group_id, channel_id).await?;
        let reply = match &parent {
            Some(p) => Some((
                &p.id,
                self.store
                    .take_counter(&p.id, Counter::Replies)
                    .await?
                    .ok_or_else(|| {
                        Invalid("reference.id is not a message in this channel".to_owned())
                    })?,
            )),
            None => None,
        };
        let now = self.now();
        let new = NewMessage {
            channel_id,
            group_id,
            seq,
            client_message_id: head.client_message_id.as_deref(),
            author: actor,
            kind: &head.kind,
            reply,
            doc,
            now,
            edit_until: edit_window(&head.kind).map(|w| now.saturating_add(w.as_secs() as i64)),
        };
        let message = match self.store.insert(&new).await {
            Ok(m) => m,
            // A concurrent create with the same key won (from another
            // process: this one holds the channel lock).
            Err(DbError::Conflict(e)) => match &head.client_message_id {
                Some(cmid) => {
                    return match self.store.by_client_key(channel_id, actor, cmid).await? {
                        Some(m) => Ok(Created::Existing(m)),
                        None => Err(DbError::Conflict(e).into()),
                    };
                }
                None => return Err(DbError::Conflict(e).into()),
            },
            Err(e) => return Err(e.into()),
        };
        // A delete of the channel that closed its log after this write
        // took its position may have purged before the write landed: take
        // the write back (the sweeper's second purge is the backstop).
        if !matches!(
            log::read(self.store.db(), channel_id).await?,
            log::LogState::Open { .. }
        ) {
            self.store.remove(&message.id).await?;
            return Err(MessageError::NotFound(NO_CHANNEL));
        }
        let live = Live::Created(channel_message(&message, Some(seq)));
        self.fanout
            .deliver(group_id, channel_id, live, origin)
            .await;
        Ok(Created::New(message))
    }

    /// `PATCH …/messages/{messageId}` and `message.update` (§7.1): `body`
    /// is the `MessageUpdate` as received.
    pub async fn edit(
        &self,
        actor: &Actor,
        group_id: &str,
        channel_id: &str,
        message_id: &str,
        body: Value,
        origin: Option<&Origin>,
    ) -> Result<StoredMessage, MessageError> {
        let caller = Caller::Actor(actor.clone());
        self.readable(&caller, group_id, channel_id).await?;
        let message = self.existing(channel_id, message_id).await?;
        // A tombstone has nothing left to edit (decision 0017).
        if message.is_deleted() {
            return Err(MessageError::NotFound(NO_MESSAGE));
        }
        if message.author != *actor {
            return Err(MessageError::Forbidden(NOT_AUTHOR));
        }
        if message.edit_until.is_some_and(|until| self.now() >= until) {
            return Err(MessageError::Forbidden(EDIT_CLOSED));
        }
        let edit: MessageUpdate = serde_json::from_value(body).map_err(bad)?;
        validate::edit_shape(&message.kind, &edit)?;
        let attachments = match &edit.attachments {
            Some(list) => Some(
                validate::attachments(
                    self.uploads.as_ref(),
                    actor,
                    actor.is_local_to(&self.home),
                    list,
                )
                .await?,
            ),
            None => None,
        };
        let doc = validate::edited_doc(&message.kind, &message.doc, &edit, attachments)?;

        let _turn = self.locks.lock(channel_id).await;
        let seq = self.take_position(group_id, channel_id).await?;
        let now = self.now();
        let edited = self
            .store
            .update_doc(&message.id, &doc, now)
            .await?
            .ok_or(MessageError::NotFound(NO_MESSAGE))?;
        self.store
            .insert_event(
                channel_id,
                group_id,
                seq,
                event_kind::UPDATED,
                &edited.id,
                now,
            )
            .await?;
        let live = Live::Updated(channel_message(&edited, Some(seq)));
        self.fanout
            .deliver(group_id, channel_id, live, origin)
            .await;
        Ok(edited)
    }

    /// `DELETE …/messages/{messageId}` and `message.delete` (§7.1): the
    /// author or a holder of the group's `moderate` may delete. Deleting a
    /// tombstone again changes nothing and fans out nothing.
    pub async fn delete(
        &self,
        actor: &Actor,
        group_id: &str,
        channel_id: &str,
        message_id: &str,
        origin: Option<&Origin>,
    ) -> Result<Deleted, MessageError> {
        let caller = Caller::Actor(actor.clone());
        let (g, _) = self.readable(&caller, group_id, channel_id).await?;
        let message = self.existing(channel_id, message_id).await?;
        let moderator = access::may(&g.standing, &g.group.policy(), actions::MODERATE);
        if message.author != *actor && !moderator {
            return Err(MessageError::Forbidden(MAY_NOT_DELETE));
        }
        if message.is_deleted() {
            return Ok(Deleted::Already(Box::new(message)));
        }
        let _turn = self.locks.lock(channel_id).await;
        let seq = self.take_position(group_id, channel_id).await?;
        let now = self.now();
        let Some(gone) = self.store.tombstone(&message.id, now).await? else {
            // Deleted meanwhile, by another process: nothing more to do.
            return Ok(Deleted::Already(Box::new(
                self.existing(channel_id, message_id).await?,
            )));
        };
        self.store
            .insert_event(
                channel_id,
                group_id,
                seq,
                event_kind::DELETED,
                &gone.id,
                now,
            )
            .await?;
        let live = Live::Deleted(message_deleted(&gone, Some(seq)));
        self.fanout
            .deliver(group_id, channel_id, live, origin)
            .await;
        Ok(Deleted::Now)
    }

    /// `GET …/messages/{messageId}`: the message, a tombstone too.
    pub async fn get(
        &self,
        caller: &Caller,
        group_id: &str,
        channel_id: &str,
        message_id: &str,
    ) -> Result<StoredMessage, MessageError> {
        self.readable(caller, group_id, channel_id).await?;
        self.existing(channel_id, message_id).await
    }

    /// `GET …/messages` (§7.2): one page of the channel's messages,
    /// tombstones included, in timeline order.
    pub async fn history(
        &self,
        caller: &Caller,
        group_id: &str,
        channel_id: &str,
        query: &HashMap<String, String>,
    ) -> Result<MessagesPage, MessageError> {
        let req = PageRequest::from_query(CursorKind::Timeline, query)?;
        self.readable(caller, group_id, channel_id).await?;
        let last = log::read(self.store.db(), channel_id).await?.last();
        let store = &self.store;
        let walked = pager::walk(CursorKind::Timeline, req, last, |positions| async move {
            store.at_positions(channel_id, &positions).await
        })
        .await?;
        Ok(page(walked))
    }

    /// `GET …/messages/{messageId}/replies` (§7.2): one page of the
    /// message's replies, in the order they were written.
    pub async fn replies(
        &self,
        caller: &Caller,
        group_id: &str,
        channel_id: &str,
        message_id: &str,
        query: &HashMap<String, String>,
    ) -> Result<MessagesPage, MessageError> {
        let req = PageRequest::from_query(CursorKind::Replies, query)?;
        self.readable(caller, group_id, channel_id).await?;
        let parent = self.existing(channel_id, message_id).await?;
        let store = &self.store;
        let id = &parent.id;
        let walked = pager::walk(
            CursorKind::Replies,
            req,
            parent.reply_seq,
            |ns| async move { store.replies_at(id, &ns).await },
        )
        .await?;
        Ok(page(walked))
    }
}

fn page(walked: pager::Walked<StoredMessage>) -> MessagesPage {
    MessagesPage {
        items: walked
            .items
            .into_iter()
            .map(|(_, m)| TimelineItem::Message(Box::new(m.to_wire())))
            .collect(),
        page: walked.page,
    }
}

/// The `message.created` / `message.updated` data for `m`, with the
/// timeline cursor of position `seq` when it is a timeline event.
pub fn channel_message(m: &StoredMessage, seq: Option<i64>) -> ChannelMessage {
    ChannelMessage {
        group_id: m.group_id.clone(),
        channel_id: m.channel_id.clone(),
        cursor: seq.map(|s| pager::encode_cursor(CursorKind::Timeline, s)),
        message: Box::new(m.to_wire()),
    }
}

/// The `message.deleted` data for the tombstone `m`, with the timeline
/// cursor of position `seq` when it is a timeline event.
pub fn message_deleted(m: &StoredMessage, seq: Option<i64>) -> MessageDeleted {
    MessageDeleted {
        group_id: m.group_id.clone(),
        channel_id: m.channel_id.clone(),
        cursor: seq.map(|s| pager::encode_cursor(CursorKind::Timeline, s)),
        message_id: m.id.clone(),
        deleted_at: m.deleted_at.map(timefmt::timestamp),
    }
}
