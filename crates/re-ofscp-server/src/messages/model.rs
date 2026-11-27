//! Messages and reactions as this provider stores them (`Message`,
//! `Reaction` in `schema.rhype`), and their wire form (§5.3).
//!
//! The columns are what queries select on or the server decides with
//! (positions, author, type, parent, counters, times); the body is one JSON
//! document, [`MessageDoc`], written and read whole.

use ofscp_core::wire::{
    Attachment, Content, Message, MessagePermissions, MessageReference, MessageType,
    MetadataObject, Reaction, ReferenceKind, Timestamp,
};
use ofscp_core::{Actor, LocalId};
use serde::{Deserialize, Serialize};

use crate::timefmt;

/// The body of a message, stored as JSON in `Message.doc`. A tombstone's
/// is [`MessageDoc::default`]: everything the author wrote is gone (§7.1).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageDoc {
    /// The body (§5.3 *Content formats*); `None` only in a tombstone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<Content>,
    /// The attachments, as checked by §5.8.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<Attachment>,
    /// The tags, when given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    /// The mentions, when given (§5.3 *Mentions*).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mentions: Option<Vec<Actor>>,
    /// An article's title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// An article's summary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// An article's cover: the id of one of its attachments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cover: Option<LocalId>,
    /// Metadata objects (§5.4).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub metadata: Vec<MetadataObject>,
}

/// A message, as stored.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredMessage {
    /// Its id (`msg_…`).
    pub id: LocalId,
    /// Its channel.
    pub channel_id: LocalId,
    /// The channel's group.
    pub group_id: LocalId,
    /// Its creation position in the channel's timeline.
    pub seq: i64,
    /// Its creation ordinal among the channel's messages (§7.7 counts;
    /// docs/decisions/0021): `None` on a message from before ordinals until
    /// its channel is numbered (`ordinals.rs`).
    pub n: Option<i64>,
    /// The idempotency key the create carried (§7.1), if any.
    pub client_message_id: Option<String>,
    /// The canonical author.
    pub author: Actor,
    /// Its type.
    pub kind: MessageType,
    /// The parent it replies to, if any.
    pub parent_id: Option<LocalId>,
    /// Its position among its parent's replies, for a reply.
    pub reply_n: Option<i64>,
    /// Reply positions handed out so far.
    pub reply_seq: i64,
    /// Reaction positions handed out so far.
    pub reaction_seq: i64,
    /// The body.
    pub doc: MessageDoc,
    /// When it was created.
    pub created_at: Timestamp,
    /// Until when its author may edit it (unix seconds), if limited.
    pub edit_until: Option<i64>,
    /// When it was last edited (unix seconds).
    pub edited_at: Option<i64>,
    /// How many edits it has had (the edit compare-and-set's version).
    pub revision: i64,
    /// When it was deleted (unix seconds): it is a tombstone.
    pub deleted_at: Option<i64>,
}

impl StoredMessage {
    /// Whether it is a tombstone.
    pub fn is_deleted(&self) -> bool {
        self.deleted_at.is_some()
    }

    /// The wire form (§5.3). A tombstone keeps its id, author, type,
    /// reference and times, and carries `deletedAt` and nothing its author
    /// wrote (§7.1). `clientMessageId` is included in every copy: the spec
    /// requires it on the author's and allows it on the rest (§7.1).
    pub fn to_wire(&self) -> Message {
        let doc = &self.doc;
        Message {
            id: self.id.clone(),
            client_message_id: self.client_message_id.clone(),
            author: self.author.clone(),
            kind: self.kind.clone(),
            // `content` is required even of a tombstone (`BaseMessage`):
            // its cleared body is empty plain text, as Forumall's is.
            content: Some(doc.content.clone().unwrap_or_else(cleared_content)),
            attachments: doc.attachments.clone(),
            reference: self.parent_id.clone().map(|id| MessageReference {
                kind: ReferenceKind::Reply,
                id,
                // Absent: the parent is in the same channel, on this
                // provider (lost-conn/ofscp#34).
                provider: None,
            }),
            tags: doc.tags.clone(),
            mentions: doc.mentions.clone(),
            title: doc.title.clone(),
            summary: doc.summary.clone(),
            cover: doc.cover.clone(),
            reply_count: None,
            created_at: self.created_at,
            edited_at: self.edited_at.map(timefmt::timestamp),
            deleted_at: self.deleted_at.map(timefmt::timestamp),
            permissions: match (self.deleted_at, self.edit_until) {
                (None, Some(until)) => Some(MessagePermissions {
                    edit_until: Some(timefmt::timestamp(until)),
                }),
                _ => None,
            },
            metadata: doc.metadata.clone(),
        }
    }
}

/// The body a tombstone carries: cleared (§7.1), but present, since the
/// message schema requires `content`.
fn cleared_content() -> Content {
    Content {
        text: String::new(),
        mime: "text/plain".to_owned(),
    }
}

/// A reaction, as stored.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredReaction {
    /// Its id (`rct_…`).
    pub id: LocalId,
    /// The message it is on.
    pub message_id: LocalId,
    /// Its position among the message's reactions.
    pub n: i64,
    /// Who reacted.
    pub author: Actor,
    /// Which reaction.
    pub key: String,
    /// Its emoji, if given.
    pub unicode: Option<String>,
    /// Its picture (HTTPS), if given.
    pub image: Option<String>,
    /// When.
    pub created_at: Timestamp,
}

impl StoredReaction {
    /// The wire form (§5.3).
    pub fn to_wire(&self) -> Reaction {
        Reaction {
            id: self.id.clone(),
            author: self.author.clone(),
            key: self.key.clone(),
            unicode: self.unicode.clone(),
            image: self.image.clone(),
            reference: MessageReference {
                kind: ReferenceKind::Message,
                id: self.message_id.clone(),
                // Absent: the message is on this provider.
                provider: None,
            },
            created_at: self.created_at,
            metadata: Vec::new(),
        }
    }
}
