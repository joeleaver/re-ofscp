//! Messages, reactions and timelines (spec §5.3, §7.1, §7.2).

use serde::{Deserialize, Serialize};

use crate::{Actor, Authority, LocalId};

use super::{Attachment, Content, MetadataObject, Paged, Patch, Timestamp, open_enum, some};

open_enum! {
    /// What a message is (§5.3). An unknown type is shown as a plain
    /// message, as well as its content allows (§2.3).
    pub enum MessageType {
        /// A chat line.
        Message = "message",
        /// A short post.
        Memo = "memo",
        /// A long post.
        Article = "article",
        /// A reaction, in discovery's `messageTypes` (§3.1).
        Reaction = "reaction",
    }
}

open_enum! {
    /// What a reference points at (§5.3).
    pub enum ReferenceKind {
        /// The message this one replies to.
        Reply = "reply",
        /// The message a reaction is on.
        Message = "message",
    }
}

/// A pointer from one message or reaction to another message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageReference {
    /// What kind of pointer.
    #[serde(rename = "type")]
    pub kind: ReferenceKind,
    /// The message's local id, issued by the provider that holds it (§2.2).
    pub id: LocalId,
    /// The provider holding the message, as a canonical authority (§2.2,
    /// §5.3; lost-conn/ofscp#34). The message is identified by
    /// `(provider, id)`. Absent, or equal to the authority of the provider
    /// holding the message that carries this reference, means that same
    /// provider: the two must be treated exactly alike. Only a DM reply can
    /// name another provider (§7.4); a present value must hold an
    /// authority, so `null` is refused.
    #[serde(
        default,
        deserialize_with = "some",
        skip_serializing_if = "Option::is_none"
    )]
    pub provider: Option<Authority>,
}

/// What the reader may do with a message.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessagePermissions {
    /// Until when its author may edit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edit_until: Option<Timestamp>,
}

/// A message in a channel or a private conversation (§5.3, `BaseMessage`).
/// A deleted one is a tombstone: `deleted_at` is set and its content is
/// cleared (§7.1), so `content` may be absent or `null`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Message {
    /// The message's local id.
    pub id: LocalId,
    /// The id its author's client gave it, for matching the echo of a send.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_message_id: Option<String>,
    /// Who wrote it.
    pub author: Actor,
    /// What it is.
    #[serde(rename = "type")]
    pub kind: MessageType,
    /// What it says; `None` on a tombstone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<Content>,
    /// Files attached to it.
    #[serde(default)]
    pub attachments: Vec<Attachment>,
    /// The message it replies to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<MessageReference>,
    /// Tags.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    /// Who it mentions, set by the author's client (§5.3, *Mentions*).
    /// When present it is authoritative for mention notifications (§10.1);
    /// when absent, mentions are parsed from the text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mentions: Option<Vec<Actor>>,
    /// An article's title, plain text (§5.3); ignored on other types.
    /// When absent, a level-1 heading opening the body is the title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// An article's summary, plain text (§5.3); ignored on other types.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// An article's cover: the id of one of its own `attachments` (§5.3);
    /// ignored on other types.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cover: Option<LocalId>,
    /// How many replies it has.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_count: Option<u64>,
    /// When it was sent.
    pub created_at: Timestamp,
    /// When it was last edited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edited_at: Option<Timestamp>,
    /// When it was deleted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<Timestamp>,
    /// What the reader may do with it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<MessagePermissions>,
    /// Extension data.
    #[serde(default)]
    pub metadata: Vec<MetadataObject>,
}

/// A new channel message: `POST .../messages`, or the `message.create`
/// command (§7.1, `MessageCreate`). Sending again with the same
/// `client_message_id` is not an error; the provider answers with the first.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageCreate {
    /// The client's own id for it.
    #[serde(
        default,
        deserialize_with = "some",
        skip_serializing_if = "Option::is_none"
    )]
    pub client_message_id: Option<String>,
    /// What it is (a plain message when left out).
    #[serde(
        default,
        rename = "type",
        deserialize_with = "some",
        skip_serializing_if = "Option::is_none"
    )]
    pub kind: Option<MessageType>,
    /// What it says.
    pub content: Content,
    /// Files attached, uploaded first to `/api/media`.
    #[serde(
        default,
        deserialize_with = "some",
        skip_serializing_if = "Option::is_none"
    )]
    pub attachments: Option<Vec<Attachment>>,
    /// The message it replies to (kind `reply`).
    #[serde(
        default,
        deserialize_with = "some",
        skip_serializing_if = "Option::is_none"
    )]
    pub reference: Option<MessageReference>,
    /// Tags.
    #[serde(
        default,
        deserialize_with = "some",
        skip_serializing_if = "Option::is_none"
    )]
    pub tags: Option<Vec<String>>,
    /// Who it mentions, set by the author's client (§5.3, *Mentions*).
    /// When present it is authoritative for mention notifications (§10.1);
    /// when absent, mentions are parsed from the text.
    #[serde(
        default,
        deserialize_with = "some",
        skip_serializing_if = "Option::is_none"
    )]
    pub mentions: Option<Vec<Actor>>,
    /// An article's title, plain text (§5.3); ignored on other types.
    /// When absent, a level-1 heading opening the body is the title.
    #[serde(
        default,
        deserialize_with = "some",
        skip_serializing_if = "Option::is_none"
    )]
    pub title: Option<String>,
    /// An article's summary, plain text (§5.3); ignored on other types.
    #[serde(
        default,
        deserialize_with = "some",
        skip_serializing_if = "Option::is_none"
    )]
    pub summary: Option<String>,
    /// An article's cover: the id of one of its own `attachments` (§5.3);
    /// ignored on other types.
    #[serde(
        default,
        deserialize_with = "some",
        skip_serializing_if = "Option::is_none"
    )]
    pub cover: Option<LocalId>,
    /// Extension data.
    #[serde(
        default,
        deserialize_with = "some",
        skip_serializing_if = "Option::is_none"
    )]
    pub metadata: Option<Vec<MetadataObject>>,
}

/// An edit (§7.1, `MessageUpdate`): the body of `PATCH .../messages/{messageId}`
/// in a channel or a DM (§7.4, §8.3), and the data of the `message.update`
/// command less its ids. Each field present replaces the stored one; an
/// absent field is unchanged. `type`, `reference` and `metadata` cannot be
/// edited, so they are not here (and are ignored if sent).
///
/// The provider refuses (`400`) an edit that [`is_empty`](Self::is_empty),
/// and an edit of a message that is not an article that
/// [`has_only_article_fields`](Self::has_only_article_fields).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageUpdate {
    /// The new content.
    #[serde(
        default,
        deserialize_with = "some",
        skip_serializing_if = "Option::is_none"
    )]
    pub content: Option<Content>,
    /// The new attachments, in full; one left out loses this message's
    /// reference to it (§5.8, *Revocation*).
    #[serde(
        default,
        deserialize_with = "some",
        skip_serializing_if = "Option::is_none"
    )]
    pub attachments: Option<Vec<Attachment>>,
    /// The new tags, in full.
    #[serde(
        default,
        deserialize_with = "some",
        skip_serializing_if = "Option::is_none"
    )]
    pub tags: Option<Vec<String>>,
    /// The new mentions, in full (§5.3).
    #[serde(
        default,
        deserialize_with = "some",
        skip_serializing_if = "Option::is_none"
    )]
    pub mentions: Option<Vec<Actor>>,
    /// An article's new title, or `null` to remove it.
    #[serde(default, skip_serializing_if = "Patch::is_keep")]
    pub title: Patch<String>,
    /// An article's new summary, or `null` to remove it.
    #[serde(default, skip_serializing_if = "Patch::is_keep")]
    pub summary: Patch<String>,
    /// An article's new cover attachment id, or `null` to remove it. After
    /// the edit it must name one of the message's attachments.
    #[serde(default, skip_serializing_if = "Patch::is_keep")]
    pub cover: Patch<LocalId>,
}

impl MessageUpdate {
    /// Whether the edit changes nothing (the schema's `anyOf`).
    pub fn is_empty(&self) -> bool {
        !self.has_general_fields() && !self.has_article_fields()
    }

    /// Whether the edit carries article fields and nothing else, which is
    /// a `400` on a message that is not an article (§7.1).
    pub fn has_only_article_fields(&self) -> bool {
        self.has_article_fields() && !self.has_general_fields()
    }

    fn has_general_fields(&self) -> bool {
        self.content.is_some()
            || self.attachments.is_some()
            || self.tags.is_some()
            || self.mentions.is_some()
    }

    fn has_article_fields(&self) -> bool {
        !(self.title.is_keep() && self.summary.is_keep() && self.cover.is_keep())
    }
}

/// The body of `PUT …/messages/{messageId}/reactions/{key}`, in a channel
/// (§7.1) or a private conversation (§7.4): how to show the reaction whose
/// `key` the path names. The body is optional and so is each field; a
/// request with no body reads as [`ReactionPut::default`]. Neither field
/// requires the other. A present field must hold a value: `null` is refused.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactionPut {
    /// Its emoji.
    #[serde(
        default,
        deserialize_with = "some",
        skip_serializing_if = "Option::is_none"
    )]
    pub unicode: Option<String>,
    /// A picture of it (HTTPS).
    #[serde(
        default,
        deserialize_with = "some",
        skip_serializing_if = "Option::is_none"
    )]
    pub image: Option<String>,
}

/// A reaction on a message (§5.3). The provider keeps no counts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Reaction {
    /// The reaction's local id.
    pub id: LocalId,
    /// Who reacted.
    pub author: Actor,
    /// Which reaction, such as `heart`.
    pub key: String,
    /// Its emoji.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unicode: Option<String>,
    /// A picture of it (HTTPS).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// The message it is on (kind `message`).
    pub reference: MessageReference,
    /// When.
    pub created_at: Timestamp,
    /// Extension data.
    #[serde(default)]
    pub metadata: Vec<MetadataObject>,
}

/// One item of a channel's history: a message or a reaction (§7.2).
///
/// Reactions carry no type tag, so the two are told apart by their fields:
/// a message has `type` (and, unless it is a tombstone, `content`); a
/// reaction has neither, and has `key`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TimelineItem {
    /// A message, perhaps a tombstone.
    Message(Box<Message>),
    /// A reaction.
    Reaction(Box<Reaction>),
}

/// `GET .../messages` and `.../replies`: one page of history (§7.2).
pub type MessagesPage = Paged<TimelineItem>;

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn a_tombstone_decodes_alone_and_in_a_page() {
        let tombstone = json!({
            "id": "msg_999", "author": "jane@a.com", "type": "message",
            "attachments": [], "createdAt": "2026-01-01T12:00:00Z",
            "deletedAt": "2026-01-01T12:06:00Z", "metadata": []
        });
        let m: Message = serde_json::from_value(tombstone.clone()).unwrap();
        assert!(m.content.is_none() && m.deleted_at.is_some());
        assert_eq!(serde_json::to_value(&m).unwrap(), tombstone);

        let nulled = json!({
            "id": "msg_1", "author": "jane@a.com", "type": "memo", "content": null,
            "createdAt": "2026-01-01T12:00:00Z", "deletedAt": "2026-01-01T12:06:00Z"
        });
        assert!(
            serde_json::from_value::<Message>(nulled)
                .unwrap()
                .content
                .is_none()
        );

        let reaction = json!({
            "id": "rct_1", "author": "bob@b.com", "key": "heart",
            "reference": {"type": "message", "id": "msg_998"},
            "createdAt": "2026-01-01T12:01:00Z", "metadata": []
        });
        let page: MessagesPage = serde_json::from_value(json!({
            "items": [tombstone, reaction], "page": {}
        }))
        .unwrap();
        assert!(matches!(&page.items[0], TimelineItem::Message(m) if m.content.is_none()));
        assert!(matches!(&page.items[1], TimelineItem::Reaction(_)));
    }

    #[test]
    fn an_edit_tells_absent_from_null_and_refuses_null_where_it_means_nothing() {
        let body = json!({"title": "New", "summary": null, "tags": ["#a"]});
        let u: MessageUpdate = serde_json::from_value(body.clone()).unwrap();
        assert_eq!(u.title, Patch::Set("New".to_owned()));
        assert_eq!(u.summary, Patch::Clear);
        assert_eq!(u.cover, Patch::Keep);
        assert_eq!(serde_json::to_value(&u).unwrap(), body);
        for field in ["content", "attachments", "tags", "mentions"] {
            let body = json!({ field: null });
            assert!(serde_json::from_value::<MessageUpdate>(body).is_err());
        }
    }

    #[test]
    fn an_edit_knows_when_it_is_empty_or_only_for_articles() {
        let empty: MessageUpdate =
            serde_json::from_value(json!({"type": "memo", "metadata": []})).unwrap();
        assert!(empty.is_empty() && !empty.has_only_article_fields());
        let article: MessageUpdate = serde_json::from_value(json!({"cover": null})).unwrap();
        assert!(!article.is_empty() && article.has_only_article_fields());
        let both: MessageUpdate =
            serde_json::from_value(json!({"cover": "att_1", "tags": []})).unwrap();
        assert!(!both.is_empty() && !both.has_only_article_fields());
    }

    /// A create request has no `null` anywhere: the schema allows none, and
    /// §5.3 makes a non-string article `title` or `summary` a 400. (Only an
    /// edit gives `null` a meaning; a received `Message` stays lenient.)
    #[test]
    fn a_create_refuses_null_instead_of_reading_it_as_absent() {
        let fields = [
            "clientMessageId",
            "type",
            "attachments",
            "reference",
            "tags",
            "mentions",
            "title",
            "summary",
            "cover",
            "metadata",
        ];
        for field in fields {
            let mut body = json!({"content": {"mime": "text/plain", "text": "hi"}});
            body[field] = serde_json::Value::Null;
            assert!(
                serde_json::from_value::<MessageCreate>(body).is_err(),
                "{field}: null accepted"
            );
        }
        let dm_fields = ["to", "attachments", "mentions", "reference"];
        for field in dm_fields {
            let mut body = json!({
                "clientMessageId": "c1", "content": {"mime": "text/plain", "text": "hi"}
            });
            body[field] = serde_json::Value::Null;
            assert!(
                serde_json::from_value::<super::super::DmMessageCreate>(body).is_err(),
                "dm {field}: null accepted"
            );
        }
    }
}
