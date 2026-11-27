//! Checking message bodies before anything is stored (§5.3, §5.8, §7.1).
//! Every failure is a `400` with the message as detail. The limits are
//! this provider's own (docs/decisions/0017).

use std::collections::HashSet;

use ofscp_core::Actor;
use ofscp_core::wire::{
    Attachment, Content, MessageCreate, MessageType, MessageUpdate, Patch, Thumbnail,
};
use serde_json::Value;

use super::model::MessageDoc;
use super::sanitize::sanitize_html;
use super::uploads::Uploads;
use crate::db::DbError;
pub use crate::profiles::validate::Invalid;
use crate::profiles::validate::metadata;

/// Longest body of a chat message or memo, in bytes.
pub const MAX_TEXT_BYTES: usize = 16 * 1024;
/// Longest body of an article, in bytes.
pub const MAX_ARTICLE_BYTES: usize = 256 * 1024;
/// Longest article title, in characters.
pub const MAX_TITLE_CHARS: usize = 300;
/// Longest article summary, in characters.
pub const MAX_SUMMARY_CHARS: usize = 1000;
/// Most tags on a message.
pub const MAX_TAGS: usize = 32;
/// Longest tag, in bytes.
pub const MAX_TAG_BYTES: usize = 64;
/// Most mentions on a message (§5.3: providers MAY limit it).
pub const MAX_MENTIONS: usize = 100;
/// Most attachments on a message.
pub const MAX_ATTACHMENTS: usize = 32;
/// Longest `clientMessageId`, in bytes.
pub const MAX_CLIENT_MESSAGE_ID_BYTES: usize = 128;

/// The body formats this provider stores (§5.3 *Content formats*). Plain
/// text and Markdown are required; HTML is optional and is stored only
/// after [`sanitize_html`].
const PLAIN: &str = "text/plain";
const MARKDOWN: &str = "text/markdown";
const HTML: &str = "text/html";

fn invalid(msg: impl Into<String>) -> Invalid {
    Invalid(msg.into())
}

/// What step 1 of a create reads (§7.1 *Order of checks*): enough to
/// apply visibility, the permission checks and the duplicate lookup before
/// the rest of the body is looked at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    /// The idempotency key, if sent.
    pub client_message_id: Option<String>,
    /// The type (`message` when omitted).
    pub kind: MessageType,
    /// Whether the body carries a `reference` at all (a reply-restricted
    /// actor's create without one is `403` at step 3).
    pub has_reference: bool,
}

/// Step 1 of a create: the body must be a JSON object, and its
/// `clientMessageId` and `type` must match the schema.
pub fn head(body: &Value) -> Result<Head, Invalid> {
    let Some(obj) = body.as_object() else {
        return Err(invalid("the body must be a JSON object"));
    };
    let client_message_id = match obj.get("clientMessageId") {
        None => None,
        Some(Value::String(s)) if !s.is_empty() => {
            if s.len() > MAX_CLIENT_MESSAGE_ID_BYTES {
                return Err(invalid(format!(
                    "clientMessageId is limited to {MAX_CLIENT_MESSAGE_ID_BYTES} bytes"
                )));
            }
            Some(s.clone())
        }
        Some(_) => return Err(invalid("clientMessageId must be a non-empty string")),
    };
    let kind = match obj.get("type") {
        None => MessageType::Message,
        Some(Value::String(s)) => creatable_kind(s)?,
        Some(_) => return Err(invalid("type must be message, memo or article")),
    };
    Ok(Head {
        client_message_id,
        kind,
        has_reference: obj.contains_key("reference"),
    })
}

/// A type a create may name: `message`, `memo` or `article` (the
/// `MessageCreate` schema's enum).
pub fn creatable_kind(s: &str) -> Result<MessageType, Invalid> {
    match MessageType::from(s) {
        k @ (MessageType::Message | MessageType::Memo | MessageType::Article) => Ok(k),
        _ => Err(invalid("type must be message, memo or article")),
    }
}

/// A body (§5.3): a supported `mime` (its parameters dropped, lowercase),
/// within the size limit for `kind`. HTML is sanitized to the §5.3
/// allow-list.
pub fn content(kind: &MessageType, c: &Content) -> Result<Content, Invalid> {
    let base = c
        .mime
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let max = match kind {
        MessageType::Article => MAX_ARTICLE_BYTES,
        _ => MAX_TEXT_BYTES,
    };
    let too_long = || {
        invalid(format!(
            "content.text is limited to {max} bytes for this type"
        ))
    };
    // Checked before sanitizing, so an oversized body costs nothing.
    if c.text.len() > max {
        return Err(too_long());
    }
    let text = match base.as_str() {
        PLAIN | MARKDOWN => c.text.clone(),
        HTML => sanitize_html(&c.text),
        _ => {
            return Err(invalid(
                "content.mime must be text/plain, text/markdown or text/html",
            ));
        }
    };
    // Sanitizing escapes text, so the stored body can be longer.
    if text.len() > max {
        return Err(too_long());
    }
    Ok(Content { text, mime: base })
}

fn tags(list: &[String]) -> Result<(), Invalid> {
    if list.len() > MAX_TAGS {
        return Err(invalid(format!("tags is limited to {MAX_TAGS} entries")));
    }
    if list
        .iter()
        .any(|t| t.len() > MAX_TAG_BYTES || t.chars().any(char::is_control))
    {
        return Err(invalid(format!(
            "each tag is limited to {MAX_TAG_BYTES} bytes, with no control characters"
        )));
    }
    Ok(())
}

/// Mentions are canonical actors already (the wire type refuses any other
/// spelling, §2.2); only their number is limited.
fn mentions(list: &[Actor]) -> Result<(), Invalid> {
    if list.len() > MAX_MENTIONS {
        return Err(invalid(format!(
            "mentions is limited to {MAX_MENTIONS} entries"
        )));
    }
    Ok(())
}

fn plain_text(field: &str, value: &str, max: usize) -> Result<(), Invalid> {
    if value.chars().count() > max {
        return Err(invalid(format!("{field} is limited to {max} characters")));
    }
    if value
        .chars()
        .any(|c| c.is_control() && c != '\n' && c != '\t')
    {
        return Err(invalid(format!(
            "{field} must not contain control characters"
        )));
    }
    Ok(())
}

/// An article's `cover` must name one of its attachments (§5.3).
fn cover_named(doc: &MessageDoc) -> Result<(), Invalid> {
    match &doc.cover {
        Some(cover) if !doc.attachments.iter().any(|a| a.id == *cover) => Err(invalid(
            "cover must be the id of one of the message's attachments",
        )),
        _ => Ok(()),
    }
}

/// Why a message's attachments were refused.
#[derive(Debug, thiserror::Error)]
pub enum AttachmentError {
    /// `400`.
    #[error(transparent)]
    Invalid(#[from] Invalid),
    /// The upload store failed.
    #[error(transparent)]
    Db(#[from] DbError),
}

fn is_https_url(s: &str) -> bool {
    url::Url::parse(s).is_ok_and(|u| u.scheme() == "https" && u.host_str().is_some())
}

/// The attachments of a message by `author`, as the message will store
/// them (§5.8 *Checks on attachments in a message*):
///
/// * one this provider hosts must be the author's own completed local
///   upload, with `mime`, `size` and `hash` as recorded; the provider's
///   record is stored, not the client's copy;
/// * a local author's attachments must all be hosted;
/// * one it does not host (a remote author's) must have `https` URLs, and
///   loses any `expiresAt` the author supplied, on it and its thumbnail.
///
/// Ids must be distinct, so that `cover` and inline references name one
/// attachment.
pub async fn attachments(
    uploads: &dyn Uploads,
    author: &Actor,
    author_is_local: bool,
    list: &[Attachment],
) -> Result<Vec<Attachment>, AttachmentError> {
    if list.len() > MAX_ATTACHMENTS {
        return Err(invalid(format!(
            "attachments is limited to {MAX_ATTACHMENTS} entries"
        ))
        .into());
    }
    let mut seen = HashSet::new();
    let mut stored = Vec::with_capacity(list.len());
    for a in list {
        if !seen.insert(a.id.as_str()) {
            return Err(invalid("attachment ids must be distinct").into());
        }
        match uploads.hosted(a.id.as_str()).await? {
            Some(up) => {
                let rec = &up.attachment;
                let matches = up.uploader == *author
                    && up.local_target
                    && up.complete
                    && rec.mime == a.mime
                    && rec.size == a.size
                    && rec.hash == a.hash;
                if !matches {
                    return Err(invalid(format!(
                        "attachment {} does not match an upload of yours on this provider",
                        a.id
                    ))
                    .into());
                }
                stored.push(rec.clone());
            }
            None if author_is_local => {
                return Err(invalid(format!(
                    "attachment {} is not an upload on this provider",
                    a.id
                ))
                .into());
            }
            None => stored.push(foreign(a)?),
        }
    }
    Ok(stored)
}

/// A remote author's attachment that this provider does not host.
fn foreign(a: &Attachment) -> Result<Attachment, Invalid> {
    if !is_https_url(&a.url) {
        return Err(invalid(format!("attachment {} url must be https", a.id)));
    }
    let thumbnail = match &a.thumbnail {
        Some(t) if !is_https_url(&t.url) => {
            return Err(invalid(format!(
                "attachment {} thumbnail url must be https",
                a.id
            )));
        }
        Some(t) => Some(Thumbnail {
            expires_at: None,
            ..t.clone()
        }),
        None => None,
    };
    Ok(Attachment {
        expires_at: None,
        thumbnail,
        ..a.clone()
    })
}

/// The stored body of a new message of `kind` (§7.1 *Sending messages*):
/// the defaults applied, article fields kept only on an article (§5.3),
/// and `attachments` as [`attachments`] returned them.
pub fn new_doc(
    kind: &MessageType,
    req: &MessageCreate,
    attachments: Vec<Attachment>,
) -> Result<MessageDoc, Invalid> {
    let content = content(kind, &req.content)?;
    if let Some(t) = &req.tags {
        tags(t)?;
    }
    if let Some(m) = &req.mentions {
        mentions(m)?;
    }
    let meta = req.metadata.clone().unwrap_or_default();
    metadata("metadata", &meta)?;
    let mut doc = MessageDoc {
        content: Some(content),
        attachments,
        tags: req.tags.clone(),
        mentions: req.mentions.clone(),
        metadata: meta,
        ..MessageDoc::default()
    };
    if *kind == MessageType::Article {
        if let Some(t) = &req.title {
            plain_text("title", t, MAX_TITLE_CHARS)?;
        }
        if let Some(s) = &req.summary {
            plain_text("summary", s, MAX_SUMMARY_CHARS)?;
        }
        doc.title = req.title.clone();
        doc.summary = req.summary.clone();
        doc.cover = req.cover.clone();
        cover_named(&doc)?;
    }
    Ok(doc)
}

/// Whether an edit may be applied to a message of `kind` at all (§7.1): it
/// must carry a field, and on a message that is not an article, a field
/// other than the article ones (lost-conn/ofscp#31, per the oracle).
pub fn edit_shape(kind: &MessageType, edit: &MessageUpdate) -> Result<(), Invalid> {
    if edit.is_empty() {
        return Err(invalid(
            "an edit must carry content, attachments, tags, mentions or an article field",
        ));
    }
    if *kind != MessageType::Article && edit.has_only_article_fields() {
        return Err(invalid(
            "title, summary and cover apply to articles only; this edit changes nothing",
        ));
    }
    Ok(())
}

/// `doc` with `edit` applied (§7.1 *Editing*): each field present replaces
/// the stored one, and the same `400` rules as a create apply to the
/// fields and to the result. `attachments` is the edit's new list as
/// [`attachments`] returned it, when the edit carries one.
pub fn edited_doc(
    kind: &MessageType,
    doc: &MessageDoc,
    edit: &MessageUpdate,
    attachments: Option<Vec<Attachment>>,
) -> Result<MessageDoc, Invalid> {
    let mut out = doc.clone();
    if let Some(c) = &edit.content {
        out.content = Some(content(kind, c)?);
    }
    if let Some(a) = attachments {
        out.attachments = a;
    }
    if let Some(t) = &edit.tags {
        tags(t)?;
        out.tags = Some(t.clone());
    }
    if let Some(m) = &edit.mentions {
        mentions(m)?;
        out.mentions = Some(m.clone());
    }
    if *kind == MessageType::Article {
        patch(&mut out.title, &edit.title, |t| {
            plain_text("title", t, MAX_TITLE_CHARS)
        })?;
        patch(&mut out.summary, &edit.summary, |s| {
            plain_text("summary", s, MAX_SUMMARY_CHARS)
        })?;
        patch(&mut out.cover, &edit.cover, |_| Ok(()))?;
        cover_named(&out)?;
    }
    Ok(out)
}

fn patch<T: Clone>(
    field: &mut Option<T>,
    edit: &Patch<T>,
    check: impl Fn(&T) -> Result<(), Invalid>,
) -> Result<(), Invalid> {
    match edit {
        Patch::Keep => {}
        Patch::Clear => *field = None,
        Patch::Set(v) => {
            check(v)?;
            *field = Some(v.clone());
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "validate_tests.rs"]
mod tests;
