//! Unit tests of `validate.rs`.

use std::collections::HashMap;
use std::sync::Mutex;

use ofscp_core::Actor;
use ofscp_core::wire::{Attachment, Content, MessageCreate, MessageType, MessageUpdate};
use serde_json::{Value, json};

use super::*;
use crate::messages::uploads::{HostedFuture, HostedUpload, NoUploads, Uploads};

fn alice() -> Actor {
    Actor::parse_canonical("alice@a.example").unwrap()
}

fn text(mime: &str, text: &str) -> Content {
    Content {
        text: text.to_owned(),
        mime: mime.to_owned(),
    }
}

fn create(v: Value) -> MessageCreate {
    serde_json::from_value(v).unwrap()
}

fn update(v: Value) -> MessageUpdate {
    serde_json::from_value(v).unwrap()
}

fn attachment(id: &str, url: &str) -> Attachment {
    serde_json::from_value(json!({
        "id": id, "mime": "image/png", "url": url, "size": 10,
        "expiresAt": "2030-01-01T00:00:00Z",
        "thumbnail": { "id": format!("{id}_t"), "mime": "image/png",
                       "url": url, "size": 1, "expiresAt": "2030-01-01T00:00:00Z" }
    }))
    .unwrap()
}

#[test]
fn the_head_reads_type_and_client_message_id_first() {
    let h = head(&json!({ "clientMessageId": "c1", "reference": {} })).unwrap();
    assert_eq!(h.client_message_id.as_deref(), Some("c1"));
    assert_eq!(h.kind, MessageType::Message);
    assert!(h.has_reference);
    assert_eq!(
        head(&json!({ "type": "memo" })).unwrap().kind,
        MessageType::Memo
    );
    for bad in [
        json!([]),
        json!("x"),
        json!({ "clientMessageId": "" }),
        json!({ "clientMessageId": 7 }),
        json!({ "clientMessageId": "c".repeat(MAX_CLIENT_MESSAGE_ID_BYTES + 1) }),
        json!({ "type": "system" }),
        json!({ "type": 1 }),
    ] {
        assert!(head(&bad).is_err(), "{bad}");
    }
}

#[test]
fn content_is_normalized_sanitized_and_bounded() {
    let c = content(
        &MessageType::Message,
        &text("Text/Plain; charset=utf-8", "hi"),
    )
    .unwrap();
    assert_eq!(c.mime, "text/plain");
    let h = content(
        &MessageType::Message,
        &text("text/html", "<b>x</b><script>y</script>"),
    )
    .unwrap();
    assert!(!h.text.contains("script"), "{}", h.text);
    assert!(h.text.contains("<b>x</b>"));
    assert!(content(&MessageType::Message, &text("image/png", "x")).is_err());
    let long = "a".repeat(MAX_TEXT_BYTES + 1);
    assert!(content(&MessageType::Message, &text("text/plain", &long)).is_err());
    assert!(content(&MessageType::Article, &text("text/plain", &long)).is_ok());
    // Escaping can push a body that fit past the limit.
    let escapes = "<".repeat(MAX_TEXT_BYTES);
    assert!(content(&MessageType::Message, &text("text/html", &escapes)).is_err());
}

#[test]
fn a_new_doc_keeps_article_fields_on_articles_only() {
    let body = json!({
        "content": { "mime": "text/plain", "text": "body" },
        "title": "T", "summary": "S", "tags": ["#a"]
    });
    let doc = new_doc(&MessageType::Article, &create(body.clone()), vec![]).unwrap();
    assert_eq!(doc.title.as_deref(), Some("T"));
    assert_eq!(doc.tags.as_deref(), Some(&["#a".to_owned()][..]));
    let doc = new_doc(&MessageType::Message, &create(body), vec![]).unwrap();
    assert_eq!(doc.title, None);
    assert_eq!(doc.summary, None);
}

#[test]
fn a_cover_must_name_an_attachment() {
    let body = json!({ "content": { "mime": "text/plain", "text": "b" }, "cover": "att_1" });
    assert!(new_doc(&MessageType::Article, &create(body.clone()), vec![]).is_err());
    let a = attachment("att_1", "https://cdn.example/a.png");
    assert!(new_doc(&MessageType::Article, &create(body), vec![a]).is_ok());
}

#[test]
fn tags_mentions_and_titles_are_bounded() {
    let base = |extra: Value| {
        let mut v = json!({ "content": { "mime": "text/plain", "text": "b" } });
        for (k, x) in extra.as_object().unwrap() {
            v[k] = x.clone();
        }
        create(v)
    };
    let many: Vec<String> = (0..=MAX_TAGS).map(|i| format!("#{i}")).collect();
    assert!(
        new_doc(
            &MessageType::Message,
            &base(json!({ "tags": many })),
            vec![]
        )
        .is_err()
    );
    let long = "t".repeat(MAX_TAG_BYTES + 1);
    assert!(
        new_doc(
            &MessageType::Message,
            &base(json!({ "tags": [long] })),
            vec![]
        )
        .is_err()
    );
    let mentions: Vec<String> = (0..=MAX_MENTIONS)
        .map(|i| format!("user{i}@a.example"))
        .collect();
    let req = base(json!({ "mentions": mentions }));
    assert!(new_doc(&MessageType::Message, &req, vec![]).is_err());
    let title = "x".repeat(MAX_TITLE_CHARS + 1);
    assert!(
        new_doc(
            &MessageType::Article,
            &base(json!({ "title": title })),
            vec![]
        )
        .is_err()
    );
    let req = base(json!({ "title": "a\u{7}b" }));
    assert!(new_doc(&MessageType::Article, &req, vec![]).is_err());
}

#[test]
fn an_edit_needs_a_field_that_applies() {
    assert!(edit_shape(&MessageType::Message, &update(json!({}))).is_err());
    let only_article = update(json!({ "title": "x" }));
    assert!(edit_shape(&MessageType::Message, &only_article).is_err());
    assert!(edit_shape(&MessageType::Article, &only_article).is_ok());
    assert!(edit_shape(&MessageType::Message, &update(json!({ "tags": [] }))).is_ok());
}

#[test]
fn an_edit_replaces_present_fields_and_clears_nulls() {
    let req = create(json!({
        "content": { "mime": "text/plain", "text": "old" },
        "title": "T", "summary": "S", "tags": ["#a"]
    }));
    let doc = new_doc(&MessageType::Article, &req, vec![]).unwrap();
    let edit = update(json!({
        "content": { "mime": "text/markdown", "text": "new" }, "summary": null
    }));
    let out = edited_doc(&MessageType::Article, &doc, &edit, None).unwrap();
    assert_eq!(out.content.unwrap().text, "new");
    assert_eq!(out.title.as_deref(), Some("T"));
    assert_eq!(out.summary, None);
    assert_eq!(out.tags, doc.tags);
    // Article fields of an edit are ignored on other types.
    let plain = new_doc(&MessageType::Message, &req, vec![]).unwrap();
    let edit = update(json!({ "tags": [], "title": "ignored" }));
    let out = edited_doc(&MessageType::Message, &plain, &edit, None).unwrap();
    assert_eq!(out.title, None);
    assert_eq!(out.tags, Some(vec![]));
}

/// Uploads with fixed records.
#[derive(Default)]
struct Fixed(Mutex<HashMap<String, HostedUpload>>);

impl Uploads for Fixed {
    fn hosted<'a>(&'a self, id: &'a str) -> HostedFuture<'a> {
        let found = self.0.lock().unwrap().get(id).cloned();
        Box::pin(async move { Ok(found) })
    }
}

#[tokio::test]
async fn local_authors_must_attach_their_own_completed_uploads() {
    let a = attachment("att_1", "https://a.example/m/1.png");
    // Nothing hosted: a local author's attachment is refused.
    assert!(
        attachments(&NoUploads, &alice(), true, std::slice::from_ref(&a))
            .await
            .is_err()
    );
    let mut record = a.clone();
    record.url = "https://a.example/media/att_1".to_owned();
    let hosted = |uploader: Actor, complete: bool| HostedUpload {
        uploader,
        local_target: true,
        complete,
        attachment: record.clone(),
    };
    let uploads = Fixed::default();
    uploads
        .0
        .lock()
        .unwrap()
        .insert("att_1".into(), hosted(alice(), true));
    let stored = attachments(&uploads, &alice(), true, std::slice::from_ref(&a))
        .await
        .unwrap();
    assert_eq!(
        stored,
        vec![record.clone()],
        "the provider's record is stored"
    );
    let bob = Actor::parse_canonical("bob@a.example").unwrap();
    assert!(
        attachments(&uploads, &bob, true, std::slice::from_ref(&a))
            .await
            .is_err()
    );
    uploads
        .0
        .lock()
        .unwrap()
        .insert("att_1".into(), hosted(alice(), false));
    assert!(
        attachments(&uploads, &alice(), true, std::slice::from_ref(&a))
            .await
            .is_err()
    );
    let mut other_size = a.clone();
    other_size.size += 1;
    uploads
        .0
        .lock()
        .unwrap()
        .insert("att_1".into(), hosted(alice(), true));
    assert!(
        attachments(&uploads, &alice(), true, &[other_size])
            .await
            .is_err()
    );
}

#[tokio::test]
async fn remote_attachments_need_https_and_lose_their_expiry() {
    let remote = Actor::parse_canonical("carol@b.example").unwrap();
    let a = attachment("att_9", "https://b.example/m/9.png");
    let stored = attachments(&NoUploads, &remote, false, &[a]).await.unwrap();
    assert_eq!(stored[0].expires_at, None);
    assert_eq!(stored[0].thumbnail.as_ref().unwrap().expires_at, None);
    let http = attachment("att_9", "http://b.example/m/9.png");
    assert!(
        attachments(&NoUploads, &remote, false, &[http])
            .await
            .is_err()
    );
    let dup = attachment("att_9", "https://b.example/m/9.png");
    assert!(
        attachments(&NoUploads, &remote, false, &[dup.clone(), dup])
            .await
            .is_err()
    );
    let many: Vec<Attachment> = (0..=MAX_ATTACHMENTS)
        .map(|i| attachment(&format!("att_{i}"), "https://b.example/x.png"))
        .collect();
    assert!(
        attachments(&NoUploads, &remote, false, &many)
            .await
            .is_err()
    );
}
