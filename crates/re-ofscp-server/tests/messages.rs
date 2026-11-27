//! Creating channel messages over REST (spec §7.1): idempotency, the
//! order of checks, attachments, HTML sanitizing, who may read (§11.3),
//! and remote authors (§8.2). Editing and deleting are in
//! messages_edit.rs; history, replies and reactions in messages_read.rs.

mod common;

use axum::http::StatusCode;
use common::assert_valid;
use common::groups::{Env, Party, env_with_remotes, join, local, remote};
use common::messages::{
    Chan, assert_problem, call, group_and_channel, message_schema, post, public_channel, raw,
    reply, text, text_with_id,
};
use serde_json::{Value, json};

/// A provider with `alice` (owner of a public group), `bob` (member),
/// `carol` (a local outsider) and the remote `mia@providerb.com` (member).
struct Cast {
    env: Env,
    alice: Party,
    bob: Party,
    carol: Party,
    mia: Party,
}

impl Cast {
    async fn new() -> Self {
        let mia = remote("mia", "providerb.com");
        let env = env_with_remotes(&[&mia]).await;
        let alice = local(&env, "alice").await;
        let bob = local(&env, "bob").await;
        let carol = local(&env, "carol").await;
        Self {
            env,
            alice,
            bob,
            carol,
            mia,
        }
    }

    /// A channel in a new `tier` group owned by alice, bob and mia members.
    /// The channel is `public` unless `channel` names a tier (the provider
    /// defaults to `private`, §5.5), so the group's tier decides.
    async fn channel(&self, tier: &str, mut channel: Value) -> Chan {
        if channel.get("tier").is_none() {
            channel["tier"] = json!("public");
        }
        let chan = group_and_channel(&self.env, &self.alice, tier, json!({}), channel).await;
        join(&self.env, &chan.g, &self.bob, "member").await;
        join(&self.env, &chan.g, &self.mia, "member").await;
        chan
    }
}

#[tokio::test]
async fn a_create_is_201_and_a_retry_with_its_client_message_id_is_200_with_the_same_message() {
    let cast = Cast::new().await;
    let env = &cast.env;
    let chan = cast.channel("public", json!({"type": "text"})).await;

    let first = post(env, &cast.alice, &chan, text_with_id("hello", "cm-1")).await;
    assert_eq!(first["author"], json!("alice@providera.com"));
    assert_eq!(first["type"], json!("message"));
    assert_eq!(first["clientMessageId"], json!("cm-1"));
    assert_eq!(
        first["content"],
        json!({"mime": "text/plain", "text": "hello"})
    );
    assert!(first["createdAt"].is_string(), "{first}");
    assert!(first.get("editedAt").is_none(), "{first}");

    let path = chan.messages();
    let (s, again) = call(
        env,
        Some(&cast.alice),
        "POST",
        &path,
        Some(text_with_id("hello", "cm-1")),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{again}");
    assert_eq!(again, first);

    // The duplicate lookup comes before the rest of the body is checked
    // (§7.1 Order of checks, step 4): a retry whose content is invalid
    // still gets the existing message, unchanged.
    let invalid_rest = json!({"clientMessageId": "cm-1", "content": 5, "reference": {"type": "x"}});
    let (s, again) = call(env, Some(&cast.alice), "POST", &path, Some(invalid_rest)).await;
    assert_eq!(s, StatusCode::OK, "{again}");
    assert_eq!(again, first);

    // The key is per author: bob's create with the same key is new.
    let bobs = post(env, &cast.bob, &chan, text_with_id("hi", "cm-1")).await;
    assert_ne!(bobs["id"], first["id"]);

    // Without a key every create is new.
    let a = post(env, &cast.alice, &chan, text("same")).await;
    let b = post(env, &cast.alice, &chan, text("same")).await;
    assert_ne!(a["id"], b["id"]);
}

#[tokio::test]
async fn step_one_rejects_a_bad_body_head_before_visibility_is_looked_at() {
    let cast = Cast::new().await;
    let env = &cast.env;
    let chan = cast.channel("public", json!({"type": "text"})).await;
    let missing = Chan {
        g: chan.g.clone(),
        c: "no-such-channel".into(),
    };
    for target in [&chan, &missing] {
        for body in [
            "[]",
            "\"text\"",
            "null",
            r#"{"clientMessageId": 5, "content": {"mime": "text/plain", "text": "x"}}"#,
            r#"{"clientMessageId": "", "content": {"mime": "text/plain", "text": "x"}}"#,
            r#"{"type": "bogus", "content": {"mime": "text/plain", "text": "x"}}"#,
            r#"{"type": 7, "content": {"mime": "text/plain", "text": "x"}}"#,
        ] {
            let (s, p) = raw(env, Some(&cast.bob), "POST", &target.messages(), body).await;
            assert_problem(s, StatusCode::BAD_REQUEST, &p);
        }
    }
    // Unsigned: 401 before anything else.
    let (s, p) = call(env, None, "POST", &chan.messages(), Some(text("x"))).await;
    assert_problem(s, StatusCode::UNAUTHORIZED, &p);
}

#[tokio::test]
async fn an_unreadable_channel_is_404_with_the_body_of_a_missing_one() {
    let cast = Cast::new().await;
    let env = &cast.env;
    let admins = cast
        .channel(
            "public",
            json!({"type": "text", "permissions": {"view": ["admin"]}}),
        )
        .await;
    let private = cast.channel("private", json!({"type": "text"})).await;
    let missing = Chan {
        g: admins.g.clone(),
        c: "nope".into(),
    };

    let (s, want) = call(
        env,
        Some(&cast.bob),
        "POST",
        &missing.messages(),
        Some(text("x")),
    )
    .await;
    assert_problem(s, StatusCode::NOT_FOUND, &want);
    // bob cannot see the admins' channel; carol, an outsider, cannot see
    // anything in the private group.
    for (who, chan) in [
        (&cast.bob, &admins),
        (&cast.carol, &private),
        (&cast.mia, &admins),
    ] {
        let (s, p) = call(env, Some(who), "POST", &chan.messages(), Some(text("x"))).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{p}");
        assert_eq!(p, want);
        let (s, p) = call(env, Some(who), "GET", &chan.messages(), None).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{p}");
        assert_eq!(p, want);
    }
    // A message id under an unreadable channel is the same 404 too.
    let m = post(env, &cast.alice, &admins, text("secret")).await;
    let id = m["id"].as_str().unwrap();
    for path in [admins.message(id), admins.replies(id), admins.reactions(id)] {
        let (s, p) = call(env, Some(&cast.bob), "GET", &path, None).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{path}: {p}");
        assert_eq!(p, want, "{path}");
    }
}

#[tokio::test]
async fn permissions_are_checked_after_visibility_and_before_the_rest_of_the_body() {
    let cast = Cast::new().await;
    let env = &cast.env;
    let open = cast.channel("public", json!({"type": "text"})).await;
    let memos = cast
        .channel(
            "public",
            json!({"type": "text", "permissions": {"post:memo": ["admin"]}}),
        )
        .await;

    // carol can read the public channel but holds no `post`.
    let (s, p) = call(
        env,
        Some(&cast.carol),
        "POST",
        &open.messages(),
        Some(text("x")),
    )
    .await;
    assert_problem(s, StatusCode::FORBIDDEN, &p);

    // `post:memo` lists only admins: bob may post messages, not memos,
    // and is refused a memo even when the rest of its body is invalid.
    post(env, &cast.bob, &memos, text("a message")).await;
    let memo = json!({"type": "memo", "content": {"mime": "text/plain", "text": "m"}});
    let (s, p) = call(
        env,
        Some(&cast.bob),
        "POST",
        &memos.messages(),
        Some(memo.clone()),
    )
    .await;
    assert_problem(s, StatusCode::FORBIDDEN, &p);
    let bad_memo = json!({"type": "memo", "content": 5});
    let (s, p) = call(
        env,
        Some(&cast.bob),
        "POST",
        &memos.messages(),
        Some(bad_memo),
    )
    .await;
    assert_problem(s, StatusCode::FORBIDDEN, &p);
    // The owner holds every grant.
    let m = post(env, &cast.alice, &memos, memo).await;
    assert_eq!(m["type"], json!("memo"));

    // After the permission checks, the rest of the body: 400.
    for body in [
        json!({"content": 5}),
        json!({}),
        json!({"content": {"mime": "application/pdf", "text": "x"}}),
        json!({"content": {"mime": "text/plain", "text": "x"}, "tags": "t"}),
    ] {
        let (s, p) = call(
            env,
            Some(&cast.bob),
            "POST",
            &open.messages(),
            Some(body.clone()),
        )
        .await;
        assert_problem(s, StatusCode::BAD_REQUEST, &p);
    }
}

#[tokio::test]
async fn reply_restricted_members_must_reply_and_references_must_name_a_message_here() {
    let cast = Cast::new().await;
    let env = &cast.env;
    let perms = json!({"replyOnly": ["member"], "replyOnlyTo": ["article"]});
    let chan = cast
        .channel("public", json!({"type": "text", "permissions": perms}))
        .await;
    let other = cast.channel("public", json!({"type": "text"})).await;
    let note = post(env, &cast.alice, &chan, text("note")).await;
    let article = post(
        env,
        &cast.alice,
        &chan,
        json!({"type": "article", "title": "T", "content": {"mime": "text/markdown", "text": "# a"}}),
    )
    .await;
    let elsewhere = post(env, &cast.alice, &other, text("elsewhere")).await;
    let path = chan.messages();

    // Without a reference: 403, even with an invalid rest of the body.
    let (s, p) = call(env, Some(&cast.bob), "POST", &path, Some(text("top"))).await;
    assert_problem(s, StatusCode::FORBIDDEN, &p);
    let (s, p) = call(
        env,
        Some(&cast.bob),
        "POST",
        &path,
        Some(json!({"content": 5})),
    )
    .await;
    assert_problem(s, StatusCode::FORBIDDEN, &p);

    // A reference that names nothing here, or is not a reply: 400.
    for parent in ["msg_nope", elsewhere["id"].as_str().unwrap()] {
        let (s, p) = call(
            env,
            Some(&cast.bob),
            "POST",
            &path,
            Some(reply("r", parent)),
        )
        .await;
        assert_problem(s, StatusCode::BAD_REQUEST, &p);
    }
    let mut not_reply = reply("r", article["id"].as_str().unwrap());
    not_reply["reference"]["type"] = json!("message");
    let (s, p) = call(env, Some(&cast.bob), "POST", &path, Some(not_reply)).await;
    assert_problem(s, StatusCode::BAD_REQUEST, &p);

    // A channel reply's `reference.provider` must be the channel's own
    // provider; another one, a non-canonical spelling or `null` is 400
    // (§7.2; lost-conn/ofscp#34).
    for provider in [json!("providerb.com"), json!("ProviderA.com"), json!(null)] {
        let mut foreign = reply("r", article["id"].as_str().unwrap());
        foreign["reference"]["provider"] = provider;
        let (s, p) = call(env, Some(&cast.bob), "POST", &path, Some(foreign)).await;
        assert_problem(s, StatusCode::BAD_REQUEST, &p);
    }
    let mut here = reply("r-here", article["id"].as_str().unwrap());
    here["reference"]["provider"] = json!("providera.com");
    let r = post(env, &cast.bob, &chan, here).await;
    assert_eq!(
        r["reference"],
        json!({"type": "reply", "id": article["id"]}),
        "a provider naming this one is the same as none"
    );

    // `replyOnlyTo` lists articles: a reply to a message is 403.
    let (s, p) = call(
        env,
        Some(&cast.bob),
        "POST",
        &path,
        Some(reply("r", note["id"].as_str().unwrap())),
    )
    .await;
    assert_problem(s, StatusCode::FORBIDDEN, &p);
    let mut ok = reply("r", article["id"].as_str().unwrap());
    ok["clientMessageId"] = json!("cm-r");
    let r = post(env, &cast.bob, &chan, ok.clone()).await;
    assert_eq!(
        r["reference"],
        json!({"type": "reply", "id": article["id"]})
    );

    // Step 3 still judges a retry as sent: without the reference it is 403
    // although the key matches; with it, the existing reply (200).
    let (s, p) = call(
        env,
        Some(&cast.bob),
        "POST",
        &path,
        Some(text_with_id("r", "cm-r")),
    )
    .await;
    assert_problem(s, StatusCode::FORBIDDEN, &p);
    let (s, again) = call(env, Some(&cast.bob), "POST", &path, Some(ok)).await;
    assert_eq!(s, StatusCode::OK, "{again}");
    assert_eq!(again, r);

    // The owner is never reply-restricted.
    post(env, &cast.alice, &chan, text("top level")).await;
}

fn with_attachment(url: &str) -> Value {
    json!({
        "content": {"mime": "text/plain", "text": "see attached"},
        "attachments": [{
            "id": "att_1",
            "mime": "image/png",
            "url": url,
            "size": 10,
            "expiresAt": "2026-02-01T00:00:00Z",
            "thumbnail": {"id": "att_1t", "mime": "image/png", "url": url, "size": 1},
        }],
    })
}

#[tokio::test]
async fn local_attachments_must_be_uploads_here_and_remote_ones_must_be_https() {
    let cast = Cast::new().await;
    let env = &cast.env;
    let chan = cast.channel("public", json!({"type": "text"})).await;
    let path = chan.messages();

    // No uploads exist on this provider, so a local author's attachment
    // names none of them (§5.8).
    let body = with_attachment("https://cdn.example/a.png");
    let (s, p) = call(env, Some(&cast.bob), "POST", &path, Some(body.clone())).await;
    assert_problem(s, StatusCode::BAD_REQUEST, &p);

    let (s, p) = call(
        env,
        Some(&cast.mia),
        "POST",
        &path,
        Some(with_attachment("http://cdn.example/a.png")),
    )
    .await;
    assert_problem(s, StatusCode::BAD_REQUEST, &p);

    // A remote author's https attachment is stored without its expiry.
    let m = post(env, &cast.mia, &chan, body).await;
    let a = &m["attachments"][0];
    assert_eq!(a["id"], json!("att_1"));
    assert_eq!(a["url"], json!("https://cdn.example/a.png"));
    assert!(a.get("expiresAt").is_none(), "{m}");
    assert_eq!(a["thumbnail"]["id"], json!("att_1t"));
}

#[tokio::test]
async fn html_bodies_are_sanitized_and_mime_parameters_dropped() {
    let cast = Cast::new().await;
    let env = &cast.env;
    let chan = cast.channel("public", json!({"type": "text"})).await;
    let body = json!({"content": {
        "mime": "Text/HTML; charset=utf-8",
        "text": "<p onclick=\"x()\">hi <b>there</b></p><script>alert(1)</script>",
    }});
    let m = post(env, &cast.bob, &chan, body).await;
    assert_eq!(m["content"]["mime"], json!("text/html"));
    let stored = m["content"]["text"].as_str().unwrap();
    assert!(!stored.contains("<script"), "{stored}");
    assert!(!stored.contains("onclick"), "{stored}");
    assert!(stored.contains("<b>there</b>"), "{stored}");

    // What GET returns is what was stored.
    let (s, got) = call(
        env,
        None,
        "GET",
        &chan.message(m["id"].as_str().unwrap()),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{got}");
    assert_eq!(got, m);
}

#[tokio::test]
async fn anonymous_readers_see_public_channels_and_nothing_else() {
    let cast = Cast::new().await;
    let env = &cast.env;
    let public = cast.channel("public", json!({"type": "text"})).await;
    let members = cast
        .channel("public", json!({"type": "text", "tier": "group"}))
        .await;
    let private = cast.channel("private", json!({"type": "text"})).await;
    let viewed = cast
        .channel(
            "public",
            json!({"type": "text", "permissions": {"view": ["member"]}}),
        )
        .await;
    let m = post(env, &cast.alice, &public, text("for all")).await;
    let id = m["id"].as_str().unwrap();

    let (s, page) = call(env, None, "GET", &public.messages(), None).await;
    assert_eq!(s, StatusCode::OK, "{page}");
    assert_eq!(page["items"], json!([m]));
    let (s, got) = call(env, None, "GET", &public.message(id), None).await;
    assert_eq!(s, StatusCode::OK, "{got}");
    assert_valid(&message_schema(), &got);
    // A signed outsider reads it as well.
    let (s, _) = call(env, Some(&cast.carol), "GET", &public.message(id), None).await;
    assert_eq!(s, StatusCode::OK);

    let missing = Chan {
        g: public.g.clone(),
        c: "absent".into(),
    };
    let (s, want) = call(env, None, "GET", &missing.messages(), None).await;
    assert_problem(s, StatusCode::NOT_FOUND, &want);
    for chan in [&members, &private, &viewed] {
        post(env, &cast.alice, chan, text("members only")).await;
        let (s, p) = call(env, None, "GET", &chan.messages(), None).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{p}");
        assert_eq!(p, want);
        // Members do read it.
        let (s, page) = call(env, Some(&cast.bob), "GET", &chan.messages(), None).await;
        assert_eq!(s, StatusCode::OK, "{page}");
        assert_eq!(page["items"].as_array().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn remote_actors_post_by_their_full_handle_and_are_never_their_local_namesake() {
    let alice_b = remote("alice", "providerb.com");
    let mia = remote("mia", "providerb.com");
    let env = env_with_remotes(&[&alice_b, &mia]).await;
    let alice = local(&env, "alice").await;
    let chan = public_channel(&env, &alice).await;
    join(&env, &chan.g, &mia, "member").await;

    let m = post(&env, &mia, &chan, text_with_id("from b", "cm-b")).await;
    assert_eq!(m["author"], json!("mia@providerb.com"));
    let (s, again) = call(
        &env,
        Some(&mia),
        "POST",
        &chan.messages(),
        Some(text_with_id("from b", "cm-b")),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{again}");
    assert_eq!(again, m);

    // alice@providerb.com is not a member: she reads the public channel
    // but may not post, nor edit or delete local alice's message.
    let (s, p) = call(
        &env,
        Some(&alice_b),
        "POST",
        &chan.messages(),
        Some(text("x")),
    )
    .await;
    assert_problem(s, StatusCode::FORBIDDEN, &p);
    let mine = post(&env, &alice, &chan, text_with_id("local", "cm-b")).await;
    assert_ne!(mine["id"], m["id"], "the key is per (handle, domain)");
    let path = chan.message(mine["id"].as_str().unwrap());
    let (s, p) = call(&env, Some(&alice_b), "PATCH", &path, Some(text("hijack"))).await;
    assert_problem(s, StatusCode::FORBIDDEN, &p);
    let (s, p) = call(&env, Some(&alice_b), "DELETE", &path, None).await;
    assert_problem(s, StatusCode::FORBIDDEN, &p);

    // mia edits her own message.
    let mpath = chan.message(m["id"].as_str().unwrap());
    let (s, edited) = call(&env, Some(&mia), "PATCH", &mpath, Some(text("edited"))).await;
    assert_eq!(s, StatusCode::OK, "{edited}");
    assert_eq!(edited["content"]["text"], json!("edited"));
}
