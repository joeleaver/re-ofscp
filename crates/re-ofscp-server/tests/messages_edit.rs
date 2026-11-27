//! Editing and deleting channel messages over REST (spec §7.1), and what
//! deleting their channel does to them (decision 0017).

mod common;

use axum::http::StatusCode;
use common::assert_valid;
use common::groups::{Env, Party, env_with_remotes, join, local};
use common::harness::SIGNED_AT;
use common::messages::{
    Chan, assert_problem, call, ids, message_schema, page_schema, post, public_channel, raw, text,
};
use ofscp_core::LocalId;
use ofscp_core::wire::MessageType;
use re_ofscp_server::messages::model::MessageDoc;
use re_ofscp_server::messages::store::NewMessage;
use re_ofscp_server::messages::{MEMO_EDIT_WINDOW, MESSAGE_EDIT_WINDOW, PURGE_GRACE};
use re_ofscp_server::timefmt;
use serde_json::{Value, json};

/// alice owns a public group with a public channel; bob is a member, dave
/// an admin (holding `moderate` by default), carol an outsider.
struct Cast {
    env: Env,
    chan: Chan,
    alice: Party,
    bob: Party,
    carol: Party,
    dave: Party,
}

impl Cast {
    async fn new() -> Self {
        let env = env_with_remotes(&[]).await;
        let alice = local(&env, "alice").await;
        let bob = local(&env, "bob").await;
        let carol = local(&env, "carol").await;
        let dave = local(&env, "dave").await;
        let chan = public_channel(&env, &alice).await;
        join(&env, &chan.g, &bob, "member").await;
        join(&env, &chan.g, &dave, "admin").await;
        Self {
            env,
            chan,
            alice,
            bob,
            carol,
            dave,
        }
    }
}

fn id(m: &Value) -> &str {
    m["id"].as_str().unwrap()
}

#[tokio::test]
async fn only_the_author_edits_and_an_edit_must_change_something_this_type_has() {
    let cast = Cast::new().await;
    let (env, chan) = (&cast.env, &cast.chan);
    let m = post(env, &cast.bob, chan, text("first")).await;
    let until = SIGNED_AT.unix_timestamp() + MESSAGE_EDIT_WINDOW.as_secs() as i64;
    assert_eq!(
        m["permissions"]["editUntil"],
        json!(timefmt::rfc3339(until))
    );
    let path = chan.message(id(&m));

    // Not the author, not even the owner or a moderator: 403.
    for who in [&cast.alice, &cast.dave, &cast.carol] {
        let (s, p) = call(env, Some(who), "PATCH", &path, Some(text("x"))).await;
        assert_problem(s, StatusCode::FORBIDDEN, &p);
    }
    // An empty edit, or only article fields on a message: 400.
    for body in [
        json!({}),
        json!({"title": "T"}),
        json!({"summary": "S"}),
        json!({"content": 5}),
    ] {
        let (s, p) = call(env, Some(&cast.bob), "PATCH", &path, Some(body)).await;
        assert_problem(s, StatusCode::BAD_REQUEST, &p);
    }
    let (s, p) = raw(env, Some(&cast.bob), "PATCH", &path, "[]").await;
    assert_problem(s, StatusCode::BAD_REQUEST, &p);

    env.clock.set(SIGNED_AT + time::Duration::seconds(30));
    let body = json!({"content": {"mime": "text/plain", "text": "second"}, "tags": ["t"]});
    let (s, edited) = call(env, Some(&cast.bob), "PATCH", &path, Some(body)).await;
    assert_eq!(s, StatusCode::OK, "{edited}");
    assert_valid(&message_schema(), &edited);
    assert_eq!(edited["content"]["text"], json!("second"));
    assert_eq!(edited["tags"], json!(["t"]));
    assert_eq!(edited["createdAt"], m["createdAt"]);
    assert_eq!(
        edited["editedAt"],
        json!(timefmt::rfc3339(SIGNED_AT.unix_timestamp() + 30))
    );
    let (s, got) = call(env, None, "GET", &path, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(got, edited);

    // An edit of a missing message is 404.
    let (s, p) = call(
        env,
        Some(&cast.bob),
        "PATCH",
        &chan.message("msg_nope"),
        Some(text("x")),
    )
    .await;
    assert_problem(s, StatusCode::NOT_FOUND, &p);
}

#[tokio::test]
async fn the_edit_window_closes_after_an_hour_for_messages_and_a_day_for_memos() {
    let cast = Cast::new().await;
    let (env, chan) = (&cast.env, &cast.chan);
    let m = post(env, &cast.bob, chan, text("chat")).await;
    let memo = post(
        env,
        &cast.bob,
        chan,
        json!({"type": "memo", "content": {"mime": "text/plain", "text": "memo"}}),
    )
    .await;
    let article = post(
        env,
        &cast.bob,
        chan,
        json!({"type": "article", "title": "A", "content": {"mime": "text/markdown", "text": "a"}}),
    )
    .await;
    assert!(
        article.get("permissions").is_none(),
        "articles have no window: {article}"
    );

    let hour = MESSAGE_EDIT_WINDOW.as_secs() as i64;
    env.clock.set(SIGNED_AT + time::Duration::seconds(hour - 1));
    let (s, p) = call(
        env,
        Some(&cast.bob),
        "PATCH",
        &chan.message(id(&m)),
        Some(text("in time")),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{p}");

    env.clock.set(SIGNED_AT + time::Duration::seconds(hour));
    let (s, p) = call(
        env,
        Some(&cast.bob),
        "PATCH",
        &chan.message(id(&m)),
        Some(text("late")),
    )
    .await;
    assert_problem(s, StatusCode::FORBIDDEN, &p);
    // The memo's window is longer; the article's never closes.
    let (s, p) = call(
        env,
        Some(&cast.bob),
        "PATCH",
        &chan.message(id(&memo)),
        Some(text("memo 2")),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{p}");
    let day = MEMO_EDIT_WINDOW.as_secs() as i64;
    env.clock.set(SIGNED_AT + time::Duration::seconds(day));
    let (s, p) = call(
        env,
        Some(&cast.bob),
        "PATCH",
        &chan.message(id(&memo)),
        Some(text("memo 3")),
    )
    .await;
    assert_problem(s, StatusCode::FORBIDDEN, &p);
    let (s, p) = call(
        env,
        Some(&cast.bob),
        "PATCH",
        &chan.message(id(&article)),
        Some(json!({"title": "B"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{p}");
    assert_eq!(p["title"], json!("B"));
}

#[tokio::test]
async fn the_author_or_a_moderator_deletes_leaving_a_tombstone() {
    let cast = Cast::new().await;
    let (env, chan) = (&cast.env, &cast.chan);
    let by_bob = post(env, &cast.bob, chan, text("bob's")).await;
    let by_alice = post(env, &cast.alice, chan, text("alice's")).await;
    let other = post(env, &cast.alice, chan, text("kept")).await;

    // Neither another member nor an outsider may delete.
    for who in [&cast.bob, &cast.carol] {
        let (s, p) = call(env, Some(who), "DELETE", &chan.message(id(&by_alice)), None).await;
        assert_problem(s, StatusCode::FORBIDDEN, &p);
    }
    // The author may; so may a moderator; again is 204 too.
    let (s, _) = call(
        env,
        Some(&cast.bob),
        "DELETE",
        &chan.message(id(&by_bob)),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = call(
        env,
        Some(&cast.dave),
        "DELETE",
        &chan.message(id(&by_alice)),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = call(
        env,
        Some(&cast.alice),
        "DELETE",
        &chan.message(id(&by_alice)),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = call(
        env,
        Some(&cast.bob),
        "DELETE",
        &chan.message(id(&by_bob)),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, p) = call(
        env,
        Some(&cast.bob),
        "DELETE",
        &chan.message("msg_nope"),
        None,
    )
    .await;
    assert_problem(s, StatusCode::NOT_FOUND, &p);

    // GET still returns the tombstone: deletedAt, its body cleared.
    let (s, gone) = call(env, None, "GET", &chan.message(id(&by_bob)), None).await;
    assert_eq!(s, StatusCode::OK, "{gone}");
    assert_valid(&message_schema(), &gone);
    assert_eq!(gone["id"], by_bob["id"]);
    assert_eq!(gone["author"], by_bob["author"]);
    assert!(gone["deletedAt"].is_string(), "{gone}");
    // `content` is cleared (§7.1), but present: `BaseMessage` requires it.
    assert_eq!(gone["content"], json!({"mime": "text/plain", "text": ""}));
    assert_eq!(gone["attachments"], json!([]), "{gone}");
    assert!(gone.get("permissions").is_none(), "{gone}");

    // History keeps tombstones in place.
    let (s, page) = call(env, None, "GET", &chan.messages(), None).await;
    assert_eq!(s, StatusCode::OK, "{page}");
    assert_valid(&page_schema(), &page);
    assert_eq!(ids(&page), [id(&other), id(&by_alice), id(&by_bob)]);
    assert!(page["items"][1]["deletedAt"].is_string(), "{page}");
    assert!(page["items"][0].get("deletedAt").is_none(), "{page}");

    // A tombstone takes neither edits nor reactions: 404.
    let (s, p) = call(
        env,
        Some(&cast.bob),
        "PATCH",
        &chan.message(id(&by_bob)),
        Some(text("back")),
    )
    .await;
    assert_problem(s, StatusCode::NOT_FOUND, &p);
    let (s, p) = raw(
        env,
        Some(&cast.bob),
        "PUT",
        &chan.reaction(id(&by_bob), "up"),
        "",
    )
    .await;
    assert_problem(s, StatusCode::NOT_FOUND, &p);
}

#[tokio::test]
async fn a_deleted_channels_messages_404_at_once_and_the_sweeper_purges_them_twice() {
    let cast = Cast::new().await;
    let (env, chan) = (&cast.env, &cast.chan);
    let parent = post(env, &cast.bob, chan, text("parent")).await;
    let child = post(
        env,
        &cast.alice,
        chan,
        common::messages::reply("child", id(&parent)),
    )
    .await;
    let (s, _) = raw(
        env,
        Some(&cast.alice),
        "PUT",
        &chan.reaction(id(&parent), "up"),
        "",
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);

    let (s, _) = call(env, Some(&cast.alice), "DELETE", &chan.channel(), None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, want) = call(env, None, "GET", &chan.messages(), None).await;
    assert_problem(s, StatusCode::NOT_FOUND, &want);
    for (method, path, body) in [
        ("GET", chan.message(id(&parent)), None),
        ("GET", chan.replies(id(&parent)), None),
        ("GET", chan.reactions(id(&parent)), None),
        ("POST", chan.messages(), Some(text("late"))),
        ("PATCH", chan.message(id(&parent)), Some(text("late"))),
        ("DELETE", chan.message(id(&parent)), None),
        ("PUT", chan.reaction(id(&parent), "late"), None),
        ("DELETE", chan.reaction(id(&parent), "up"), None),
    ] {
        let (s, p) = call(env, Some(&cast.bob), method, &path, body).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{method} {path}: {p}");
        assert_eq!(p, want, "{method} {path}");
    }

    // The rows outlive the request until the sweeper runs.
    let store = env.state.messages.store();
    let pid = LocalId::new(id(&parent)).unwrap();
    let alice = cast.alice.id();
    assert!(store.message(&chan.c, id(&parent)).await.unwrap().is_some());

    let now = SIGNED_AT.unix_timestamp();
    assert_eq!(env.state.messages.sweep(now).await.unwrap(), 1);
    for m in [&parent, &child] {
        assert!(
            store.message(&chan.c, id(m)).await.unwrap().is_none(),
            "{m}"
        );
    }
    assert!(store.reaction(&pid, &alice, "up").await.unwrap().is_none());
    // A write that took its position before the close and landed after
    // the first purge (its writer's own take-back failed, say) is caught
    // by the second.
    let late = store
        .insert(&NewMessage {
            channel_id: &chan.c,
            group_id: &chan.g,
            seq: 99,
            client_message_id: None,
            author: &alice,
            kind: &MessageType::Message,
            reply: None,
            doc: &MessageDoc::default(),
            now,
            edit_until: None,
        })
        .await
        .unwrap();
    // Within the grace period there is nothing more to do; after it, the
    // second purge drops the log, and then nothing is left.
    let grace = PURGE_GRACE.as_secs() as i64;
    assert_eq!(env.state.messages.sweep(now + grace - 1).await.unwrap(), 0);
    assert_eq!(env.state.messages.sweep(now + grace + 1).await.unwrap(), 1);
    assert!(
        store
            .message(&chan.c, late.id.as_str())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        env.state.messages.sweep(now + 2 * grace + 2).await.unwrap(),
        0
    );
}

#[tokio::test]
async fn concurrent_edits_keep_each_others_fields_and_a_stale_edit_writes_nothing() {
    let cast = Cast::new().await;
    let (env, chan) = (&cast.env, &cast.chan);
    let article = json!({"type": "article", "title": "T", "content": {"mime": "text/markdown", "text": "# a"}});
    let a = post(env, &cast.alice, chan, article).await;
    let path = chan.message(id(&a));
    let alice = Some(&cast.alice);
    let (title, tags) = tokio::join!(
        call(env, alice, "PATCH", &path, Some(json!({"title": "New"}))),
        call(env, alice, "PATCH", &path, Some(json!({"tags": ["x"]}))),
    );
    assert_eq!(title.0, StatusCode::OK, "{}", title.1);
    assert_eq!(tags.0, StatusCode::OK, "{}", tags.1);
    let (_, now) = call(env, None, "GET", &path, None).await;
    assert_eq!(
        (&now["title"], &now["tags"]),
        (&json!("New"), &json!(["x"]))
    );

    // An edit built from an older body, as one from another process
    // racing this one would be, is refused by the revision check.
    let store = env.state.messages.store();
    let stored = store.message(&chan.c, id(&a)).await.unwrap().unwrap();
    assert_eq!(stored.revision, 2);
    let stale = store
        .update_doc(&stored.id, 1, &MessageDoc::default(), 1)
        .await
        .unwrap();
    assert!(stale.is_none());
    let (_, after) = call(env, None, "GET", &path, None).await;
    assert_eq!(after, now);
}

#[tokio::test]
async fn deleting_a_group_closes_its_channels_messages_too() {
    let cast = Cast::new().await;
    let (env, chan) = (&cast.env, &cast.chan);
    let m = post(env, &cast.bob, chan, text("in a doomed group")).await;
    let (s, _) = call(
        env,
        Some(&cast.alice),
        "DELETE",
        &format!("/api/groups/{}", chan.g),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, p) = call(env, Some(&cast.bob), "GET", &chan.message(id(&m)), None).await;
    assert_problem(s, StatusCode::NOT_FOUND, &p);
    let (s, p) = call(
        env,
        Some(&cast.bob),
        "POST",
        &chan.messages(),
        Some(text("x")),
    )
    .await;
    assert_problem(s, StatusCode::NOT_FOUND, &p);
    assert_eq!(
        env.state
            .messages
            .sweep(SIGNED_AT.unix_timestamp())
            .await
            .unwrap(),
        1
    );
    let store = env.state.messages.store();
    assert!(store.message(&chan.c, id(&m)).await.unwrap().is_none());
}
