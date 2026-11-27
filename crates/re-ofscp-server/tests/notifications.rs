//! Making notification entries (spec §10.1 *Mentions*, *When entries are
//! created*; §10.2 modes; docs/decisions/0023; security requirements 1
//! and 7), on a real rhypedb-server.

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use common::groups::{Party, create_channel, id, local, remote};
use common::harness::SIGNED_AT;
use common::messages::{Chan, call, post, reply, text, text_with_id};
use common::notifications::{Cast, FEED, SETTINGS, all_entries, set};
use common::ws::{Client, serve};
use common::{assert_valid, schema};
use serde_json::{Value, json};

const QUIET: Duration = Duration::from_millis(300);

fn assert_problem(status: StatusCode, body: &Value, want: StatusCode, code: &str) {
    assert_eq!(status, want, "{body}");
    assert_eq!(body["errorCode"], code, "{body}");
}

/// What `by` would get: `(type, message id)` pairs.
fn want(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(t, m)| ((*t).to_owned(), (*m).to_owned()))
        .collect()
}

/// Post `body` in the cast's channel as `by`; its id.
async fn say(cast: &Cast, by: &Party, body: Value) -> String {
    id(&post(&cast.env, by, &cast.chan, body).await)
}

#[tokio::test]
async fn remote_and_unsigned_callers_are_refused() {
    let mia = remote("mia", "b.example");
    let cast = Cast::with_remotes(&[&mia]).await;
    let setting = json!({"scopeType": "group", "scopeId": "grp_1", "mode": "all"});
    let routes = [
        ("GET", FEED.to_owned(), None),
        ("POST", format!("{FEED}/seen"), Some(json!({}))),
        ("POST", format!("{FEED}/read"), Some(json!({}))),
        ("GET", SETTINGS.to_owned(), None),
        ("PUT", SETTINGS.to_owned(), Some(setting)),
        (
            "DELETE",
            format!("{SETTINGS}?scopeType=group&scopeId=grp_1"),
            None,
        ),
    ];
    for (method, path, body) in routes {
        let (s, b) = call(&cast.env, Some(&mia), method, &path, body.clone()).await;
        assert_problem(s, &b, StatusCode::FORBIDDEN, "forbidden");
        let (s, b) = call(&cast.env, None, method, &path, body).await;
        assert_problem(s, &b, StatusCode::UNAUTHORIZED, "unauthorized");
    }
}

#[tokio::test]
async fn mentions_follow_the_section_10_1_grammar() {
    let cast = Cast::new().await;
    let env = &cast.env;
    let bobby = local(env, "bobby").await;
    common::groups::join(env, &cast.chan.g, &bobby, "member").await;

    // An address in prose is no mention; nor is a mention of another
    // provider's bob, nor alice's mention of herself.
    say(
        &cast,
        &cast.alice,
        text("mail bob@example.com or @bob@b.example"),
    )
    .await;
    say(&cast, &cast.alice, text("note to self, @alice")).await;
    assert!(all_entries(env, &cast.bob).await.is_empty());
    assert!(all_entries(env, &cast.alice).await.is_empty());

    // Case-insensitive; the longest handle run, so `@bobby` is bobby only;
    // a qualified mention of this provider is a mention too.
    let upper = say(&cast, &cast.alice, text("hey @BoB!")).await;
    let longest = say(&cast, &cast.alice, text("thanks @bobby.")).await;
    let qualified = say(&cast, &cast.alice, text("cc @bob@providera.com")).await;
    assert_eq!(
        all_entries(env, &cast.bob).await,
        want(&[("mention", &qualified), ("mention", &upper)])
    );
    assert_eq!(
        all_entries(env, &bobby).await,
        want(&[("mention", &longest)])
    );

    // Explicit `mentions` are exactly who is mentioned: the text is unread.
    let body = json!({
        "content": {"mime": "text/plain", "text": "@bob look"},
        "mentions": ["carol@providera.com", "mia@b.example"],
    });
    let explicit = say(&cast, &cast.alice, body).await;
    assert_eq!(
        all_entries(env, &cast.carol).await,
        want(&[("mention", &explicit)])
    );
    assert_eq!(all_entries(env, &cast.bob).await.len(), 2);
}

#[tokio::test]
async fn mention_beats_reply_beats_message_one_entry_each() {
    let cast = Cast::new().await;
    let env = &cast.env;
    let parent = say(&cast, &cast.bob, text("a question")).await;

    let answer = say(&cast, &cast.alice, reply("an answer", &parent)).await;
    let both = say(&cast, &cast.alice, reply("@bob an answer", &parent)).await;
    // Bob's reply to himself notifies no one.
    say(&cast, &cast.bob, reply("me too", &parent)).await;
    assert_eq!(
        all_entries(env, &cast.bob).await,
        want(&[("mention", &both), ("reply", &answer)])
    );

    // With the channel set to `all`, every message makes an entry, still
    // at most one, of the highest type.
    set(env, &cast.bob, "channel", &cast.chan.c, "all").await;
    let plain = say(&cast, &cast.alice, text("news")).await;
    let mention = say(&cast, &cast.alice, text("@bob news")).await;
    let replied = say(&cast, &cast.alice, reply("more", &parent)).await;
    assert_eq!(
        all_entries(env, &cast.bob).await[..3],
        want(&[
            ("reply", &replied),
            ("mention", &mention),
            ("message", &plain)
        ])
    );
    // Carol kept the default (`mentions`): none of that was for her.
    assert!(all_entries(env, &cast.carol).await.is_empty());
}

#[tokio::test]
async fn the_channel_setting_wins_over_the_group_setting() {
    let cast = Cast::new().await;
    let env = &cast.env;
    // A group set to `all` makes message entries in its channels...
    set(env, &cast.bob, "group", &cast.chan.g, "all").await;
    let first = say(&cast, &cast.alice, text("one")).await;
    assert_eq!(
        all_entries(env, &cast.bob).await,
        want(&[("message", &first)])
    );
    // ...unless the channel says otherwise.
    set(env, &cast.bob, "channel", &cast.chan.c, "mentions").await;
    say(&cast, &cast.alice, text("two")).await;
    assert_eq!(all_entries(env, &cast.bob).await.len(), 1);

    // A group set to `none` with the channel at `all`: the channel wins.
    set(env, &cast.carol, "group", &cast.chan.g, "none").await;
    set(env, &cast.carol, "channel", &cast.chan.c, "all").await;
    let third = say(&cast, &cast.alice, text("three")).await;
    assert_eq!(
        all_entries(env, &cast.carol).await,
        want(&[("message", &third)])
    );
}

#[tokio::test]
async fn none_suppresses_mentions_replies_and_messages() {
    let cast = Cast::new().await;
    let env = &cast.env;
    let parent = say(&cast, &cast.bob, text("a question")).await;
    set(env, &cast.bob, "channel", &cast.chan.c, "none").await;
    say(&cast, &cast.alice, text("@bob hello")).await;
    say(&cast, &cast.alice, reply("@bob an answer", &parent)).await;
    say(&cast, &cast.alice, reply("an answer", &parent)).await;
    assert!(all_entries(env, &cast.bob).await.is_empty());

    // Set at the group, with no channel setting, it suppresses too.
    set(env, &cast.carol, "group", &cast.chan.g, "none").await;
    say(&cast, &cast.alice, text("@carol hello")).await;
    assert!(all_entries(env, &cast.carol).await.is_empty());
}

#[tokio::test]
async fn nobody_who_cannot_read_the_channel_or_has_no_active_account_is_notified() {
    let cast = Cast::new().await;
    let env = &cast.env;
    // A channel of the group only admins may view.
    let body = json!({"type": "text", "tier": "public", "permissions": {"view": ["admin"]}});
    let hidden = Chan {
        g: cast.chan.g.clone(),
        c: id(&create_channel(env, &cast.alice, &cast.chan.g, body).await),
    };
    set(env, &cast.carol, "channel", &hidden.c, "all").await;
    let m = post(env, &cast.alice, &hidden, text("@bob secret")).await;
    assert_eq!(m["content"]["text"], "@bob secret");
    assert!(all_entries(env, &cast.bob).await.is_empty());
    assert!(all_entries(env, &cast.carol).await.is_empty());

    // Someone outside the private group, mentioned or set to `all`.
    let dave = local(env, "dave").await;
    set(env, &dave, "group", &cast.chan.g, "all").await;
    say(&cast, &cast.alice, text("@dave hello")).await;
    assert!(all_entries(env, &dave).await.is_empty());

    // A disabled account, and a handle with no account at all.
    let store = &env.state.accounts.store;
    let carol = store.find_user("carol").await.unwrap().unwrap();
    env.state
        .accounts
        .disable_account(&carol, SIGNED_AT.unix_timestamp())
        .await
        .unwrap();
    say(&cast, &cast.alice, text("@carol @nobody hello")).await;
    let rows = env
        .state
        .db
        .fetch::<Value>(&re_ofscp_server::db::Ql::new("Notification.filter(.n > 0)"))
        .await
        .unwrap();
    assert!(rows.is_empty(), "{rows:?}");
}

#[tokio::test]
async fn edits_and_retried_creates_make_no_entries() {
    let cast = Cast::new().await;
    let env = &cast.env;
    let m = say(&cast, &cast.alice, text("hello")).await;
    let (s, b) = call(
        env,
        Some(&cast.alice),
        "PATCH",
        &cast.chan.message(&m),
        Some(text("hello @bob")),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert!(all_entries(env, &cast.bob).await.is_empty());

    let first = say(&cast, &cast.alice, text_with_id("@bob hi", "c1")).await;
    let (s, again) = call(
        env,
        Some(&cast.alice),
        "POST",
        &cast.chan.messages(),
        Some(text_with_id("@bob hi", "c1")),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{again}");
    assert_eq!(
        all_entries(env, &cast.bob).await,
        want(&[("mention", &first)])
    );
}

async fn connect(cast: &Cast, who: &Party) -> Client {
    let addr = serve(cast.env.app.clone()).await;
    let mut c = Client::connect(addr, "10.0.0.2").await;
    c.authenticate(
        &who.actor,
        &who.key_id,
        &who.key,
        SIGNED_AT.unix_timestamp(),
    )
    .await;
    c
}

#[tokio::test]
async fn notification_created_reaches_only_the_recipient() {
    let cast = Cast::new().await;
    let mut phone = connect(&cast, &cast.bob).await;
    let mut laptop = connect(&cast, &cast.bob).await;
    let mut carol = connect(&cast, &cast.carol).await;
    let mut alice = connect(&cast, &cast.alice).await;

    let m = say(&cast, &cast.alice, text("@bob ping")).await;
    let page = common::notifications::feed(&cast.env, &cast.bob, "").await;
    for c in [&mut phone, &mut laptop] {
        let e = c.event().await;
        assert_eq!(e["type"], "notification.created", "{e}");
        assert_valid(&schema("ws/notification-created.json"), &e);
        assert_eq!(e["data"]["notification"], page["items"][0]);
        assert_eq!(e["data"]["notification"]["sourceMessageId"], m.as_str());
        assert_eq!(e["data"]["notification"]["author"], cast.alice.actor);
    }
    assert!(carol.silent_for(QUIET).await);
    assert!(alice.silent_for(QUIET).await);
}
