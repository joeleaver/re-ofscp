//! The queue of messages whose `message` entries are made off the request
//! path (spec §10.1, §10.2; docs/decisions/0023, *The background queue*),
//! on a real rhypedb-server.

mod common;

use axum::http::StatusCode;
use common::groups::{Party, id};
use common::messages::{call, post, text};
use common::notifications::{Cast, SETTINGS, all_entries, set};
use re_ofscp_server::db::Ql;
use re_ofscp_server::notifications::store::FeedStore;
use serde_json::Value;

/// Post `body` in the cast's channel as `by`; its id.
async fn say(cast: &Cast, by: &Party, body: Value) -> String {
    id(&post(&cast.env, by, &cast.chan, body).await)
}

fn message(m: &str) -> Vec<(String, String)> {
    vec![("message".to_owned(), m.to_owned())]
}

#[tokio::test]
async fn nothing_is_queued_for_a_scope_with_no_all_setting() {
    let cast = Cast::new().await;
    let env = &cast.env;
    let queue = env.state.notifications.background();
    let hold = queue.hold();
    // No setting anywhere, then settings that are not `all`.
    say(&cast, &cast.alice, text("one")).await;
    set(env, &cast.bob, "channel", &cast.chan.c, "mentions").await;
    set(env, &cast.carol, "group", &cast.chan.g, "none").await;
    say(&cast, &cast.alice, text("two")).await;
    assert_eq!(queue.unfinished(), 0);

    // A channel `all` setting queues the message...
    set(env, &cast.bob, "channel", &cast.chan.c, "all").await;
    let three = say(&cast, &cast.alice, text("three")).await;
    assert_eq!(queue.unfinished(), 1);
    // ...and no longer, once cleared.
    let clear = format!("{SETTINGS}?scopeType=channel&scopeId={}", cast.chan.c);
    let (s, b) = call(env, Some(&cast.bob), "DELETE", &clear, None).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    say(&cast, &cast.alice, text("four")).await;
    assert_eq!(queue.unfinished(), 1);
    // A group `all` setting queues it too.
    set(env, &cast.carol, "group", &cast.chan.g, "all").await;
    let five = say(&cast, &cast.alice, text("five")).await;
    assert_eq!(queue.unfinished(), 2);

    drop(hold);
    env.state.notifications.flush().await;
    assert_eq!(queue.unfinished(), 0);
    // Turns read the settings as they are then: bob's is gone, carol's
    // applies to "three" too. "four" was never queued: when it was
    // created, no `all` setting covered it.
    assert!(all_entries(env, &cast.bob).await.is_empty());
    let mut want = message(&five);
    want.extend(message(&three));
    assert_eq!(all_entries(env, &cast.carol).await, want);
}

#[tokio::test]
async fn a_message_deleted_before_its_turn_gets_no_entries() {
    let cast = Cast::new().await;
    let env = &cast.env;
    set(env, &cast.bob, "channel", &cast.chan.c, "all").await;
    let hold = env.state.notifications.background().hold();
    let gone = say(&cast, &cast.alice, text("soon gone")).await;
    let kept = say(&cast, &cast.alice, text("kept")).await;
    let (s, b) = call(
        env,
        Some(&cast.alice),
        "DELETE",
        &cast.chan.message(&gone),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{b}");
    drop(hold);
    env.state.notifications.flush().await;

    assert_eq!(all_entries(env, &cast.bob).await, message(&kept));
    let rows = env
        .state
        .db
        .fetch::<Value>(
            &Ql::new("Notification.filter(.message_id == ")
                .str(&gone)
                .raw(")"),
        )
        .await
        .unwrap();
    assert!(rows.is_empty(), "{rows:?}");
}

#[tokio::test]
async fn a_direct_entry_leaves_no_gap_for_a_message_entry() {
    let cast = Cast::new().await;
    let env = &cast.env;
    set(env, &cast.bob, "channel", &cast.chan.c, "all").await;
    let first = say(&cast, &cast.alice, text("@bob first")).await;
    let second = say(&cast, &cast.alice, text("second")).await;
    assert_eq!(
        all_entries(env, &cast.bob).await,
        vec![
            ("message".to_owned(), second),
            ("mention".to_owned(), first),
        ]
    );
    // Two entries, two positions: the turn for the mentioned message took
    // none for bob.
    let feed = FeedStore::new(env.state.db.clone());
    assert_eq!(feed.last(&cast.bob.actor).await.unwrap(), 2);
}
