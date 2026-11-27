//! Channels from before message ordinals (docs/decisions/0022 *Existing
//! data*), on a real rhypedb-server: numbered exactly by the first request
//! when short, by the background task when long (the request answering
//! `503` meanwhile), and numbered on past edits without starting over.

mod common;

use std::collections::BTreeMap;
use std::time::Duration;

use axum::http::StatusCode;
use common::groups::{Env, Party, call, id};
use common::messages::{Chan, post, text};
use common::read_markers::{legacy_log, legacy_message, mark, scopes, setup, unread};
use futures_util::future::join_all;
use re_ofscp_server::messages::numbering::{INLINE_LIMIT, Numbering};
use re_ofscp_server::messages::{log, tally};
use serde_json::{Value, json};

/// The creation ordinal of message `m` of `chan`.
async fn ordinal(env: &Env, chan: &Chan, m: &str) -> i64 {
    let store = env.state.messages.store();
    store.message(&chan.c, m).await.unwrap().unwrap().n.unwrap()
}

/// A legacy channel of twelve positions, where 4 and 9 were edits: ten
/// messages, seven by alice (one deleted), three by bob. Message ids by
/// position.
async fn legacy_channel(
    env: &Env,
    alice: &Party,
    bob: &Party,
    chan: &Chan,
) -> BTreeMap<i64, String> {
    legacy_log(env, chan, 12).await;
    let mut by_seq = BTreeMap::new();
    for (seq, who, deleted) in [
        (1, alice, false),
        (2, bob, false),
        (3, alice, false),
        (5, alice, true),
        (6, bob, false),
        (7, alice, false),
        (8, alice, false),
        (10, bob, false),
        (11, alice, false),
        (12, alice, false),
    ] {
        by_seq.insert(seq, legacy_message(env, chan, seq, who, deleted).await);
    }
    by_seq
}

#[tokio::test]
async fn short_channels_are_numbered_by_the_first_request() {
    let (env, alice, bob, chan) = setup().await;
    let by_seq = legacy_channel(&env, &alice, &bob, &chan).await;
    // The first readers number the channel once, whichever of them gets
    // there first; all of them see the same exact counts.
    let first = join_all((0..8).map(|_| unread(&env, &bob, &chan.c))).await;
    assert!(first.iter().all(|n| *n == 7), "{first:?}");
    assert_eq!(unread(&env, &alice, &chan.c).await, 3);
    assert_eq!(ordinal(&env, &chan, &by_seq[&12]).await, 10);
    assert_eq!(ordinal(&env, &chan, &by_seq[&6]).await, 5);

    // Bob at his own message (seq 6): alice's 7, 8, 11, 12 are after it.
    assert_eq!(
        mark(&env, &bob, &[(&chan.c, &by_seq[&6])]).await[0]["unreadCount"],
        4
    );
    // Alice at seq 7: bob's 10.
    assert_eq!(
        mark(&env, &alice, &[(&chan.c, &by_seq[&7])]).await[0]["unreadCount"],
        1
    );
    // New messages continue the numbering.
    let new = id(&post(&env, &alice, &chan, text("new")).await);
    assert_eq!(ordinal(&env, &chan, &new).await, 11);
    assert_eq!(unread(&env, &bob, &chan.c).await, 5);
    assert_eq!(unread(&env, &alice, &chan.c).await, 1);
}

fn assert_numbering(s: StatusCode, body: &Value) {
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["errorCode"], "service_unavailable", "{body}");
}

#[tokio::test]
async fn long_channels_are_numbered_in_the_background_and_requests_wait_with_503() {
    let (env, alice, bob, chan) = setup().await;
    // Past the inline limit: positions mostly edits, so the test is quick,
    // but a request must not number it itself.
    legacy_log(&env, &chan, INLINE_LIMIT + 1).await;
    let first = legacy_message(&env, &chan, 1, &alice, false).await;
    let last = legacy_message(&env, &chan, INLINE_LIMIT + 1, &bob, false).await;

    let (s, b) = call(&env, Some(&bob), "GET", "/api/me/read-markers", None).await;
    assert_numbering(s, &b);
    let body = json!({"markers": [{"scopeId": chan.c, "lastReadMessageId": first}]});
    let (s, b) = call(
        &env,
        Some(&bob),
        "PATCH",
        "/api/me/read-markers",
        Some(body),
    )
    .await;
    assert_numbering(s, &b);
    let (s, b) = call(
        &env,
        Some(&alice),
        "POST",
        &chan.messages(),
        Some(text("x")),
    )
    .await;
    assert_numbering(s, &b);
    // Nothing was numbered or taken by them.
    let counts = log::read_counts(&env.state.db, &chan.c)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((counts.last_seq, counts.messages), (INLINE_LIMIT + 1, None));

    // The background task numbers it (its startup pass, or the requests'
    // hand-over), and the same requests then answer exactly.
    let task = tokio::spawn(env.state.messages.clone().number_forever());
    let mut got = None;
    for _ in 0..200 {
        let (s, b) = call(&env, Some(&bob), "GET", "/api/me/read-markers", None).await;
        if s == StatusCode::OK {
            got = Some(b);
            break;
        }
        assert_numbering(s, &b);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    task.abort();
    let got = got.expect("the background task numbered the channel");
    assert_eq!(got["scopes"][0]["unreadCount"], 1, "{got}");
    assert_eq!(ordinal(&env, &chan, &last).await, 2);
    assert_eq!(unread(&env, &alice, &chan.c).await, 1);
    let new = id(&post(&env, &alice, &chan, text("new")).await);
    assert_eq!(ordinal(&env, &chan, &new).await, 3);
}

#[tokio::test]
async fn the_startup_pass_numbers_every_channel_from_before() {
    let (env, alice, bob, chan) = setup().await;
    legacy_channel(&env, &alice, &bob, &chan).await;
    // A channel made since ordinals needs nothing.
    let fresh = common::messages::public_channel(&env, &alice).await;
    post(&env, &alice, &fresh, text("hi")).await;

    assert_eq!(env.state.messages.number_all().await.unwrap(), 1);
    let counts = log::read_counts(&env.state.db, &chan.c)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(counts.messages, Some(10));
    assert_eq!(
        tally::get(&env.state.db, &chan.c, &alice.actor)
            .await
            .unwrap(),
        7
    );
    assert_eq!(
        tally::get(&env.state.db, &chan.c, &bob.actor)
            .await
            .unwrap(),
        3
    );
    // Run again, it finds nothing to do.
    assert_eq!(env.state.messages.number_all().await.unwrap(), 0);
    assert_eq!(unread(&env, &bob, &chan.c).await, 7);
    assert_eq!(scopes(&env, &alice).await.len(), 2);
}

/// An edit moves `last_seq` without adding a message. One landing between
/// a numbering's reads and its final compare-and-set fails that
/// compare-and-set, and the numbering then reads only the edit's position,
/// keeping what it counted, rather than starting over (decision 0022).
#[tokio::test]
async fn an_edit_during_numbering_costs_a_reread_of_its_position_only() {
    let (env, alice, bob, chan) = setup().await;
    let by_seq = legacy_channel(&env, &alice, &bob, &chan).await;
    let db = env.state.db.clone();

    let mut run = Numbering::new(&chan.c);
    run.scan(&db, 12).await.unwrap();
    assert_eq!(run.positions_read(), 12);
    // An edit takes its position as the numbering is about to finish.
    assert_eq!(log::take(&db, &chan.c).await.unwrap(), Some(13));
    assert!(!run.finish(&db).await.unwrap());
    let counts = log::read_counts(&db, &chan.c).await.unwrap().unwrap();
    assert_eq!((counts.last_seq, counts.messages), (13, None));

    // Two more edits, then the numbering goes on from position 13.
    for want in [14, 15] {
        assert_eq!(log::take(&db, &chan.c).await.unwrap(), Some(want));
    }
    run.scan(&db, 15).await.unwrap();
    assert_eq!(run.positions_read(), 15);
    assert!(run.finish(&db).await.unwrap());
    assert_eq!(run.messages(), 10);
    let counts = log::read_counts(&db, &chan.c).await.unwrap().unwrap();
    assert_eq!((counts.last_seq, counts.messages), (15, Some(10)));

    // The counts are exact.
    assert_eq!(unread(&env, &bob, &chan.c).await, 7);
    assert_eq!(unread(&env, &alice, &chan.c).await, 3);
    assert_eq!(
        mark(&env, &bob, &[(&chan.c, &by_seq[&6])]).await[0]["unreadCount"],
        4
    );
    let new = id(&post(&env, &alice, &chan, text("new")).await);
    assert_eq!(ordinal(&env, &chan, &new).await, 11);
}
