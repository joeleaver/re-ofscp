//! Exact unread counts (spec §7.7: "MUST be exact", lost-conn/ofscp#41;
//! docs/decisions/0022) on a real rhypedb-server: long runs, tombstones,
//! the reader's own messages, concurrent writers and markers, and creates
//! left part-way. Channels from before message ordinals are in
//! tests/read_marker_numbering.rs.

mod common;

use std::collections::BTreeSet;

use axum::http::StatusCode;
use common::groups::{Env, Party, call, id};
use common::messages::{Chan, post, reply, text, text_with_id};
use common::races::RACERS;
use common::read_markers::{mark, posts, scopes, setup, unread};
use futures_util::future::join_all;
use re_ofscp_server::db::Ql;
use re_ofscp_server::messages::{log, tally};
use re_ofscp_server::read_markers::store::MarkerStore;

/// The creation ordinal of message `m` of `chan`.
async fn ordinal(env: &Env, chan: &Chan, m: &str) -> i64 {
    let store = env.state.messages.store();
    store.message(&chan.c, m).await.unwrap().unwrap().n.unwrap()
}

async fn delete(env: &Env, by: &Party, chan: &Chan, m: &str) {
    let (s, b) = call(env, Some(by), "DELETE", &chan.message(m), None).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{b}");
}

#[tokio::test]
async fn more_than_a_hundred_unread_are_counted_exactly() {
    let (env, alice, bob, chan) = setup().await;
    let m = posts(&env, &alice, &chan, 150).await;
    let got = scopes(&env, &bob).await;
    assert_eq!(got[0]["unreadCount"], 150, "{}", got[0]);
    assert!(got[0].get("unreadCountCapped").is_none(), "{}", got[0]);
    // His own message is never unread.
    posts(&env, &bob, &chan, 1).await;
    assert_eq!(unread(&env, &bob, &chan.c).await, 150);
    let moved = mark(&env, &bob, &[(&chan.c, &m[9])]).await;
    assert_eq!(moved[0]["unreadCount"], 140);
    assert_eq!(unread(&env, &bob, &chan.c).await, 140);
}

#[tokio::test]
async fn tombstones_keep_counting() {
    let (env, alice, bob, chan) = setup().await;
    let m = posts(&env, &alice, &chan, 5).await;
    mark(&env, &bob, &[(&chan.c, &m[0])]).await;
    delete(&env, &alice, &chan, &m[2]).await;
    delete(&env, &alice, &chan, &m[3]).await;
    assert_eq!(unread(&env, &bob, &chan.c).await, 4);
    // A marker may rest on a tombstone.
    assert_eq!(
        mark(&env, &bob, &[(&chan.c, &m[3])]).await[0]["unreadCount"],
        1
    );
    mark(&env, &bob, &[(&chan.c, &m[4])]).await;
    delete(&env, &alice, &chan, &m[4]).await;
    assert_eq!(unread(&env, &bob, &chan.c).await, 0);
}

#[tokio::test]
async fn the_readers_own_messages_before_and_after_the_marker_never_count() {
    let (env, alice, bob, chan) = setup().await;
    // A1 B1 A2 B2 A3 B3 A4 (a reply to B1) B4 A5.
    let mut seq: Vec<String> = Vec::new();
    for i in 0..9 {
        let (by, body) = match i {
            6 => (&alice, reply("A4", &seq[1])),
            i if i % 2 == 0 => (&alice, text(&format!("A{}", i / 2 + 1))),
            i => (&bob, text(&format!("B{}", i / 2 + 1))),
        };
        seq.push(id(&post(&env, by, &chan, body).await));
    }
    assert_eq!(unread(&env, &bob, &chan.c).await, 5);
    assert_eq!(unread(&env, &alice, &chan.c).await, 4);
    // At A3: A4 and A5 are after it; B3 and B4 are his.
    assert_eq!(
        mark(&env, &bob, &[(&chan.c, &seq[4])]).await[0]["unreadCount"],
        2
    );
    // At his own B3: the same two.
    assert_eq!(
        mark(&env, &bob, &[(&chan.c, &seq[5])]).await[0]["unreadCount"],
        2
    );
    // Alice at B2: B3 and B4.
    assert_eq!(
        mark(&env, &alice, &[(&chan.c, &seq[3])]).await[0]["unreadCount"],
        2
    );
    posts(&env, &bob, &chan, 1).await;
    assert_eq!(unread(&env, &bob, &chan.c).await, 2);
    assert_eq!(unread(&env, &alice, &chan.c).await, 3);
    // The newest message read: nothing left.
    let last = seq.last().unwrap();
    assert_eq!(
        mark(&env, &bob, &[(&chan.c, last)]).await[0]["unreadCount"],
        0
    );
}

#[tokio::test]
async fn concurrent_creates_keep_ordinals_dense_and_counts_exact() {
    let (env, alice, bob, chan) = setup().await;
    let half = RACERS / 2;
    let path = chan.messages();
    let creates = (0..RACERS).map(|i| {
        let by = if i < half { &alice } else { &bob };
        call(&env, Some(by), "POST", &path, Some(text(&format!("m{i}"))))
    });
    // And one message alice sends several times with one clientMessageId.
    let repeats = (0..8).map(|_| {
        let body = text_with_id("once", "c-1");
        call(&env, Some(&alice), "POST", &path, Some(body))
    });
    let (made, repeated) = tokio::join!(join_all(creates), join_all(repeats));
    let mut ids: Vec<String> = Vec::new();
    for (s, m) in &made {
        assert_eq!(*s, StatusCode::CREATED, "{m}");
        ids.push(id(m));
    }
    let once: BTreeSet<String> = repeated.iter().map(|(_, m)| id(m)).collect();
    assert_eq!(once.len(), 1, "{repeated:?}");
    ids.extend(once);

    let mut ordinals = Vec::new();
    for m in &ids {
        ordinals.push(ordinal(&env, &chan, m).await);
    }
    ordinals.sort_unstable();
    let total = i64::try_from(ids.len()).unwrap();
    assert_eq!(ordinals, (1..=total).collect::<Vec<_>>());
    let alices = u64::try_from(half + 1).unwrap();
    assert_eq!(unread(&env, &bob, &chan.c).await, alices);
    assert_eq!(
        unread(&env, &alice, &chan.c).await,
        u64::try_from(RACERS - half).unwrap()
    );
    let db = env.state.db.clone();
    assert_eq!(
        tally::get(&db, &chan.c, &alice.actor).await.unwrap(),
        i64::try_from(alices).unwrap()
    );
}

#[tokio::test]
async fn concurrent_marker_updates_end_at_the_newest_message() {
    let (env, alice, bob, chan) = setup().await;
    let m = posts(&env, &alice, &chan, 40).await;
    let newest = m.last().unwrap().clone();
    let updates = (0..RACERS).map(|k| {
        let at = if k == RACERS / 2 {
            newest.clone()
        } else {
            m[(k * 7) % 39].clone()
        };
        let scope = chan.c.clone();
        let (env, bob) = (&env, &bob);
        async move { mark(env, bob, &[(&scope, &at)]).await }
    });
    join_all(updates).await;
    let got = scopes(&env, &bob).await;
    assert_eq!(got[0]["lastReadMessageId"], newest.as_str(), "{}", got[0]);
    assert_eq!(got[0]["unreadCount"], 0);
    let stored = MarkerStore::new(env.state.db.clone())
        .get(&bob.id(), &chan.c)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((stored.n, stored.own), (40, 0));
}

/// Leave a create of `author` pending on `chan`'s log as a process that
/// stopped part-way would: its position and ordinal taken, and its
/// author's ordinal too when `took_tally`, but no message written.
async fn stalled_create(env: &Env, chan: &Chan, author: &Party, took_tally: bool) {
    #[derive(serde::Deserialize)]
    struct Log {
        last_seq: i64,
        message_count: i64,
    }
    let db = &env.state.db;
    let q = Ql::new("ChannelLog.filter(.channel_id == ")
        .str(&chan.c)
        .raw(")");
    let log = db.one::<Log>(&q).await.unwrap().data;
    let q = Ql::new("ChannelLog.filter(.channel_id == ")
        .str(&chan.c)
        .raw(").update({ last_seq: ")
        .int(log.last_seq + 1)
        .raw(", message_count: ")
        .int(log.message_count + 1)
        .raw(", pending_id: \"msg_stalled\", pending_author: ")
        .str(&author.actor)
        .raw(" })");
    db.execute(&q).await.unwrap();
    if took_tally {
        let count = tally::get(db, &chan.c, &author.actor).await.unwrap();
        let q = Ql::new("MessageTally.filter(.key == ")
            .str(&format!("{} {}", chan.c, author.actor))
            .raw(").update({ count: ")
            .int(count + 1)
            .raw(" })");
        db.execute(&q).await.unwrap();
    }
}

#[tokio::test]
async fn a_create_left_part_way_is_settled_exactly() {
    let (env, alice, bob, chan) = setup().await;
    posts(&env, &alice, &chan, 3).await;
    let db = env.state.db.clone();

    // Stopped after taking its author's ordinal: a read settles it.
    stalled_create(&env, &chan, &alice, true).await;
    assert_eq!(unread(&env, &bob, &chan.c).await, 3);
    assert_eq!(tally::get(&db, &chan.c, &alice.actor).await.unwrap(), 3);
    let m = id(&post(&env, &alice, &chan, text("4")).await);
    assert_eq!(ordinal(&env, &chan, &m).await, 4);

    // Stopped before it: the next create settles it, and the tally is
    // left alone.
    stalled_create(&env, &chan, &alice, false).await;
    let m = id(&post(&env, &alice, &chan, text("5")).await);
    assert_eq!(ordinal(&env, &chan, &m).await, 5);
    assert_eq!(tally::get(&db, &chan.c, &alice.actor).await.unwrap(), 5);
    assert_eq!(unread(&env, &bob, &chan.c).await, 5);
    assert_eq!(
        mark(&env, &bob, &[(&chan.c, &m)]).await[0]["unreadCount"],
        0
    );
}

/// A create that finds another create still pending after settling under
/// its lock can only be meeting another process's (decision 0022): the
/// log refuses it a position (`Unsettled`), which the create answers `503`
/// with `Retry-After` (`messages/routes.rs` pins that mapping). Nothing is
/// taken meanwhile.
#[tokio::test]
async fn a_create_meeting_a_pending_create_takes_nothing() {
    let (env, alice, _bob, chan) = setup().await;
    posts(&env, &alice, &chan, 2).await;
    let db = env.state.db.clone();
    stalled_create(&env, &chan, &alice, false).await;
    let before = log::read_counts(&db, &chan.c).await.unwrap().unwrap();
    assert_eq!(
        log::take_create(&db, &chan.c, "msg_other", &alice.actor)
            .await
            .unwrap(),
        log::CreateTake::Unsettled
    );
    assert_eq!(
        log::read_counts(&db, &chan.c).await.unwrap().unwrap(),
        before
    );
}
