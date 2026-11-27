//! Read markers of channels being deleted (spec §7.7; docs/decisions/0022
//! *Deleted channels are not scopes*), on a real rhypedb-server.
//!
//! Deleting a channel (`delete_channel`) or its group (`purge_group`)
//! closes the channel's message logs first and removes the channel rows
//! after. These tests run the close alone, so the rows stay: the channels
//! are still listed as readable, but their counts are gone. They must be
//! left out of `GET`, `PATCH` and `read.updated`, and never answer `500`.

mod common;

use std::time::Duration;

use common::groups::{Env, Party, create_channel, id};
use common::messages::{Chan, public_channel};
use common::read_markers::{connect, mark, posts, scopes, setup};
use re_ofscp_server::messages::log;
use re_ofscp_server::read_markers::store::MarkerStore;
use serde_json::{Value, json};

const QUIET: Duration = Duration::from_millis(300);

/// Another public channel of `chan`'s group.
async fn sibling(env: &Env, owner: &Party, chan: &Chan) -> Chan {
    let body = json!({"type": "text", "tier": "public"});
    Chan {
        g: chan.g.clone(),
        c: id(&create_channel(env, owner, &chan.g, body).await),
    }
}

/// The scope ids of `got`, in order.
fn scope_ids(got: &[Value]) -> Vec<&str> {
    got.iter().filter_map(|s| s["scopeId"].as_str()).collect()
}

#[tokio::test]
async fn a_channel_whose_log_is_closed_is_no_scope() {
    let (env, alice, bob, chan) = setup().await;
    let other = sibling(&env, &alice, &chan).await;
    let m = posts(&env, &alice, &chan, 2).await;
    let o = posts(&env, &alice, &other, 1).await;
    // Bob's marker is at the first message: n = 1.
    assert_eq!(mark(&env, &bob, &[(&chan.c, &m[0])]).await.len(), 1);
    let mut phone = connect(&env, &bob).await;

    // `delete_channel`'s first step, alone: the log closes, the row stays.
    log::close_channel(&env.state.db, &chan.g, &chan.c)
        .await
        .unwrap();
    assert_eq!(
        scopes(&env, &bob).await,
        [json!({"scopeId": other.c, "unreadCount": 1, "groupId": other.g})]
    );

    // A marker there is ignored, and nothing is announced.
    assert!(mark(&env, &bob, &[(&chan.c, &m[1])]).await.is_empty());
    assert!(phone.silent_for(QUIET).await);
    // Beside a scope that moves, only that one is reported and announced.
    let moved = mark(&env, &bob, &[(&chan.c, &m[1]), (&other.c, &o[0])]).await;
    assert_eq!(scope_ids(&moved), [other.c.as_str()]);
    let e = phone.event().await;
    assert_eq!(e["type"], "read.updated", "{e}");
    assert_eq!(e["data"], json!({ "markers": moved }));
    // No marker was set in the closed channel.
    let store = MarkerStore::new(env.state.db.clone());
    let kept = store.get(&bob.id(), &chan.c).await.unwrap().unwrap();
    assert_eq!((kept.message_id.as_str(), kept.n), (m[0].as_str(), 1));

    // Its closed log dropped (as the sweeper does after both purges) while
    // the row is still there: bob's marker says the channel was written
    // to, so having no log means it was deleted. Still no scope.
    log::delete_closed(&env.state.db, &chan.c).await.unwrap();
    assert_eq!(scope_ids(&scopes(&env, &bob).await), [other.c.as_str()]);
    assert!(mark(&env, &bob, &[(&chan.c, &m[1])]).await.is_empty());
}

#[tokio::test]
async fn a_purged_groups_channels_are_no_scopes() {
    let (env, alice, bob, chan) = setup().await;
    let other = sibling(&env, &alice, &chan).await;
    let unwritten = sibling(&env, &alice, &chan).await;
    let elsewhere = public_channel(&env, &alice).await;
    common::groups::join(&env, &elsewhere.g, &bob, "member").await;
    let m = posts(&env, &alice, &chan, 2).await;
    let o = posts(&env, &alice, &other, 3).await;
    let e = posts(&env, &alice, &elsewhere, 1).await;
    mark(&env, &bob, &[(&chan.c, &m[0]), (&other.c, &o[1])]).await;

    // `purge_group`'s first step, alone: every log of the group closes.
    log::close_group(&env.state.db, &chan.g).await.unwrap();
    let mut got = scopes(&env, &bob).await;
    got.sort_by(|a, b| a["scopeId"].as_str().cmp(&b["scopeId"].as_str()));
    // A channel never written to has no log for the close to close and no
    // counts to lose: until its row goes it is a scope with nothing unread.
    // The other group is untouched.
    let mut want = vec![
        json!({"scopeId": unwritten.c, "unreadCount": 0, "groupId": unwritten.g}),
        json!({"scopeId": elsewhere.c, "unreadCount": 1, "groupId": elsewhere.g}),
    ];
    want.sort_by(|a, b| a["scopeId"].as_str().cmp(&b["scopeId"].as_str()));
    assert_eq!(got, want);

    let moved = mark(
        &env,
        &bob,
        &[(&chan.c, &m[1]), (&other.c, &o[2]), (&elsewhere.c, &e[0])],
    )
    .await;
    assert_eq!(scope_ids(&moved), [elsewhere.c.as_str()]);
}
