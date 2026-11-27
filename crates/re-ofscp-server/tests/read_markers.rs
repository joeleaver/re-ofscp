//! Read markers and unread counts (spec §7.7; docs/decisions/0021;
//! security requirements 1 and 5), on a real rhypedb-server: `GET`/`PATCH
//! /api/me/read-markers` and the `read.updated` event. Exact counts are in
//! tests/read_marker_counts.rs.

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use common::groups::{Env, Party, call, create_channel, env_with_remotes, id, remote};
use common::harness::SIGNED_AT;
use common::members::kick;
use common::messages::{Chan, public_channel};
use common::read_markers::{mark, posts, scopes, setup};
use common::ws::{Client, serve};
use common::{assert_valid, schema};
use re_ofscp_server::read_markers::store::MarkerStore;
use serde_json::{Value, json};

const QUIET: Duration = Duration::from_millis(300);

fn assert_problem(status: StatusCode, body: &Value, want: StatusCode, code: &str) {
    assert_eq!(status, want, "{body}");
    assert_eq!(body["errorCode"], code, "{body}");
}

#[tokio::test]
async fn remote_and_unsigned_callers_are_refused() {
    let carol = remote("carol", "b.example");
    let env = env_with_remotes(&[&carol]).await;
    let body = json!({"markers": [{"scopeId": "chn_1", "lastReadMessageId": "msg_1"}]});
    for (method, body) in [("GET", None), ("PATCH", Some(body))] {
        let path = "/api/me/read-markers";
        let (s, b) = call(&env, Some(&carol), method, path, body.clone()).await;
        assert_problem(s, &b, StatusCode::FORBIDDEN, "forbidden");
        let (s, b) = call(&env, None, method, path, body).await;
        assert_problem(s, &b, StatusCode::UNAUTHORIZED, "unauthorized");
    }
}

#[tokio::test]
async fn malformed_bodies_are_400() {
    let (env, _, bob, _) = setup().await;
    for body in [
        json!({}),
        json!({"markers": []}),
        json!({"markers": [{"scopeId": "chn_1"}]}),
        json!({"markers": [{"scopeId": "", "lastReadMessageId": "msg_1"}]}),
        json!({"markers": [{"scopeId": "chn_1", "lastReadSeq": 4}]}),
    ] {
        let (s, b) = call(
            &env,
            Some(&bob),
            "PATCH",
            "/api/me/read-markers",
            Some(body),
        )
        .await;
        assert_problem(s, &b, StatusCode::BAD_REQUEST, "bad_request");
    }
}

#[tokio::test]
async fn scopes_are_the_readable_channels_of_the_users_groups() {
    let (env, alice, bob, chan) = setup().await;
    // A channel of the same group bob may not view, and a public group he
    // is not in: neither is a scope of his.
    let body = json!({"type": "text", "tier": "public", "permissions": {"view": ["admin"]}});
    let hidden = id(&create_channel(&env, &alice, &chan.g, body).await);
    let elsewhere = public_channel(&env, &alice).await;
    let m = posts(&env, &alice, &chan, 3).await;
    posts(&env, &bob, &chan, 1).await;

    let got = scopes(&env, &bob).await;
    assert_eq!(
        got,
        [json!({"scopeId": chan.c, "unreadCount": 3, "groupId": chan.g})]
    );
    // Alice sees every channel; her own messages are never unread.
    let mut mine: Vec<String> = scopes(&env, &alice)
        .await
        .iter()
        .map(|s| {
            assert_eq!(s["unreadCount"], if s["scopeId"] == chan.c { 1 } else { 0 });
            s["scopeId"].as_str().unwrap().to_owned()
        })
        .collect();
    mine.sort();
    let mut want = vec![chan.c.clone(), hidden, elsewhere.c];
    want.sort();
    assert_eq!(mine, want);

    // A deleted message keeps its place in history, and still counts.
    let (s, _) = call(&env, Some(&alice), "DELETE", &chan.message(&m[2]), None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(scopes(&env, &bob).await[0]["unreadCount"], 3);

    // Kicked, bob has no scopes there.
    assert_eq!(
        kick(&env, &alice, &chan.g, "bob").await,
        StatusCode::NO_CONTENT
    );
    assert!(scopes(&env, &bob).await.is_empty());
}

#[tokio::test]
async fn markers_only_move_forward() {
    let (env, alice, bob, chan) = setup().await;
    let m = posts(&env, &alice, &chan, 3).await;
    posts(&env, &bob, &chan, 1).await;

    let moved = mark(&env, &bob, &[(&chan.c, &m[1])]).await;
    let want = json!({
        "scopeId": chan.c, "lastReadMessageId": m[1], "unreadCount": 1, "groupId": chan.g,
    });
    assert_eq!(moved, std::slice::from_ref(&want));
    assert_eq!(scopes(&env, &bob).await, std::slice::from_ref(&want));
    // Behind or at the marker: nothing moves, nothing is reported.
    assert!(mark(&env, &bob, &[(&chan.c, &m[0])]).await.is_empty());
    assert!(mark(&env, &bob, &[(&chan.c, &m[1])]).await.is_empty());
    assert_eq!(scopes(&env, &bob).await, [want]);

    // Several markers for one scope: the newest wins, reported once.
    let moved = mark(&env, &bob, &[(&chan.c, &m[2]), (&chan.c, &m[0])]).await;
    assert_eq!(moved.len(), 1);
    assert_eq!(moved[0]["lastReadMessageId"], m[2].as_str());
    assert_eq!(moved[0]["unreadCount"], 0);
}

#[tokio::test]
async fn markers_for_unusable_scopes_are_ignored() {
    let (env, alice, bob, chan) = setup().await;
    let body = json!({"type": "text", "tier": "public", "permissions": {"view": ["admin"]}});
    let hidden = Chan {
        g: chan.g.clone(),
        c: id(&create_channel(&env, &alice, &chan.g, body).await),
    };
    let elsewhere = public_channel(&env, &alice).await;
    let in_hidden = posts(&env, &alice, &hidden, 1).await;
    let in_elsewhere = posts(&env, &alice, &elsewhere, 1).await;
    let in_chan = posts(&env, &alice, &chan, 1).await;

    // A channel bob cannot view, one in a group he is not in, one that does
    // not exist, a scope that is no id, and a message of another channel:
    // each is ignored with 200, as an unknown scope (§7.7).
    let moved = mark(
        &env,
        &bob,
        &[
            (&hidden.c, &in_hidden[0]),
            (&elsewhere.c, &in_elsewhere[0]),
            ("chn_nosuch", &in_chan[0]),
            ("not an id", &in_chan[0]),
            (&chan.c, &in_elsewhere[0]),
            (&chan.c, "msg_nosuch"),
        ],
    )
    .await;
    assert!(moved.is_empty());
    let store = MarkerStore::new(env.state.db.clone());
    let ids = [hidden.c.clone(), elsewhere.c.clone(), chan.c.clone()];
    assert!(store.for_scopes(&bob.id(), &ids).await.unwrap().is_empty());
}

#[tokio::test]
async fn a_deleted_channels_markers_are_purged_by_the_sweeper() {
    let (env, alice, bob, chan) = setup().await;
    let m = posts(&env, &alice, &chan, 1).await;
    assert_eq!(mark(&env, &bob, &[(&chan.c, &m[0])]).await.len(), 1);
    let store = MarkerStore::new(env.state.db.clone());
    assert!(store.get(&bob.id(), &chan.c).await.unwrap().is_some());

    let (s, _) = call(&env, Some(&alice), "DELETE", &chan.channel(), None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(scopes(&env, &bob).await.is_empty());
    env.state
        .messages
        .sweep(SIGNED_AT.unix_timestamp())
        .await
        .unwrap();
    assert!(store.get(&bob.id(), &chan.c).await.unwrap().is_none());
}

async fn connect(env: &Env, who: &Party) -> Client {
    let addr = serve(env.app.clone()).await;
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
async fn moves_reach_every_connection_of_the_user_and_no_one_else() {
    let (env, alice, bob, chan) = setup().await;
    let m = posts(&env, &alice, &chan, 2).await;
    let mut phone = connect(&env, &bob).await;
    let mut laptop = connect(&env, &bob).await;
    let mut other = connect(&env, &alice).await;

    let moved = mark(&env, &bob, &[(&chan.c, &m[0])]).await;
    for c in [&mut phone, &mut laptop] {
        let e = c.event().await;
        assert_eq!(e["type"], "read.updated", "{e}");
        assert_valid(&schema("ws/read-updated.json"), &e);
        assert_eq!(e["data"], json!({ "markers": moved }));
    }
    // A request that moves nothing announces nothing.
    assert!(mark(&env, &bob, &[(&chan.c, &m[0])]).await.is_empty());
    assert!(phone.silent_for(QUIET).await);
    assert!(other.silent_for(QUIET).await);
}
