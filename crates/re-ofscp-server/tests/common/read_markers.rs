//! Requests against `/api/me/read-markers` (tests/read_markers.rs,
//! tests/read_marker_counts.rs, tests/read_marker_numbering.rs), and
//! channels as stored before message ordinals.

use axum::http::StatusCode;
use serde_json::{Value, json};

use re_ofscp_server::db::Ql;
use re_ofscp_server::messages::model::MessageDoc;

use super::groups::{Env, Party, call, env_with_remotes, id, join, local};
use super::harness::SIGNED_AT;
use super::messages::{Chan, post, public_channel, text};
use super::ws::{Client, serve};
use super::{assert_valid, schema};

/// `GET /api/me/read-markers` as `by`, checked against the schema.
pub async fn scopes(env: &Env, by: &Party) -> Vec<Value> {
    let (s, body) = call(env, Some(by), "GET", "/api/me/read-markers", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_valid(&schema("read-markers-response.json"), &body);
    body["scopes"].as_array().unwrap().clone()
}

/// `PATCH /api/me/read-markers` as `by` with `(scopeId, messageId)` pairs;
/// panics unless `200`. Returns the scopes that moved.
pub async fn mark(env: &Env, by: &Party, markers: &[(&str, &str)]) -> Vec<Value> {
    let markers: Vec<Value> = markers
        .iter()
        .map(|(s, m)| json!({"scopeId": s, "lastReadMessageId": m}))
        .collect();
    let body = json!({ "markers": markers });
    let (s, body) = call(env, Some(by), "PATCH", "/api/me/read-markers", Some(body)).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_valid(&schema("read-markers-response.json"), &body);
    body["scopes"].as_array().unwrap().clone()
}

/// Alice's public group with one public channel, bob a member.
pub async fn setup() -> (Env, Party, Party, Chan) {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let chan = public_channel(&env, &alice).await;
    join(&env, &chan.g, &bob, "member").await;
    (env, alice, bob, chan)
}

/// Post `n` messages in `chan` as `by`; their ids, in order.
pub async fn posts(env: &Env, by: &Party, chan: &Chan, n: usize) -> Vec<String> {
    let mut ids = Vec::with_capacity(n);
    for i in 0..n {
        ids.push(id(&post(env, by, chan, text(&format!("m{i}"))).await));
    }
    ids
}

/// `by`'s unread count in `scope`, from `GET`.
pub async fn unread(env: &Env, by: &Party, scope: &str) -> u64 {
    let got = scopes(env, by).await;
    let entry = got
        .iter()
        .find(|s| s["scopeId"] == scope)
        .unwrap_or_else(|| panic!("no scope {scope} in {got:?}"));
    entry["unreadCount"].as_u64().unwrap()
}

/// Give `chan` a log as stored before message ordinals: no `counted` or
/// `message_count`, positions `1..=last_seq` handed out.
pub async fn legacy_log(env: &Env, chan: &Chan, last_seq: i64) {
    let q = Ql::new("ChannelLog.create({ channel_id: ")
        .str(&chan.c)
        .raw(", group_id: ")
        .str(&chan.g)
        .raw(", last_seq: ")
        .int(last_seq)
        .raw(", state: \"open\", purged_at: 0 })");
    env.state.db.execute(&q).await.unwrap();
}

/// Write a message at position `seq` of `chan` as stored before
/// ordinals: no `n`, `author_n` or `apos`. Returns its id.
pub async fn legacy_message(
    env: &Env,
    chan: &Chan,
    seq: i64,
    author: &Party,
    deleted: bool,
) -> String {
    let id = format!("msg_legacy{seq}");
    let now = SIGNED_AT.unix_timestamp();
    let q = Ql::new("Message.create({ message_id: ")
        .str(&id)
        .raw(", channel_id: ")
        .str(&chan.c)
        .raw(", group_id: ")
        .str(&chan.g)
        .raw(", pos: ")
        .str(&format!("{}:{seq}", chan.c))
        .raw(", seq: ")
        .int(seq)
        .raw(", client_key: ")
        .str(&format!("m {id}"))
        .raw(", author: ")
        .str(&author.actor)
        .raw(", kind: \"message\", parent_id: \"\", reply_pos: ")
        .str(&format!("m {id}"))
        .raw(", reply_seq: 0, reaction_seq: 0, doc: ")
        .str(&serde_json::to_string(&MessageDoc::default()).unwrap())
        .raw(", created_at: ")
        .unix_seconds(now)
        .raw(", edit_until: 0, edited_at: 0, revision: 0, deleted_at: ")
        .int(if deleted { now } else { 0 })
        .raw(" })");
    env.state.db.execute(&q).await.unwrap();
    id
}

/// A WebSocket connection of `who`, authenticated.
pub async fn connect(env: &Env, who: &Party) -> Client {
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
