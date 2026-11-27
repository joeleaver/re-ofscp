//! Requests against `/api/me/read-markers` (tests/read_markers.rs,
//! tests/read_marker_counts.rs).

use axum::http::StatusCode;
use serde_json::{Value, json};

use super::groups::{Env, Party, call, env_with_remotes, id, join, local};
use super::messages::{Chan, post, public_channel, text};
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
