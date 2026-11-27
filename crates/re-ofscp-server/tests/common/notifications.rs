//! Requests against the notification feed and its settings (§10.1, §10.2;
//! tests/notifications*.rs), every answer checked against the spec schemas.

use axum::http::StatusCode;
use serde_json::{Value, json};

use super::groups::{Env, Party, env_with_remotes, join, local};
use super::messages::{Chan, call, group_and_channel};
use super::{assert_valid, schema};

/// The feed endpoint.
pub const FEED: &str = "/api/me/notifications";
/// The settings endpoint.
pub const SETTINGS: &str = "/api/me/notification-settings";

/// Alice (the owner), bob and carol (members), and a channel of a private
/// group (so only members can read it) on a provider that knows `remotes`.
pub struct Cast {
    pub env: Env,
    pub alice: Party,
    pub bob: Party,
    pub carol: Party,
    pub chan: Chan,
}

impl Cast {
    /// The cast, with `remotes` known to the provider.
    pub async fn with_remotes(remotes: &[&Party]) -> Self {
        let env = env_with_remotes(remotes).await;
        let alice = local(&env, "alice").await;
        let bob = local(&env, "bob").await;
        let carol = local(&env, "carol").await;
        let chan = group_and_channel(
            &env,
            &alice,
            "private",
            json!({}),
            json!({"type": "text", "tier": "public"}),
        )
        .await;
        join(&env, &chan.g, &bob, "member").await;
        join(&env, &chan.g, &carol, "member").await;
        Self {
            env,
            alice,
            bob,
            carol,
            chan,
        }
    }

    /// The cast on a provider with no remotes.
    pub async fn new() -> Self {
        Self::with_remotes(&[]).await
    }
}

/// `GET /api/me/notifications{query}` as `by`, once every entry left to the
/// background so far is made; panics unless `200`.
pub async fn feed(env: &Env, by: &Party, query: &str) -> Value {
    env.state.notifications.flush().await;
    let (s, body) = call(env, Some(by), "GET", &format!("{FEED}{query}"), None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_valid(&schema("notifications-response.json"), &body);
    body
}

/// The `(type, sourceMessageId)` of each entry of a feed page, in order.
pub fn entries(page: &Value) -> Vec<(String, String)> {
    page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| {
            (
                n["type"].as_str().unwrap().to_owned(),
                n["sourceMessageId"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

/// The `(type, sourceMessageId)` of every entry `by` can see.
pub async fn all_entries(env: &Env, by: &Party) -> Vec<(String, String)> {
    entries(&feed(env, by, "?limit=100").await)
}

/// `POST /api/me/notifications/{which}` as `by` with `body` (none when
/// `None`); panics unless `200`.
pub async fn mark(env: &Env, by: &Party, which: &str, body: Option<Value>) -> Value {
    let path = format!("{FEED}/{which}");
    let (s, out) = call(env, Some(by), "POST", &path, body).await;
    assert_eq!(s, StatusCode::OK, "{out}");
    assert_valid(&schema("notifications-mark-response.json"), &out);
    out
}

/// `PUT /api/me/notification-settings` as `by`; panics unless `200`.
pub async fn set(env: &Env, by: &Party, scope_type: &str, scope_id: &str, mode: &str) -> Value {
    let body = json!({"scopeType": scope_type, "scopeId": scope_id, "mode": mode});
    let (s, out) = call(env, Some(by), "PUT", SETTINGS, Some(body.clone())).await;
    assert_eq!(s, StatusCode::OK, "{out}");
    assert_valid(&schema("notification-setting.json"), &out);
    assert_eq!(out, body);
    out
}

/// `GET /api/me/notification-settings` as `by`: its `prefs`.
pub async fn prefs(env: &Env, by: &Party) -> Vec<Value> {
    let (s, out) = call(env, Some(by), "GET", SETTINGS, None).await;
    assert_eq!(s, StatusCode::OK, "{out}");
    assert_valid(&schema("notification-settings-response.json"), &out);
    out["prefs"].as_array().unwrap().clone()
}

/// The `counts` object a feed or mark answer carries.
pub fn counts(mention: u64, reply: u64, message: u64) -> Value {
    json!({"mention": mention, "reply": reply, "message": message})
}
