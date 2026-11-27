//! Requests against the group list (`/api/me/groups`, spec §5.7 *My
//! groups*) for tests/my_groups.rs and tests/my_groups_ws.rs.

use axum::http::StatusCode;
use serde_json::Value;

use super::groups::{Env, Party, call};

/// Percent-encode `s` as one path segment: everything but RFC 3986
/// unreserved characters.
pub fn segment(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The path of `group_ref`'s pointer.
pub fn pointer_path(group_ref: &str) -> String {
    format!("/api/me/groups/{}", segment(group_ref))
}

/// `PUT` a pointer to `group_ref` as `by` with `body`.
pub async fn put(
    env: &Env,
    by: &Party,
    group_ref: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    call(env, Some(by), "PUT", &pointer_path(group_ref), body).await
}

/// `DELETE` the pointer to `group_ref` as `by`.
pub async fn delete(env: &Env, by: &Party, group_ref: &str) -> (StatusCode, Value) {
    call(env, Some(by), "DELETE", &pointer_path(group_ref), None).await
}

/// `GET /api/me/groups` as `by`; panics unless `200`. Returns `groups`.
pub async fn list(env: &Env, by: &Party) -> Vec<Value> {
    let (s, body) = call(env, Some(by), "GET", "/api/me/groups", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    body["groups"].as_array().unwrap().clone()
}

/// The `group` URIs of `entries`.
pub fn uris(entries: &[Value]) -> Vec<String> {
    entries
        .iter()
        .map(|e| e["group"].as_str().unwrap().to_owned())
        .collect()
}

/// The object URI of hosted group `id` on `providera.com`.
pub fn hosted(id: &str) -> String {
    format!("https://providera.com/api/groups/{id}")
}
