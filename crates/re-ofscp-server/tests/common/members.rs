//! Requests against the §5.7 membership endpoints
//! (tests/groups_membership.rs, tests/groups_member_edits.rs,
//! tests/ws_members.rs).

use axum::http::StatusCode;
use serde_json::{Value, json};

use super::groups::{Env, Party, call};

/// `POST /api/groups/{group}/join` as `who`, with `body`.
pub async fn join_http(
    env: &Env,
    who: &Party,
    group: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    call(
        env,
        Some(who),
        "POST",
        &format!("/api/groups/{group}/join"),
        body,
    )
    .await
}

/// `GET /api/groups/{group}/members{query}` as `who`.
pub async fn members(
    env: &Env,
    who: Option<&Party>,
    group: &str,
    query: &str,
) -> (StatusCode, Value) {
    call(
        env,
        who,
        "GET",
        &format!("/api/groups/{group}/members{query}"),
        None,
    )
    .await
}

/// Every member of `group` as `(user, role)`, newest first, read as `who`.
pub async fn roster(env: &Env, who: &Party, group: &str) -> Vec<(String, String)> {
    let (s, page) = members(env, Some(who), group, "?limit=100").await;
    assert_eq!(s, StatusCode::OK, "{page}");
    page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| {
            (
                m["user"].as_str().unwrap().to_owned(),
                m["role"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

/// `PATCH /api/groups/{group}/members/{user_ref}` to `role`, as `by`.
pub async fn set_role(
    env: &Env,
    by: &Party,
    group: &str,
    user_ref: &str,
    role: &str,
) -> (StatusCode, Value) {
    let path = format!("/api/groups/{group}/members/{user_ref}");
    call(env, Some(by), "PATCH", &path, Some(json!({ "role": role }))).await
}

/// `DELETE /api/groups/{group}/members/{user_ref}` as `by`.
pub async fn kick(env: &Env, by: &Party, group: &str, user_ref: &str) -> StatusCode {
    let path = format!("/api/groups/{group}/members/{user_ref}");
    call(env, Some(by), "DELETE", &path, None).await.0
}

/// `PATCH .../members/{user_ref}/display-name` with `body`, as `by`.
pub async fn nickname(
    env: &Env,
    by: &Party,
    group: &str,
    user_ref: &str,
    body: Value,
) -> (StatusCode, Value) {
    let path = format!("/api/groups/{group}/members/{user_ref}/display-name");
    call(env, Some(by), "PATCH", &path, Some(body)).await
}

/// `POST /api/groups/{group}/leave` as `who`.
pub async fn leave(env: &Env, who: &Party, group: &str) -> StatusCode {
    call(
        env,
        Some(who),
        "POST",
        &format!("/api/groups/{group}/leave"),
        None,
    )
    .await
    .0
}

/// A group body of `tier` and `join_policy`, with any `extra` fields.
pub fn group_with_policy(tier: &str, join_policy: &str, extra: Value) -> Value {
    let mut body = json!({ "name": "G", "tier": tier, "joinPolicy": join_policy });
    if let (Some(b), Some(e)) = (body.as_object_mut(), extra.as_object()) {
        b.extend(e.clone());
    }
    body
}
