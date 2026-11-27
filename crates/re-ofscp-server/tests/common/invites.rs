//! Requests against the §5.6 invite endpoints (tests/groups_invites.rs,
//! tests/groups_invite_races.rs).

use axum::http::StatusCode;
use re_ofscp_server::db::Ql;
use serde_json::{Value, json};

use super::groups::{Env, Party, call};

/// `POST /api/groups/{group}/invites` as `by`, with `body`.
pub async fn create_invite_http(
    env: &Env,
    by: Option<&Party>,
    group: &str,
    body: Value,
) -> (StatusCode, Value) {
    let path = format!("/api/groups/{group}/invites");
    call(env, by, "POST", &path, Some(body)).await
}

/// Create an invite in `group` as `by`; panics unless `201`. Returns it.
pub async fn create_invite(env: &Env, by: &Party, group: &str, body: Value) -> Value {
    let (s, i) = create_invite_http(env, Some(by), group, body).await;
    assert_eq!(s, StatusCode::CREATED, "{i}");
    i
}

/// The `token` of an invite.
pub fn token(invite: &Value) -> String {
    invite["token"].as_str().unwrap().to_owned()
}

/// `POST /api/invites/{token}/redeem` as `who`.
pub async fn redeem(env: &Env, who: Option<&Party>, token: &str) -> (StatusCode, Value) {
    let path = format!("/api/invites/{token}/redeem");
    call(env, who, "POST", &path, Some(json!({}))).await
}

/// `GET /api/groups/{group}/invites{query}` as `who`.
pub async fn list_invites(
    env: &Env,
    who: Option<&Party>,
    group: &str,
    query: &str,
) -> (StatusCode, Value) {
    let path = format!("/api/groups/{group}/invites{query}");
    call(env, who, "GET", &path, None).await
}

/// The `uses` the list shows for invite `id` (as `by`, a manager).
pub async fn uses(env: &Env, by: &Party, group: &str, id: &str) -> u64 {
    let (s, list) = list_invites(env, Some(by), group, "").await;
    assert_eq!(s, StatusCode::OK, "{list}");
    list["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["id"] == json!(id))
        .unwrap_or_else(|| panic!("invite {id} not listed: {list}"))["uses"]
        .as_u64()
        .unwrap()
}

/// How many rows of `kind` (`GroupInvite`, `GroupInviteUse`,
/// `Membership`, `JoinRequest`) belong to `group`.
pub async fn rows_of_group(env: &Env, kind: &'static str, group: &str) -> usize {
    let q = match kind {
        "GroupInvite" => Ql::new("GroupInvite.filter(.group_id == "),
        "GroupInviteUse" => Ql::new("GroupInviteUse.filter(.group_id == "),
        "Membership" => Ql::new("Membership.filter(.group_id == "),
        "JoinRequest" => Ql::new("JoinRequest.filter(.group_id == "),
        other => panic!("not a type these tests count: {other}"),
    };
    let q = q.str(group).raw(")");
    env.state
        .db
        .fetch::<serde::de::IgnoredAny>(&q)
        .await
        .unwrap()
        .len()
}
