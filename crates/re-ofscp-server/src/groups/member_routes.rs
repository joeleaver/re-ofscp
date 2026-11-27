//! HTTP endpoints for group membership (spec §5.7, and the §8.2 channel
//! join alias).
//!
//! | Route | Who |
//! | --- | --- |
//! | `POST /api/groups/{g}/join` | anyone signed; by `joinPolicy` and tier |
//! | `POST /api/groups/{g}/channels/{c}/join` | as the group join, whatever `c` |
//! | `POST /api/groups/{g}/leave` | members but the owner |
//! | `GET /api/groups/{g}/members` | members |
//! | `PATCH /api/groups/{g}/members/{u}` | `manage` + subset rule; `owner`: the owner |
//! | `DELETE /api/groups/{g}/members/{u}` | `moderate` + subset rule |
//! | `PATCH /api/groups/{g}/members/{u}/display-name` | self; others: `members.set-nickname` + subset rule |
//! | `GET /api/groups/{g}/requests` | `manage` or `moderate` |
//! | `POST /api/groups/{g}/requests/{r}/approve` | `manage` or `moderate` |
//! | `POST /api/groups/{g}/requests/{r}/deny` | `manage` or `moderate` |
//!
//! Every route needs a user signature: unsigned is `401`, a provider
//! signature `403`. Remote actors (§8.2) use them exactly as local ones,
//! by their full actor; a `{userRef}` names anyone, local or remote
//! (`profiles::user_ref::resolve_actor`), and a malformed one is `404`.
//! Role and nickname changes emit `member.updated` (`ws/members.rs`).
//!
//! Authorization comes before body validation (decision 0014): a body is
//! parsed here but its error is handed to the operation, which answers it
//! only once the caller is authorized, so a caller lacking permission gets
//! `403`/`404` whatever it sends.

use std::collections::HashMap;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{patch, post};
use axum::{Json, Router};
use re_ofscp_types::Actor;
use re_ofscp_types::wire::{JoinRequest, Member, Paged};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer};

use super::joining::Joined;
use super::member_ops::Updated;
use super::paging::PageQuery;
use super::routes::{group_id, local_id};
use super::validate::Invalid;
use crate::AppState;
use crate::problem::Problem;
use crate::profiles::user_ref::resolve_actor;
use crate::signing::Authenticated;

/// Largest request body these routes accept: a role, a nickname or a join
/// message, far below axum's 2 MiB default.
pub const MEMBER_BODY_LIMIT: usize = 16 * 1024;

/// The membership routes, merged into the signed router.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/groups/{group_id}/join", post(join))
        .route(
            "/api/groups/{group_id}/channels/{channel_id}/join",
            post(join_channel),
        )
        .route("/api/groups/{group_id}/leave", post(leave))
        .route(
            "/api/groups/{group_id}/members",
            axum::routing::get(list_members),
        )
        .route(
            "/api/groups/{group_id}/members/{user_ref}",
            patch(change_role).delete(kick),
        )
        .route(
            "/api/groups/{group_id}/members/{user_ref}/display-name",
            patch(set_display_name),
        )
        .route(
            "/api/groups/{group_id}/requests",
            axum::routing::get(list_requests),
        )
        .route(
            "/api/groups/{group_id}/requests/{request_id}/approve",
            post(approve),
        )
        .route(
            "/api/groups/{group_id}/requests/{request_id}/deny",
            post(deny),
        )
        .layer(DefaultBodyLimit::max(MEMBER_BODY_LIMIT))
}

/// A JSON body, or why it is malformed (answered `400` by the operation,
/// after authorization).
fn body<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Invalid> {
    serde_json::from_slice(bytes).map_err(|e| Invalid(format!("invalid request body: {e}")))
}

/// The member `{userRef}` names (§2.2), or `404`.
fn target(state: &AppState, user_ref: &str) -> Result<Actor, Problem> {
    resolve_actor(user_ref, &state.config.domain)
        .ok_or_else(|| Problem::not_found().with_detail("no such member"))
}

/// Tell live readers about each change that `member.updated` carries.
async fn announce(state: &AppState, group_id: &str, updated: &[Updated]) {
    for u in updated.iter().filter(|u| u.changed) {
        state
            .ws
            .member_updated(&state.groups, group_id, &u.member)
            .await;
    }
}

#[derive(Deserialize)]
struct JoinBody {
    #[serde(default)]
    message: Option<String>,
}

/// `POST /api/groups/{groupId}/join` (§5.7): `201` with the `Member`, `202`
/// with the `JoinRequest`, or `200` with the existing `Member`.
async fn join(
    State(state): State<AppState>,
    auth: Authenticated,
    Path(g): Path<String>,
    bytes: Bytes,
) -> Result<Response, Problem> {
    let actor = auth.actor()?;
    group_id(&g)?;
    join_as(&state, actor, &g, &bytes).await
}

/// `POST /api/groups/{groupId}/channels/{channelId}/join` (§8.2): joins
/// the group, answering exactly as [`join`] whatever the channel.
async fn join_channel(
    State(state): State<AppState>,
    auth: Authenticated,
    Path((g, _channel)): Path<(String, String)>,
    bytes: Bytes,
) -> Result<Response, Problem> {
    let actor = auth.actor()?;
    group_id(&g)?;
    join_as(&state, actor, &g, &bytes).await
}

async fn join_as(
    state: &AppState,
    actor: &Actor,
    g: &str,
    bytes: &[u8],
) -> Result<Response, Problem> {
    // The body is optional (§5.7).
    let message = if bytes.iter().all(u8::is_ascii_whitespace) {
        Ok(None)
    } else {
        body::<JoinBody>(bytes).map(|b| b.message)
    };
    let message = message.as_ref().map(Option::as_deref).map_err(Clone::clone);
    Ok(match state.groups.join(actor, g, message).await? {
        Joined::Already(m) => (StatusCode::OK, Json(m)).into_response(),
        Joined::Member(m) => (StatusCode::CREATED, Json(m)).into_response(),
        Joined::Requested(r) => (StatusCode::ACCEPTED, Json(r)).into_response(),
    })
}

/// `POST /api/groups/{groupId}/leave` (§5.7): `204`.
async fn leave(
    State(state): State<AppState>,
    auth: Authenticated,
    Path(g): Path<String>,
) -> Result<StatusCode, Problem> {
    let actor = auth.actor()?;
    group_id(&g)?;
    state.groups.leave(actor, &g).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /api/groups/{groupId}/members` (§5.7, paged per §7.2).
async fn list_members(
    State(state): State<AppState>,
    auth: Authenticated,
    Path(g): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Paged<Member>>, Problem> {
    let actor = auth.actor()?;
    group_id(&g)?;
    let query = PageQuery::from_params(&params);
    Ok(Json(state.groups.list_members(actor, &g, &query).await?))
}

#[derive(Deserialize)]
struct RoleBody {
    role: String,
}

/// `PATCH /api/groups/{groupId}/members/{userRef}` (§5.7): `200` with the
/// updated `Member`.
async fn change_role(
    State(state): State<AppState>,
    auth: Authenticated,
    Path((g, user_ref)): Path<(String, String)>,
    bytes: Bytes,
) -> Result<Json<Member>, Problem> {
    let actor = auth.actor()?;
    group_id(&g)?;
    let req = body::<RoleBody>(&bytes);
    let who = target(&state, &user_ref)?;
    let role = req.as_ref().map(|r| r.role.as_str()).map_err(Clone::clone);
    let updated = state.groups.change_role(actor, &g, &who, role).await?;
    announce(&state, &g, &updated).await;
    let first = updated.into_iter().next().ok_or_else(Problem::internal)?;
    Ok(Json(first.member))
}

/// `DELETE /api/groups/{groupId}/members/{userRef}` (§5.7): `204`.
async fn kick(
    State(state): State<AppState>,
    auth: Authenticated,
    Path((g, user_ref)): Path<(String, String)>,
) -> Result<StatusCode, Problem> {
    let actor = auth.actor()?;
    group_id(&g)?;
    let who = target(&state, &user_ref)?;
    state.groups.kick(actor, &g, &who).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The display-name body: the field is required, `null` allowed.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DisplayNameBody {
    #[serde(default, deserialize_with = "present")]
    display_name_override: Option<Option<String>>,
}

/// A field that is present (`Some`), possibly `null` (`Some(None)`).
fn present<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Option<String>>, D::Error> {
    Option::<String>::deserialize(d).map(Some)
}

/// `PATCH /api/groups/{groupId}/members/{userRef}/display-name` (§5.7):
/// `200` with the updated `Member`.
async fn set_display_name(
    State(state): State<AppState>,
    auth: Authenticated,
    Path((g, user_ref)): Path<(String, String)>,
    bytes: Bytes,
) -> Result<Json<Member>, Problem> {
    let actor = auth.actor()?;
    group_id(&g)?;
    let raw = body::<DisplayNameBody>(&bytes).and_then(|req| {
        req.display_name_override
            .ok_or_else(|| Invalid("`displayNameOverride` is required (it may be null)".to_owned()))
    });
    let who = target(&state, &user_ref)?;
    let raw = raw.as_ref().map(Option::as_deref).map_err(Clone::clone);
    let updated = state.groups.set_display_name(actor, &g, &who, raw).await?;
    announce(&state, &g, std::slice::from_ref(&updated)).await;
    Ok(Json(updated.member))
}

/// `GET /api/groups/{groupId}/requests` (§5.7, paged per §7.2).
async fn list_requests(
    State(state): State<AppState>,
    auth: Authenticated,
    Path(g): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Paged<JoinRequest>>, Problem> {
    let actor = auth.actor()?;
    group_id(&g)?;
    let query = PageQuery::from_params(&params);
    Ok(Json(state.groups.list_requests(actor, &g, &query).await?))
}

/// `POST /api/groups/{groupId}/requests/{requestId}/approve` (§5.7): `200`
/// with the new `Member`.
async fn approve(
    State(state): State<AppState>,
    auth: Authenticated,
    Path((g, r)): Path<(String, String)>,
) -> Result<Json<Member>, Problem> {
    let actor = auth.actor()?;
    group_id(&g)?;
    local_id(&r, "no such join request")?;
    Ok(Json(state.groups.approve_request(actor, &g, &r).await?))
}

/// `POST /api/groups/{groupId}/requests/{requestId}/deny` (§5.7): `204`.
async fn deny(
    State(state): State<AppState>,
    auth: Authenticated,
    Path((g, r)): Path<(String, String)>,
) -> Result<StatusCode, Problem> {
    let actor = auth.actor()?;
    group_id(&g)?;
    local_id(&r, "no such join request")?;
    state.groups.deny_request(actor, &g, &r).await?;
    Ok(StatusCode::NO_CONTENT)
}
