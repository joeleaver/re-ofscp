//! HTTP endpoints for group invites (spec §5.6; docs/decisions/0019).
//!
//! | Route | Who |
//! | --- | --- |
//! | `POST /api/groups/{g}/invites` | `manage` + subset rule on the role |
//! | `GET /api/groups/{g}/invites` | `manage` |
//! | `DELETE /api/groups/{g}/invites/{i}` | `manage` |
//! | `POST /api/invites/{token}/redeem` | anyone signed, local or remote |
//! | `POST /api/invites/{token}/guest` | nobody: guests are unsupported (`403`) |
//!
//! Every route but `/guest` needs a user signature: unsigned is `401`, a
//! provider signature `403`. A token is never logged: it is a path
//! segment here, and request tracing records the route template only.

use std::collections::HashMap;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use re_ofscp_types::wire::{Invite, InviteCreateRequest, InviteRedeemResponse, Paged};

use super::routes::{group_id, local_id};
use crate::AppState;
use crate::problem::Problem;
use crate::signing::Authenticated;

/// Largest request body these routes accept: an invite's terms.
pub const INVITE_BODY_LIMIT: usize = 16 * 1024;

const GUESTS_UNSUPPORTED: &str = "this provider does not offer guest accounts (§4.8); redeem the invite with an existing account";

/// The invite routes, merged into the signed router.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/groups/{group_id}/invites",
            get(list_invites).post(create_invite),
        )
        .route(
            "/api/groups/{group_id}/invites/{invite_id}",
            delete(revoke_invite),
        )
        .route("/api/invites/{token}/redeem", post(redeem))
        .route("/api/invites/{token}/guest", post(guest))
        .layer(DefaultBodyLimit::max(INVITE_BODY_LIMIT))
}

/// `POST /api/groups/{groupId}/invites` (§5.6): `201` with the `Invite`,
/// carrying its token (`invite-create-response.json`). Every field of the body, and the body itself, is
/// optional.
async fn create_invite(
    State(state): State<AppState>,
    auth: Authenticated,
    Path(g): Path<String>,
    bytes: Bytes,
) -> Result<Response, Problem> {
    let actor = auth.actor()?;
    group_id(&g)?;
    let req: InviteCreateRequest = if bytes.iter().all(u8::is_ascii_whitespace) {
        InviteCreateRequest::default()
    } else {
        serde_json::from_slice(&bytes)
            .map_err(|e| Problem::bad_request().with_detail(format!("invalid request body: {e}")))?
    };
    let invite = state.groups.create_invite(actor, &g, &req).await?;
    Ok((StatusCode::CREATED, Json(invite)).into_response())
}

/// `GET /api/groups/{groupId}/invites` (§5.6, paged per §7.2): the
/// invites without their tokens (lost-conn/ofscp#40).
async fn list_invites(
    State(state): State<AppState>,
    auth: Authenticated,
    Path(g): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Paged<Invite>>, Problem> {
    let actor = auth.actor()?;
    group_id(&g)?;
    let query = super::paging::PageQuery::from_params(&params);
    Ok(Json(state.groups.list_invites(actor, &g, &query).await?))
}

/// `DELETE /api/groups/{groupId}/invites/{inviteId}` (§5.6): `204`.
async fn revoke_invite(
    State(state): State<AppState>,
    auth: Authenticated,
    Path((g, i)): Path<(String, String)>,
) -> Result<StatusCode, Problem> {
    let actor = auth.actor()?;
    group_id(&g)?;
    local_id(&i, "no such invite")?;
    state.groups.revoke_invite(actor, &g, &i).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /api/invites/{token}/redeem` (§5.6): `200` with the group, the
/// invite's channel and the caller's role.
async fn redeem(
    State(state): State<AppState>,
    auth: Authenticated,
    Path(token): Path<String>,
) -> Result<Json<InviteRedeemResponse>, Problem> {
    let actor = auth.actor()?;
    let redeemed = state.groups.redeem_invite(actor, &token).await?;
    Ok(Json(redeemed.response))
}

/// `POST /api/invites/{token}/guest` (§5.6, §4.8): always `403`. Guests
/// are optional and this provider offers none, so no invite grants one
/// (`grantsGuest: true` is refused at creation).
async fn guest() -> Problem {
    Problem::forbidden().with_detail(GUESTS_UNSUPPORTED)
}
