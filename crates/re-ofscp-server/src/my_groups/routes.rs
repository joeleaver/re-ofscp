//! HTTP endpoints for the user's group list (spec §5.7, *My groups*).
//!
//! | Route | Auth | Answers |
//! | --- | --- | --- |
//! | `GET /api/me/groups` | signed, local actor | `200` |
//! | `PUT /api/me/groups/{groupRef}` | signed, local actor | `200`, `400`, `403`, `404`, `409`, `503` |
//! | `DELETE /api/me/groups/{groupRef}` | signed, local actor | `204`, `400`, `409` |
//!
//! Remote signers are refused with `403` before anything else (security
//! requirement 1), then the request is read (`400`, recording nothing),
//! then the federation policy is applied to the group's provider (`403`).

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use re_ofscp_types::wire::{GroupPointer, GroupPointersResponse};

use super::{MyGroupsError, request};
use crate::AppState;
use crate::problem::Problem;
use crate::signing::Authenticated;

/// Largest `PUT` body: a role hint and room for extension fields.
pub const BODY_LIMIT: usize = 4 * 1024;
/// `Retry-After` while the federation policy is not loaded.
const POLICY_RETRY_SECS: u64 = 5;

impl From<MyGroupsError> for Problem {
    fn from(e: MyGroupsError) -> Self {
        let detail = e.to_string();
        let p = match e {
            MyGroupsError::Denied(_) => Problem::forbidden(),
            MyGroupsError::PolicyUnknown => Problem::service_unavailable(POLICY_RETRY_SECS),
            MyGroupsError::NotMember => Problem::not_found(),
            MyGroupsError::Hosted(_) | MyGroupsError::Limit | MyGroupsError::Contended => {
                Problem::conflict()
            }
            MyGroupsError::Listing(_) | MyGroupsError::Db(_) => {
                tracing::error!(error = %detail, "group list operation failed");
                return Problem::internal();
            }
        };
        p.with_detail(detail)
    }
}

fn bad_request(e: request::Invalid) -> Problem {
    Problem::bad_request().with_detail(e.0)
}

/// `GET /api/me/groups`.
pub async fn list(
    State(state): State<AppState>,
    auth: Authenticated,
) -> Result<Json<GroupPointersResponse>, Problem> {
    let actor = auth.local_actor(&state.config.domain)?;
    let groups = state.my_groups.list(actor).await?;
    Ok(Json(GroupPointersResponse {
        groups,
        metadata: Vec::new(),
    }))
}

/// `PUT /api/me/groups/{groupRef}`.
pub async fn put(
    State(state): State<AppState>,
    auth: Authenticated,
    Path(group_ref): Path<String>,
    body: Bytes,
) -> Result<Json<GroupPointer>, Problem> {
    let actor = auth.local_actor(&state.config.domain)?;
    let group = request::group_ref(&group_ref).map_err(bad_request)?;
    let role = request::role_hint(&body).map_err(bad_request)?;
    let now = state.verifier.now();
    let entry = state
        .my_groups
        .put(actor, &group, role.as_deref(), now)
        .await?;
    Ok(Json(entry))
}

/// `DELETE /api/me/groups/{groupRef}`.
pub async fn delete(
    State(state): State<AppState>,
    auth: Authenticated,
    Path(group_ref): Path<String>,
) -> Result<StatusCode, Problem> {
    let actor = auth.local_actor(&state.config.domain)?;
    let group = request::group_ref(&group_ref).map_err(bad_request)?;
    state.my_groups.delete(actor, &group).await?;
    Ok(StatusCode::NO_CONTENT)
}
