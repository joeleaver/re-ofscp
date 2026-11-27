//! HTTP endpoints for follows (spec §7.6).
//!
//! | Route | Auth | Answers |
//! | --- | --- | --- |
//! | `GET /api/me/follows` | signed, local actor | `200` |
//! | `POST /api/me/follows` | signed, local actor | `201`, `200` (already followed), `400`, `403`, `404`, `409`, `503` |
//! | `DELETE /api/me/follows/{channelRef}` | signed, local actor | `204`, `400` |
//!
//! Remote signers are refused with `403` before anything else (security
//! requirement 1), then the request is read (`400`, recording nothing).

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use ofscp_core::wire::{Follow, FollowsResponse};

use super::{FollowError, request};
use crate::AppState;
use crate::problem::Problem;
use crate::signing::Authenticated;

/// Largest `POST` body: a channel URI, a group reference and room for
/// extension fields.
pub const BODY_LIMIT: usize = 4 * 1024;
/// `Retry-After` while the federation policy is not loaded.
const POLICY_RETRY_SECS: u64 = 5;

impl From<FollowError> for Problem {
    fn from(e: FollowError) -> Self {
        let detail = e.to_string();
        let p = match e {
            FollowError::Denied(_) => Problem::forbidden(),
            FollowError::PolicyUnknown => Problem::service_unavailable(POLICY_RETRY_SECS),
            FollowError::NotFound => Problem::not_found(),
            FollowError::Limit | FollowError::Contended => Problem::conflict(),
            FollowError::TooMany(_) | FollowError::Db(_) => {
                tracing::error!(error = %detail, "follow operation failed");
                return Problem::internal();
            }
        };
        p.with_detail(detail)
    }
}

fn bad_request(e: request::Invalid) -> Problem {
    Problem::bad_request().with_detail(e.0)
}

/// `GET /api/me/follows`.
pub async fn list(
    State(state): State<AppState>,
    auth: Authenticated,
) -> Result<Json<FollowsResponse>, Problem> {
    let actor = auth.local_actor(&state.config.domain)?;
    let follows = state.follows.list(actor).await?;
    Ok(Json(FollowsResponse {
        follows,
        metadata: Vec::new(),
    }))
}

/// `POST /api/me/follows`.
pub async fn create(
    State(state): State<AppState>,
    auth: Authenticated,
    body: Bytes,
) -> Result<(StatusCode, Json<Follow>), Problem> {
    let actor = auth.local_actor(&state.config.domain)?;
    let raw = request::create_body(&body).map_err(bad_request)?;
    let channel = request::channel_ref(&raw, &state.config.domain).map_err(bad_request)?;
    let now = state.verifier.now();
    let (follow, created) = state.follows.follow(actor, &channel, now).await?;
    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(follow)))
}

/// `DELETE /api/me/follows/{channelRef}`. The router decodes the segment
/// exactly once, so a URI arrives percent-encoded as one segment.
pub async fn delete(
    State(state): State<AppState>,
    auth: Authenticated,
    Path(channel_ref): Path<String>,
) -> Result<StatusCode, Problem> {
    let actor = auth.local_actor(&state.config.domain)?;
    let channel = request::channel_ref(&channel_ref, &state.config.domain).map_err(bad_request)?;
    state.follows.unfollow(actor, &channel).await?;
    Ok(StatusCode::NO_CONTENT)
}
