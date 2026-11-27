//! HTTP endpoints for read markers (spec §7.7).
//!
//! | Route | Auth | Answers |
//! | --- | --- | --- |
//! | `GET /api/me/read-markers` | signed, local actor | `200` |
//! | `PATCH /api/me/read-markers` | signed, local actor | `200`, `400` |
//!
//! Remote signers are refused with `403` before anything else (security
//! requirement 1). A marker for a scope the caller cannot use is ignored,
//! never answered `403` or `404` (§7.7).

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;

use ofscp_core::wire::ReadMarkersResponse;

use super::{MarkerError, request};
use crate::AppState;
use crate::problem::Problem;
use crate::signing::Authenticated;

/// Largest `PATCH` body: [`request::MAX_MARKERS_PER_REQUEST`] markers of
/// two ids each, with room for extension fields.
pub const BODY_LIMIT: usize = 32 * 1024;

impl From<MarkerError> for Problem {
    fn from(e: MarkerError) -> Self {
        tracing::error!(error = %e, "read marker operation failed");
        Problem::internal()
    }
}

/// `GET /api/me/read-markers`.
pub async fn list(
    State(state): State<AppState>,
    auth: Authenticated,
) -> Result<Json<ReadMarkersResponse>, Problem> {
    let actor = auth.local_actor(&state.config.domain)?;
    let scopes = state.read_markers.scopes(actor).await?;
    Ok(Json(ReadMarkersResponse { scopes }))
}

/// `PATCH /api/me/read-markers`.
pub async fn update(
    State(state): State<AppState>,
    auth: Authenticated,
    body: Bytes,
) -> Result<Json<ReadMarkersResponse>, Problem> {
    let actor = auth.local_actor(&state.config.domain)?;
    let updates =
        request::update_body(&body).map_err(|e| Problem::bad_request().with_detail(e.0))?;
    let now = state.verifier.now();
    let scopes = state.read_markers.update(actor, &updates, now).await?;
    Ok(Json(ReadMarkersResponse { scopes }))
}
