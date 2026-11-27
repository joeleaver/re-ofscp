//! HTTP endpoints for read markers (spec §7.7).
//!
//! | Route | Auth | Answers |
//! | --- | --- | --- |
//! | `GET /api/me/read-markers` | signed, local actor | `200`, `503` |
//! | `PATCH /api/me/read-markers` | signed, local actor | `200`, `400`, `503` |
//!
//! `503` (with `Retry-After`) is transient: a write conflict that outlasted
//! its retries, the database unreachable, or a channel from before message
//! ordinals still being numbered (`messages/numbering.rs`).
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
use crate::db::DbError;
use crate::messages::numbering;
use crate::problem::Problem;
use crate::signing::Authenticated;

/// Largest `PATCH` body: [`request::MAX_MARKERS_PER_REQUEST`] markers of
/// two ids each, with room for extension fields.
pub const BODY_LIMIT: usize = 32 * 1024;

impl From<MarkerError> for Problem {
    fn from(e: MarkerError) -> Self {
        match e {
            // Transient, as for messages (`messages/routes.rs`): retry.
            MarkerError::Db(DbError::Unavailable(_) | DbError::Contended(_)) => {
                tracing::warn!(error = %e, "read marker operation: retryable");
                Problem::service_unavailable(1)
            }
            MarkerError::Numbering(c) => {
                tracing::info!(channel = %c, "read marker operation: channel being numbered");
                Problem::service_unavailable(numbering::RETRY_AFTER_SECS)
            }
            e => {
                tracing::error!(error = %e, "read marker operation failed");
                Problem::internal()
            }
        }
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

#[cfg(test)]
mod tests {
    use axum::http::{StatusCode, header};
    use axum::response::IntoResponse;

    use super::*;

    fn answer(e: MarkerError) -> (StatusCode, Option<String>) {
        let r = Problem::from(e).into_response();
        let retry = r
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        (r.status(), retry)
    }

    #[test]
    fn transient_failures_are_503_with_retry_after_and_others_500() {
        let busy = StatusCode::SERVICE_UNAVAILABLE;
        for e in [
            DbError::Unavailable("down".into()),
            DbError::Contended("busy".into()),
        ] {
            assert_eq!(answer(MarkerError::Db(e)), (busy, Some("1".into())));
        }
        assert_eq!(
            answer(MarkerError::Numbering("chn_1".into())),
            (busy, Some(numbering::RETRY_AFTER_SECS.to_string()))
        );
        assert_eq!(
            answer(MarkerError::Db(DbError::Decode("bad".into()))),
            (StatusCode::INTERNAL_SERVER_ERROR, None)
        );
    }
}
