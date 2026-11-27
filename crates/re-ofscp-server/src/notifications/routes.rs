//! HTTP endpoints for the notification feed and its settings (spec §10.1,
//! §10.2).
//!
//! | Route | Auth | Answers |
//! | --- | --- | --- |
//! | `GET /api/me/notifications` | signed, local actor | `200`, `400` |
//! | `POST /api/me/notifications/seen` | signed, local actor | `200`, `400` |
//! | `POST /api/me/notifications/read` | signed, local actor | `200`, `400` |
//! | `GET /api/me/notification-settings` | signed, local actor | `200` |
//! | `PUT /api/me/notification-settings` | signed, local actor | `200`, `400` |
//! | `DELETE /api/me/notification-settings` | signed, local actor | `200`, `400` |
//!
//! Remote signers are refused with `403` before anything else (security
//! requirement 1).

use std::collections::HashMap;

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Query, State};
use ofscp_core::wire::{
    NotificationSetting, NotificationSettingsResponse, NotificationsMarkResponse,
    NotificationsResponse,
};
use serde::Serialize;

use super::NotificationError;
use super::request::{self, Invalid};
use super::store::Mark;
use crate::AppState;
use crate::db::DbError;
use crate::problem::Problem;
use crate::signing::Authenticated;

/// Largest `seen`/`read` body: [`request::MAX_IDS`] ids of up to 128
/// characters, with room for extension fields.
pub const MARK_BODY_LIMIT: usize = 96 * 1024;
/// Largest settings body.
pub const SETTING_BODY_LIMIT: usize = 4 * 1024;

impl From<NotificationError> for Problem {
    fn from(e: NotificationError) -> Self {
        match e {
            NotificationError::TooMany(e) => Problem::bad_request().with_detail(e.to_string()),
            NotificationError::Db(e) => internal(e),
        }
    }
}

fn internal(e: DbError) -> Problem {
    tracing::error!(error = %e, "notification operation failed");
    Problem::internal()
}

fn bad(e: Invalid) -> Problem {
    Problem::bad_request().with_detail(e.0)
}

/// `GET /api/me/notifications`.
pub async fn list(
    State(state): State<AppState>,
    auth: Authenticated,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Json<NotificationsResponse>, Problem> {
    let actor = auth.local_actor(&state.config.domain)?;
    let query = request::list_query(&q).map_err(bad)?;
    Ok(Json(state.notifications.list(actor, &query).await?))
}

async fn mark(
    state: &AppState,
    auth: &Authenticated,
    body: &[u8],
    mark: Mark,
) -> Result<Json<NotificationsMarkResponse>, Problem> {
    let actor = auth.local_actor(&state.config.domain)?;
    let ids = request::mark_body(body).map_err(bad)?;
    let now = state.verifier.now();
    let (affected, counts) = state.notifications.mark(actor, &ids, mark, now).await?;
    Ok(Json(NotificationsMarkResponse { affected, counts }))
}

/// `POST /api/me/notifications/seen`.
pub async fn seen(
    State(state): State<AppState>,
    auth: Authenticated,
    body: Bytes,
) -> Result<Json<NotificationsMarkResponse>, Problem> {
    mark(&state, &auth, &body, Mark::Seen).await
}

/// `POST /api/me/notifications/read`.
pub async fn read(
    State(state): State<AppState>,
    auth: Authenticated,
    body: Bytes,
) -> Result<Json<NotificationsMarkResponse>, Problem> {
    mark(&state, &auth, &body, Mark::Read).await
}

/// `GET /api/me/notification-settings`.
pub async fn settings(
    State(state): State<AppState>,
    auth: Authenticated,
) -> Result<Json<NotificationSettingsResponse>, Problem> {
    let actor = auth.local_actor(&state.config.domain)?;
    let prefs = state
        .notifications
        .settings(actor)
        .await
        .map_err(internal)?;
    Ok(Json(NotificationSettingsResponse { prefs }))
}

/// `PUT /api/me/notification-settings`: the setting as stored.
pub async fn put_setting(
    State(state): State<AppState>,
    auth: Authenticated,
    body: Bytes,
) -> Result<Json<NotificationSetting>, Problem> {
    let actor = auth.local_actor(&state.config.domain)?;
    let (scope, mode) = request::setting_body(&body).map_err(bad)?;
    let now = state.verifier.now();
    state
        .notifications
        .put_setting(actor, &scope, mode, now)
        .await?;
    Ok(Json(scope.setting(mode)))
}

/// `DELETE /api/me/notification-settings` answer.
#[derive(Debug, Serialize)]
pub struct Cleared {
    /// Whether a setting was removed.
    pub cleared: bool,
}

/// `DELETE /api/me/notification-settings?scopeType=&scopeId=`.
pub async fn clear_setting(
    State(state): State<AppState>,
    auth: Authenticated,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Json<Cleared>, Problem> {
    let actor = auth.local_actor(&state.config.domain)?;
    let scope = request::clear_query(&q).map_err(bad)?;
    let cleared = state
        .notifications
        .clear_setting(actor, &scope)
        .await
        .map_err(internal)?;
    Ok(Json(Cleared { cleared }))
}
