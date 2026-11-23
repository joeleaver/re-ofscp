//! re-ofscp — an enterprise-grade OFSCP provider.
//!
//! The binary (`src/main.rs`) only wires configuration, logging and shutdown;
//! everything testable lives here.

pub mod config;

use std::sync::Arc;
use std::time::Duration;

use axum::{Json, Router, extract::State, routing::get};
use re_ofscp_types::{Health, OFSCP_VERSION};

pub use config::Config;

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
}

/// Build the HTTP router.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
}

/// `GET /api/health` — liveness plus a database reachability probe.
async fn health(State(state): State<AppState>) -> Json<Health> {
    let database = database_reachable(&state.config.rhypedb_addr).await;
    Json(Health {
        status: if database { "ok" } else { "degraded" }.to_owned(),
        ofscp: OFSCP_VERSION.to_owned(),
        domain: state.config.domain.clone(),
        database,
    })
}

/// Whether rhypedb accepts a connection within a short timeout.
async fn database_reachable(addr: &str) -> bool {
    matches!(
        tokio::time::timeout(
            Duration::from_secs(2),
            rhypedb_client::AsyncClient::connect(addr)
        )
        .await,
        Ok(Ok(_))
    )
}
