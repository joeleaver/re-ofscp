//! re-ofscp — an enterprise-grade OFSCP provider.
//!
//! The binary (`src/main.rs`) only wires configuration, logging and shutdown;
//! everything testable lives here.

pub mod config;
pub mod problem;
pub mod replay;
pub mod signing;

use std::sync::Arc;
use std::time::Duration;

use axum::{Json, Router, extract::State, middleware, routing::get};
use re_ofscp_types::{Health, OFSCP_VERSION};

pub use config::Config;
pub use problem::Problem;

use replay::ReplayStore;
use signing::{Clock, KeyResolver, SystemClock, Verifier};

/// Maximum clock skew accepted on signed requests, in seconds (§4.5 step 3, §8).
pub const MAX_SKEW_SECS: i64 = 300;

/// How long a nonce is remembered (§4.5 step 4: at least the skew window,
/// RECOMMENDED ≥600 s). Twice the skew, so a nonce outlives every moment its
/// timestamp is still acceptable.
pub const REPLAY_RETENTION_SECS: i64 = 2 * MAX_SKEW_SECS;

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    /// Verifies every signed request, REST and federation alike, against the
    /// one provider-wide replay store.
    pub verifier: Arc<Verifier>,
}

impl AppState {
    /// Build state with the wall clock.
    pub fn new(config: Config, keys: Arc<dyn KeyResolver>) -> Self {
        Self::with_clock(config, keys, Arc::new(SystemClock))
    }

    /// Build state with an explicit clock (tests).
    pub fn with_clock(config: Config, keys: Arc<dyn KeyResolver>, clock: Arc<dyn Clock>) -> Self {
        // The store begins now. For one skew window, signed requests get 503
        // because a predecessor process may have recorded them
        // (docs/decisions/0001-replay-store.md, lost-conn/ofscp#17).
        let replay = Arc::new(ReplayStore::new(
            config.replay_capacity,
            REPLAY_RETENTION_SECS,
            clock.now().unix_timestamp(),
            MAX_SKEW_SECS,
        ));
        let verifier = Arc::new(Verifier::new(
            config.domain.clone(),
            MAX_SKEW_SECS,
            replay,
            keys,
            clock,
        ));
        Self {
            config: Arc::new(config),
            verifier,
        }
    }
}

/// Build the HTTP router.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .layer(middleware::from_fn_with_state(
            state.verifier.clone(),
            signing::authenticate,
        ))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
}

/// `GET /api/health` — liveness plus a database reachability probe.
async fn health(State(state): State<AppState>) -> Json<Health> {
    let database = database_reachable(&state.config.rhypedb_addr).await;
    Json(Health {
        status: if database { "ok" } else { "degraded" }.to_owned(),
        ofscp: OFSCP_VERSION.to_owned(),
        domain: state.config.domain.to_string(),
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
