//! re-ofscp — an enterprise-grade OFSCP provider.
//!
//! The binary (`src/main.rs`) only wires configuration, logging and shutdown;
//! everything testable lives here.

pub mod config;
pub mod db;
pub mod problem;
pub mod replay;
pub mod signing;

use std::sync::Arc;
use std::time::Duration;

use axum::{Json, Router, extract::State, middleware, routing::get};
use problem::ProblemBase;
use re_ofscp_types::{Health, OFSCP_VERSION};

pub use config::Config;
pub use problem::Problem;

use db::{Db, DbConfig};
use replay::ReplayStore;
use replay::ledger::{LedgerError, NonceLedger, RhypeLedger};
use signing::{Clock, KeyResolver, StaticKeys, SystemClock, Verifier};

/// Maximum clock skew accepted on signed requests, in seconds (§4.5 step 3, §8).
pub const MAX_SKEW_SECS: i64 = 300;

/// How often expired nonces are deleted from the persistent ledger.
pub const LEDGER_PURGE_INTERVAL: Duration = Duration::from_secs(60);

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    /// The rhypedb connection pool.
    pub db: Arc<Db>,
    /// Verifies every signed request, REST and federation alike, against the
    /// one provider-wide replay store.
    pub verifier: Arc<Verifier>,
}

/// Builds an [`AppState`]. Defaults: the wall clock, no keys, and the
/// rhypedb-backed replay ledger.
pub struct AppStateBuilder {
    config: Config,
    keys: Arc<dyn KeyResolver>,
    ledger: Option<Arc<dyn NonceLedger>>,
    clock: Arc<dyn Clock>,
}

impl AppStateBuilder {
    /// Resolve signing keys with `keys`.
    #[must_use]
    pub fn keys(mut self, keys: Arc<dyn KeyResolver>) -> Self {
        self.keys = keys;
        self
    }

    /// Persist nonces to `ledger` instead of rhypedb.
    #[must_use]
    pub fn ledger(mut self, ledger: Arc<dyn NonceLedger>) -> Self {
        self.ledger = Some(ledger);
        self
    }

    /// Use `clock` instead of the wall clock.
    #[must_use]
    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Build the state. The replay store starts in its restart warm-up;
    /// [`AppState::restore_replay`] ends it once the ledger is reloaded.
    pub fn build(self) -> AppState {
        let config = self.config;
        let db = Arc::new(Db::new(DbConfig::new(config.rhypedb_addr.clone())));
        let ledger = self
            .ledger
            .unwrap_or_else(|| Arc::new(RhypeLedger::new(db.clone())));
        let replay = Arc::new(ReplayStore::new(
            config.replay,
            MAX_SKEW_SECS,
            self.clock.now().unix_timestamp(),
            config.domain.as_str(),
        ));
        let verifier = Arc::new(Verifier::new(
            config.domain.clone(),
            MAX_SKEW_SECS,
            replay,
            ledger,
            self.keys,
            self.clock,
        ));
        AppState {
            config: Arc::new(config),
            db,
            verifier,
        }
    }
}

impl AppState {
    /// Start building state for `config`.
    pub fn builder(config: Config) -> AppStateBuilder {
        AppStateBuilder {
            config,
            keys: Arc::new(StaticKeys::default()),
            ledger: None,
            clock: Arc::new(SystemClock),
        }
    }

    /// Reload every live nonce from the persistent ledger into the replay
    /// store and end its restart warm-up. Call before serving. On error the
    /// warm-up stays in force (signed requests get `503` for one skew window
    /// after startup), which is safe.
    pub async fn restore_replay(&self) -> Result<usize, LedgerError> {
        let now = self.verifier.now();
        let restored = self.verifier.ledger().load(now).await?;
        let store = self.verifier.replay_store();
        // First the previous process's clock: anything it purged as expired
        // must stay expired here, whatever our wall clock reads.
        if let Some(clock) = restored.clock {
            store.raise_clock(clock);
        }
        let count = store.restore(restored.nonces, now);
        store.end_warm_up();
        Ok(count)
    }

    /// Delete expired nonces from the ledger, every
    /// [`LEDGER_PURGE_INTERVAL`], until the task is dropped.
    pub async fn purge_ledger_forever(self) {
        let mut tick = tokio::time::interval(LEDGER_PURGE_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            // Purge by the store's clock (never decreasing), which the ledger
            // persists before deleting anything.
            let clock = self.verifier.replay_store().clock(self.verifier.now());
            if let Err(e) = self.verifier.ledger().purge(clock).await {
                tracing::warn!(error = %e, "purging expired nonces failed");
            }
        }
    }
}

/// Build the HTTP router.
///
/// Layer order, outermost first: tracing, problem rendering (so every
/// [`Problem`], including the signature layer's and extractors' rejections,
/// gets its body), signature verification, routes.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .route("/problems/{code}", get(problem::describe))
        .fallback(|| async { Problem::not_found() })
        .method_not_allowed_fallback(|| async { Problem::method_not_allowed() })
        .layer(middleware::from_fn_with_state(
            state.verifier.clone(),
            signing::authenticate,
        ))
        .layer(middleware::map_response_with_state(
            ProblemBase::new(&state.config.domain),
            problem::render,
        ))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
}

/// `GET /api/health` — liveness plus a database reachability probe.
async fn health(State(state): State<AppState>) -> Json<Health> {
    let database = tokio::time::timeout(Duration::from_secs(2), state.db.ping())
        .await
        .unwrap_or(false);
    Json(Health {
        status: if database { "ok" } else { "degraded" }.to_owned(),
        ofscp: OFSCP_VERSION.to_owned(),
        domain: state.config.domain.to_string(),
        database,
    })
}
