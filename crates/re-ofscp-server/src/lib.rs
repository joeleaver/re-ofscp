//! re-ofscp — an enterprise-grade OFSCP provider.
//!
//! The binary (`src/main.rs`) only wires configuration, logging and shutdown;
//! everything testable lives here.

pub mod accounts;
pub mod admin;
pub mod client;
pub mod config;
pub mod db;
pub mod outbound;
pub mod problem;
pub mod ratelimit;
pub mod remote_keys;
pub mod replay;
pub mod signing;
pub mod timefmt;

use std::sync::Arc;
use std::time::Duration;

use axum::routing::{delete, get, post};
use axum::{Json, Router, extract::State, middleware};
use problem::ProblemBase;
use re_ofscp_types::{Health, OFSCP_VERSION};

pub use config::Config;
pub use problem::Problem;

use accounts::Accounts;
use admin::{AdminSecrets, Admins, ConsoleOrigins};
use db::{Db, DbConfig};
use outbound::{OutboundClient, OutboundConfig};
use remote_keys::RemoteKeys;
use replay::ReplayStore;
use replay::ledger::{LedgerError, NonceLedger, RhypeLedger};
use signing::{Clock, KeyResolver, SystemClock, Verifier};

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
    /// Accounts, passwords, bootstrap tokens and device keys.
    pub accounts: Arc<Accounts>,
    /// Admin identity, sessions and the audit log.
    pub admins: Arc<Admins>,
    /// Verifies every signed request, REST and federation alike, against the
    /// one provider-wide replay store.
    pub verifier: Arc<Verifier>,
}

/// Builds an [`AppState`]. Defaults: the wall clock, local keys from the
/// account store, remote keys fetched through the SSRF-safe outbound client
/// configured from `OUTBOUND_ALLOW_HOSTS`, and the rhypedb-backed replay
/// ledger.
pub struct AppStateBuilder {
    config: Config,
    keys: Option<Arc<dyn KeyResolver>>,
    remote_keys: Option<Arc<dyn KeyResolver>>,
    outbound: Option<Arc<OutboundClient>>,
    ledger: Option<Arc<dyn NonceLedger>>,
    clock: Arc<dyn Clock>,
}

impl AppStateBuilder {
    /// Resolve *every* signing key with `keys`, bypassing the account
    /// store (tests).
    #[must_use]
    pub fn keys(mut self, keys: Arc<dyn KeyResolver>) -> Self {
        self.keys = Some(keys);
        self
    }

    /// Resolve remote signers with `remote` (local accounts still come from
    /// the account store).
    #[must_use]
    pub fn remote_keys(mut self, remote: Arc<dyn KeyResolver>) -> Self {
        self.remote_keys = Some(remote);
        self
    }

    /// Make outbound requests (remote key fetches) through `client`
    /// instead of one built from the configuration (tests trusting a local
    /// certificate authority).
    #[must_use]
    pub fn outbound(mut self, client: Arc<OutboundClient>) -> Self {
        self.outbound = Some(client);
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
    /// Fails only if the outbound HTTP client cannot be set up.
    pub fn build(self) -> Result<AppState, outbound::BuildError> {
        let config = self.config;
        let outbound = match self.outbound {
            Some(client) => client,
            None => Arc::new(OutboundClient::new(&OutboundConfig::new(
                config.outbound_allow_hosts.clone(),
            ))?),
        };
        let remote_keys = self
            .remote_keys
            .unwrap_or_else(|| Arc::new(RemoteKeys::new(outbound, self.clock.clone())));
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
        let accounts = Arc::new(Accounts::new(
            config.domain.clone(),
            config.registration,
            db.clone(),
            remote_keys,
        ));
        let admins = Arc::new(Admins::new(
            config.domain.clone(),
            ConsoleOrigins::new(&config.domain, config.admin_loopback_http),
            db.clone(),
            accounts.passwords.clone(),
            AdminSecrets {
                secret_key: config.admin_secret_key.as_ref().map(|k| k.0),
                setup_token: config.admin_setup_token.as_ref().map(|t| t.0.clone()),
            },
        ));
        let keys: Arc<dyn KeyResolver> = self.keys.unwrap_or_else(|| accounts.keys.clone());
        let verifier = Arc::new(Verifier::new(
            config.domain.clone(),
            MAX_SKEW_SECS,
            replay,
            ledger,
            keys,
            self.clock,
        ));
        Ok(AppState {
            config: Arc::new(config),
            db,
            accounts,
            admins,
            verifier,
        })
    }
}

impl AppState {
    /// Start building state for `config`.
    pub fn builder(config: Config) -> AppStateBuilder {
        AppStateBuilder {
            config,
            keys: None,
            remote_keys: None,
            outbound: None,
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
/// gets its body), signature verification (OFSCP routes only), routes.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .route(
            "/api/auth/register",
            post(accounts::routes::register).layer(auth_body_limit()),
        )
        .route(
            "/api/auth/login",
            post(accounts::routes::login).layer(auth_body_limit()),
        )
        .route(
            "/api/auth/device-keys",
            post(accounts::routes::register_device_key)
                .layer(auth_body_limit())
                .get(accounts::routes::list_device_keys),
        )
        .route(
            "/api/auth/device-keys/{key_id}",
            delete(accounts::routes::revoke_device_key),
        )
        .route(
            "/.well-known/ofscp/users/{handle}/keys",
            get(accounts::routes::user_keys),
        )
        .route("/problems/{code}", get(problem::describe))
        .fallback(|| async { Problem::not_found() })
        .method_not_allowed_fallback(|| async { Problem::method_not_allowed() })
        .layer(middleware::from_fn_with_state(
            state.verifier.clone(),
            signing::authenticate,
        ))
        // Added after the signature layer, so it does not wrap them: admin
        // requests are authenticated by the admin session, never by OFSCP
        // signatures (docs/decisions/0005).
        .merge(admin::routes::router())
        .layer(middleware::map_response_with_state(
            ProblemBase::new(&state.config.domain),
            problem::render,
        ))
        .layer(
            tower_http::trace::TraceLayer::new_for_http().make_span_with(
                // The path only: query strings can carry secrets (invite
                // tokens in `?invite=`, §4.1.1 "SHOULD NOT log invite
                // tokens").
                |req: &axum::http::Request<axum::body::Body>| {
                    tracing::info_span!(
                        "request",
                        method = %req.method(),
                        path = %req.uri().path(),
                    )
                },
            ),
        )
        .with_state(state)
}

/// Body limit for the unauthenticated auth endpoints, whose bodies are a
/// handle, a password (at most 1 KiB) and similar: far below axum's 2 MiB
/// default, so nobody can make the provider buffer and parse megabytes
/// before any check.
fn auth_body_limit() -> axum::extract::DefaultBodyLimit {
    axum::extract::DefaultBodyLimit::max(accounts::routes::AUTH_BODY_LIMIT)
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
