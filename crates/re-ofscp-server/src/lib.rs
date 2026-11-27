//! re-ofscp — an enterprise-grade OFSCP provider.
//!
//! The binary (`src/main.rs`) only wires configuration, logging and shutdown;
//! everything testable lives here.

pub mod accounts;
pub mod admin;
pub mod client;
pub mod config;
pub mod cors;
pub mod db;
pub mod discovery;
pub mod federation;
pub mod groups;
pub mod messages;
pub mod outbound;
pub mod privacy;
pub mod problem;
pub mod profiles;
pub mod provider_key;
pub mod ratelimit;
pub mod registrable;
pub mod remote_keys;
pub mod replay;
pub mod signing;
pub mod timefmt;
pub mod ws;

use std::sync::Arc;
use std::time::Duration;

use axum::routing::{delete, get, patch, post, put};
use axum::{Json, Router, extract::State, middleware};
use problem::ProblemBase;
use re_ofscp_types::{Health, OFSCP_VERSION};

pub use config::Config;
pub use problem::Problem;

use accounts::Accounts;
use admin::{AdminSecrets, Admins, ConsoleOrigins};
use db::{Db, DbConfig, DbError};
use federation::FederationPolicy;
use federation::store::PolicyStore;
use groups::Groups;
use messages::uploads::{NoUploads, Uploads};
use messages::{MessageTimeline, Messages};
use outbound::{OutboundClient, OutboundConfig};
use privacy::{Contacts, GroupMemberships, Liveness, Relationships};
use profiles::Profiles;
use remote_keys::RemoteKeys;
use replay::ReplayStore;
use replay::ledger::{LedgerError, NonceLedger, RhypeLedger};
use signing::{Clock, KeyResolver, SystemClock, Verifier};
use ws::live::HubFanout;
use ws::{GroupTopics, Hub, Seams, WsConfig};

/// Maximum clock skew accepted on signed requests, in seconds (§4.5 step 3, §8).
pub const MAX_SKEW_SECS: i64 = 300;

/// How often expired nonces are deleted from the persistent ledger.
pub const LEDGER_PURGE_INTERVAL: Duration = Duration::from_secs(60);

/// The first wait between attempts of [`AppState::restore_replay_until_loaded`];
/// it doubles up to [`RESTORE_RETRY_MAX`]. Short, because on jkbase the
/// managed rhypedb starts beside the app and usually listens within a second.
pub const RESTORE_RETRY_MIN: Duration = Duration::from_millis(100);

/// The longest wait between restore attempts.
pub const RESTORE_RETRY_MAX: Duration = Duration::from_secs(2);

/// How often a restore that keeps failing is reported at `WARN` (the
/// attempts in between log at `DEBUG`).
const RESTORE_WARN_EVERY: Duration = Duration::from_secs(30);

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
    /// Groups, channels and membership (§5.2, §5.5).
    pub groups: Arc<Groups>,
    /// Channel messages.
    pub messages: Arc<Messages>,
    /// Verifies every signed request, REST and federation alike, against the
    /// one provider-wide replay store.
    pub verifier: Arc<Verifier>,
    /// The discovery document (§3.1), serialized once.
    pub discovery: Arc<discovery::Published>,
    /// The federation allow/deny policy (§8 *Authorization*): stored, and
    /// in force in the verifier, the remote key resolver and the outbound
    /// client.
    pub federation: Arc<PolicyStore>,
    /// Profiles, presence and privacy settings (§5.1, §6).
    pub profiles: Arc<Profiles>,
    /// The WebSocket layer (§7.1): live connections, fan-out, force-close.
    pub ws: Arc<Hub>,
}

/// Why [`AppStateBuilder::build`] failed.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("setting up the outbound client: {0}")]
    Outbound(#[from] outbound::BuildError),
    #[error("preparing the discovery document: {0}")]
    Discovery(#[from] discovery::PublishError),
    /// The state starts background work (the WebSocket hub's group
    /// follower), so it must be built inside a Tokio runtime.
    #[error("the state must be built inside a Tokio runtime")]
    NoRuntime,
}

/// Builds an [`AppState`]. Defaults: the wall clock, local keys from the
/// account store, remote keys fetched through the SSRF-safe outbound client
/// configured from `OUTBOUND_ALLOW_HOSTS`, and the rhypedb-backed replay
/// ledger.
///
/// The federation policy in force is the outbound client's: one built here
/// starts with the policy unknown (federation refused) until
/// [`AppState::load_federation`] reads it.
pub struct AppStateBuilder {
    config: Config,
    keys: Option<Arc<dyn KeyResolver>>,
    remote_keys: Option<Arc<dyn KeyResolver>>,
    outbound: Option<Arc<OutboundClient>>,
    ledger: Option<Arc<dyn NonceLedger>>,
    clock: Arc<dyn Clock>,
    relationships: Relationships,
    group_memberships: Option<Arc<dyn GroupMemberships>>,
    liveness: Option<Arc<dyn Liveness>>,
    ws_config: WsConfig,
    ws_seams: Option<Seams>,
    uploads: Option<Arc<dyn Uploads>>,
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
    /// certificate authority). Its federation policy becomes the state's.
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

    /// Answer the `sharedGroups` tier and membership listings (§6.1, §6.5)
    /// from `groups` instead of this provider's own groups (tests).
    #[must_use]
    pub fn group_memberships(mut self, groups: Arc<dyn GroupMemberships>) -> Self {
        self.group_memberships = Some(groups);
        self
    }

    /// Answer the `contacts` tier (§6.1) from `contacts` instead of
    /// [`privacy::NoContacts`].
    #[must_use]
    pub fn contacts(mut self, contacts: Arc<dyn Contacts>) -> Self {
        self.relationships.contacts = contacts;
        self
    }

    /// Derive online/offline (§7.5) from `liveness` instead of this
    /// provider's own WebSocket connections.
    #[must_use]
    pub fn liveness(mut self, liveness: Arc<dyn Liveness>) -> Self {
        self.liveness = Some(liveness);
        self
    }

    /// Use `clock` instead of the wall clock.
    #[must_use]
    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Run the WebSocket layer with `config` instead of the defaults.
    #[must_use]
    pub fn ws_config(mut self, config: WsConfig) -> Self {
        self.ws_config = config;
        self
    }

    /// Plug channel access, timelines and messages into the WebSocket
    /// layer instead of the provider's own (channel access from its
    /// groups, the message log) (tests).
    #[must_use]
    pub fn ws_seams(mut self, seams: Seams) -> Self {
        self.ws_seams = Some(seams);
        self
    }

    /// Check message attachments' local media ids against `uploads`
    /// instead of knowing none (§5.8).
    #[must_use]
    pub fn uploads(mut self, uploads: Arc<dyn Uploads>) -> Self {
        self.uploads = Some(uploads);
        self
    }

    /// Build the state. The replay store starts in its restart warm-up;
    /// [`AppState::restore_replay`] ends it once the ledger is reloaded.
    /// Fails if the outbound HTTP client cannot be set up, the discovery
    /// document cannot be serialized, or it is called outside a Tokio
    /// runtime.
    ///
    /// It starts, on the current runtime, the task that turns group access
    /// changes into WebSocket re-checks (`ws::follow_groups`), so every
    /// state revokes live subscriptions at once; the task ends when the
    /// state is dropped.
    pub fn build(self) -> Result<AppState, BuildError> {
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| BuildError::NoRuntime)?;
        let config = self.config;
        let discovery = Arc::new(discovery::Published::new(&config)?);
        let outbound = match self.outbound {
            Some(client) => client,
            None => Arc::new(OutboundClient::new(&OutboundConfig::new(
                config.outbound_allow_hosts.clone(),
                Arc::new(FederationPolicy::unloaded_for(config.domain.clone())),
            ))?),
        };
        let policy = outbound.policy().clone();
        let remote_keys = self
            .remote_keys
            .unwrap_or_else(|| Arc::new(RemoteKeys::new(outbound, self.clock.clone())));
        let db = Arc::new(Db::new(DbConfig::new(config.rhypedb_addr.clone())));
        let federation = Arc::new(PolicyStore::new(
            db.clone(),
            policy.clone(),
            config.domain.clone(),
        ));
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
            config.provider_key.published(),
            config.registration.clone(),
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
        let groups = Arc::new(Groups::new(
            config.domain.clone(),
            db.clone(),
            self.clock.clone(),
        ));
        let mut relationships = self.relationships;
        relationships.groups = match self.group_memberships {
            Some(g) => g,
            None => groups.clone(),
        };
        let keys: Arc<dyn KeyResolver> = self.keys.unwrap_or_else(|| accounts.keys.clone());
        let clock = self.clock.clone();
        let verifier = Arc::new(Verifier::new(
            config.domain.clone(),
            MAX_SKEW_SECS,
            replay,
            ledger,
            keys,
            policy,
            self.clock,
        ));
        let fanout = Arc::new(HubFanout::new(groups.clone()));
        let messages = Arc::new(Messages::new(
            db.clone(),
            groups.clone(),
            self.uploads.unwrap_or_else(|| Arc::new(NoUploads)),
            fanout.clone(),
            clock,
        ));
        let ws = Arc::new(Hub::new(
            self.ws_config,
            verifier.clone(),
            config.client_ip_header.clone(),
            config.domain.clone(),
            self.ws_seams.unwrap_or_else(|| Seams {
                topics: Arc::new(GroupTopics::new(groups.clone())),
                timeline: Arc::new(MessageTimeline::new(messages.clone())),
                messages: Some(messages.clone()),
            }),
        ));
        fanout.attach(&ws);
        accounts.on_revocation(ws.clone());
        // Subscriptions whose access a group change revokes end at once.
        ws::follow_groups(&runtime, &ws, &groups);
        let liveness = self.liveness.unwrap_or_else(|| ws.clone());
        let profiles = Arc::new(Profiles::new(
            config.domain.clone(),
            db.clone(),
            relationships,
            liveness,
        ));
        Ok(AppState {
            config: Arc::new(config),
            db,
            accounts,
            admins,
            groups,
            messages,
            verifier,
            discovery,
            federation,
            profiles,
            ws,
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
            relationships: Relationships::default(),
            group_memberships: None,
            liveness: None,
            ws_config: WsConfig::default(),
            ws_seams: None,
            uploads: None,
        }
    }

    /// Reload every live nonce from the persistent ledger into the replay
    /// store and end its restart warm-up. Call before serving. On error the
    /// warm-up stays in force (signed requests get `503` for one skew window
    /// after startup), which is safe. One attempt: startup uses
    /// [`AppState::restore_replay_until_loaded`], which retries.
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

    /// [`AppState::restore_replay`], retried until the ledger can be read.
    ///
    /// At startup the database may not be listening yet (on jkbase the
    /// managed rhypedb starts beside the app, about a second after it), so a
    /// single attempt would leave the warm-up in force for a whole skew
    /// window after every restart. Each failure is retried, waiting from
    /// [`RESTORE_RETRY_MIN`] doubling to [`RESTORE_RETRY_MAX`], and the
    /// warm-up ends as soon as a load succeeds, even after serving began:
    /// until then every signed request the warm-up does not refuse is
    /// recorded in memory, and [`replay::ReplayStore::restore`] keeps those
    /// entries, so ending it late is as safe as ending it before serving.
    ///
    /// Returns the number restored, or [`LedgerError::NotPersistent`] at
    /// once for a ledger that persists nothing (its warm-up stays in force
    /// and expires on its own). Logs the outcome.
    pub async fn restore_replay_until_loaded(self) -> Result<usize, LedgerError> {
        let mut wait = RESTORE_RETRY_MIN;
        let mut last_warn: Option<tokio::time::Instant> = None;
        loop {
            match self.restore_replay().await {
                Ok(n) => {
                    tracing::info!(restored = n, "replay store restored from the ledger");
                    return Ok(n);
                }
                Err(LedgerError::NotPersistent) => {
                    tracing::warn!(
                        "replay ledger does not persist; signed requests get 503 for one skew window"
                    );
                    return Err(LedgerError::NotPersistent);
                }
                Err(e) => {
                    let now = tokio::time::Instant::now();
                    if last_warn.is_none_or(|t| now.duration_since(t) >= RESTORE_WARN_EVERY) {
                        last_warn = Some(now);
                        tracing::warn!(
                            error = %e,
                            "replay ledger unavailable; signed requests get 503 until it loads \
                             (at most one skew window after startup)"
                        );
                    } else {
                        tracing::debug!(error = %e, "replay ledger still unavailable; retrying");
                    }
                    tokio::time::sleep(wait).await;
                    wait = (wait * 2).min(RESTORE_RETRY_MAX);
                }
            }
        }
    }

    /// The replay store's background work for the life of the process:
    /// [`AppState::restore_replay_until_loaded`], its outcome sent on
    /// `restored` (startup waits on it before serving), then
    /// [`AppState::purge_ledger_forever`].
    ///
    /// The purge starts only after the restore: the ledger is read in pages
    /// by offset, and rows deleted meanwhile would shift the pages and skip a
    /// live nonce. (The ledger's `@unique` key would still refuse that
    /// nonce's replay, but the in-memory store is meant to hold it too.)
    pub async fn maintain_replay(
        self,
        restored: tokio::sync::oneshot::Sender<Result<usize, LedgerError>>,
    ) {
        let outcome = self.clone().restore_replay_until_loaded().await;
        // Startup may have stopped waiting; the outcome is logged either way.
        let _ = restored.send(outcome);
        self.purge_ledger_forever().await;
    }

    /// Read the stored federation policy and put it in force. Call before
    /// serving; until it succeeds every federation decision fails closed
    /// (`503` inbound, nothing sent outbound).
    pub async fn load_federation(&self) -> Result<(), DbError> {
        self.federation.load().await
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
/// Layer order, outermost first: tracing, CORS (§3.4: preflights are
/// answered before anything else, and every response, problems included,
/// gets the headers; the admin paths are excluded by path), problem
/// rendering (so every [`Problem`], including the signature layer's and
/// extractors' rejections, gets its body), signature verification (OFSCP
/// routes only), routes.
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
        .route("/api/groups", post(groups::routes::create_group))
        .route(
            "/api/groups/{group_id}",
            get(groups::routes::get_group)
                .patch(groups::routes::update_group)
                .delete(groups::routes::delete_group),
        )
        .route(
            "/api/groups/{group_id}/channels",
            get(groups::routes::list_channels).post(groups::routes::create_channel),
        )
        .route(
            "/api/groups/{group_id}/channels/{channel_id}",
            get(groups::routes::get_channel)
                .patch(groups::routes::update_channel)
                .delete(groups::routes::delete_channel),
        )
        .route("/api/tiers", get(groups::routes::tiers))
        .route("/api/me", get(profiles::routes::me))
        .route(
            "/api/me/profile",
            patch(profiles::routes::update_profile).layer(profile_body_limit()),
        )
        .route(
            "/api/me/presence",
            put(profiles::routes::set_presence).layer(profile_body_limit()),
        )
        .route(
            "/api/me/privacy",
            get(profiles::routes::privacy)
                .put(profiles::routes::update_privacy)
                .layer(profile_body_limit()),
        )
        .route(
            "/api/users/{user_ref}/profile",
            get(profiles::routes::user_profile),
        )
        .route(
            "/api/users/{user_ref}/presence",
            get(profiles::routes::user_presence),
        )
        .route(
            "/api/users/{user_ref}/groups",
            get(profiles::routes::user_groups),
        )
        .route(discovery::PATH, get(discovery::get))
        .route("/problems/{code}", get(problem::describe))
        .merge(messages::routes::router())
        .fallback(|| async { Problem::not_found() })
        .method_not_allowed_fallback(|| async { Problem::method_not_allowed() })
        .layer(middleware::from_fn_with_state(
            signing::SignatureLayer::new(
                state.verifier.clone(),
                state.config.client_ip_header.clone(),
            ),
            signing::authenticate,
        ))
        // Added after the signature layer, so it does not wrap them: admin
        // requests are authenticated by the admin session, never by OFSCP
        // signatures (docs/decisions/0005).
        .merge(admin::routes::router())
        // Unsigned upgrade: the handshake inside the socket authenticates
        // (§7.1).
        .route(ws::PATH, get(ws::upgrade))
        .layer(middleware::map_response_with_state(
            ProblemBase::new(&state.config.domain),
            problem::render,
        ))
        .layer(middleware::from_fn(cors::layer))
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

/// Body limit for the profile, presence and privacy updates.
fn profile_body_limit() -> axum::extract::DefaultBodyLimit {
    axum::extract::DefaultBodyLimit::max(profiles::routes::PROFILE_BODY_LIMIT)
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
