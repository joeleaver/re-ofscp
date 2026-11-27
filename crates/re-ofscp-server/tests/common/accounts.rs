//! A provider over a real rhypedb-server, and requests against its account
//! endpoints (tests/accounts.rs, tests/registration.rs).

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::SigningKey;
use re_ofscp_server::privacy::{GroupMemberships, Liveness};
use re_ofscp_server::signing::StaticKeys;
use re_ofscp_server::{AppState, Config, router};
use serde_json::{Value, json};

use super::harness::{SIGNED_AT, SettableClock, send};
use super::rhypedb::RhypeServer;

/// "Now" for every test: the store began well before, so no warm-up.
pub const NOW: &str = "2026-01-01T12:00:00Z";

/// A running provider and its database.
pub struct Env {
    _server: RhypeServer,
    /// The provider's state.
    pub state: AppState,
    /// Its router.
    pub app: Router,
    /// Its clock (starts at [`SIGNED_AT`]).
    pub clock: Arc<SettableClock>,
}

/// How to build an [`Env`].
#[derive(Default)]
pub struct EnvOptions {
    /// Resolver for remote signers.
    pub remote: Option<StaticKeys>,
    /// `REGISTRATION`, when set.
    pub registration: Option<&'static str>,
    /// Leave `ADMIN_SECRET_KEY` unset (the admin API is then off).
    pub no_admin: bool,
    /// Group memberships for the visibility policy.
    pub groups: Option<Arc<dyn GroupMemberships>>,
    /// Connection liveness for presence.
    pub liveness: Option<Arc<dyn Liveness>>,
    /// Leave the federation policy unloaded (as before startup loads it).
    pub no_federation: bool,
    /// The group-list change backlog (`AppStateBuilder::group_list_backlog`).
    pub group_list_backlog: Option<usize>,
}

/// `ADMIN_SETUP_TOKEN` in tests.
pub const SETUP_TOKEN: &str = "setup-token-for-tests-0123456789abcdef";

/// `ADMIN_SECRET_KEY` in tests (bytes 0..32).
const ADMIN_SECRET_KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

fn config(server: &RhypeServer, registration: Option<&'static str>, admin: bool) -> Config {
    let addr = server.tcp_addr();
    Config::from_lookup(move |k| match k {
        "DOMAIN" => Some("providera.com".into()),
        "PROVIDER_SIGNING_KEY" => Some(super::PROVIDER_SIGNING_KEY.into()),
        "RHYPEDB_ADDR" => Some(addr.clone()),
        // Tests choose their own source address per request.
        "CLIENT_IP_HEADER" => Some("x-test-ip".into()),
        "REGISTRATION" => registration.map(str::to_owned),
        "ADMIN_SECRET_KEY" if admin => Some(ADMIN_SECRET_KEY.into()),
        "ADMIN_SETUP_TOKEN" => Some(SETUP_TOKEN.into()),
        _ => None,
    })
    .unwrap()
}

/// A provider for `providera.com`, past its replay warm-up.
pub async fn env_with(opts: EnvOptions) -> Env {
    let server = RhypeServer::start();
    let clock = SettableClock::at(SIGNED_AT - time::Duration::seconds(400));
    let mut b =
        AppState::builder(config(&server, opts.registration, !opts.no_admin)).clock(clock.clone());
    if let Some(r) = opts.remote {
        b = b.remote_keys(Arc::new(r));
    }
    if let Some(g) = opts.groups {
        b = b.group_memberships(g);
    }
    if let Some(l) = opts.liveness {
        b = b.liveness(l);
    }
    if let Some(n) = opts.group_list_backlog {
        b = b.group_list_backlog(n);
    }
    let state = b.build().unwrap();
    state.restore_replay().await.unwrap();
    if !opts.no_federation {
        state.load_federation().await.unwrap();
    }
    clock.set(SIGNED_AT);
    let app = router(state.clone());
    Env {
        _server: server,
        state,
        app,
        clock,
    }
}

/// A second provider process over `env`'s database (as after a restart),
/// with its federation policy loaded from it.
pub async fn restarted(env: &Env) -> AppState {
    let state = AppState::builder(config(&env._server, None, true))
        .clock(env.clock.clone())
        .build()
        .unwrap();
    state.load_federation().await.unwrap();
    state
}

/// [`env_with`] the defaults.
pub async fn env() -> Env {
    env_with(EnvOptions::default()).await
}

/// Create an account directly (as the admin API will).
pub async fn create(env: &Env, handle: &str, password: &str) {
    env.state
        .accounts
        .create_account(handle, "Some Name", password, SIGNED_AT.unix_timestamp())
        .await
        .unwrap();
}

/// A JSON POST from client address `ip`.
pub fn post_json(path: &str, body: Value, ip: &str) -> Request<Body> {
    Request::post(path)
        .header("host", "providera.com")
        .header("content-type", "application/json")
        .header("x-test-ip", ip)
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// `POST /api/auth/login`: status, body, `Retry-After`.
pub async fn login(
    env: &Env,
    handle: &str,
    password: &str,
    ip: &str,
) -> (StatusCode, Value, Option<String>) {
    let (s, j, _, r) = send(
        &env.app,
        post_json(
            "/api/auth/login",
            json!({"handle": handle, "password": password}),
            ip,
        ),
    )
    .await;
    (s, j, r)
}

/// `POST /api/auth/device-keys` with bootstrap `token`.
pub async fn register_key(
    env: &Env,
    token: &str,
    key: &SigningKey,
    ip: &str,
) -> (StatusCode, Value) {
    let body = json!({
        "public_key": B64.encode(key.verifying_key().to_bytes()),
        "algorithm": "Ed25519",
        "device_name": "Firefox on Linux",
    });
    let mut req = post_json("/api/auth/device-keys", body, ip);
    req.headers_mut().insert(
        header::AUTHORIZATION,
        format!("Bearer {token}").parse().unwrap(),
    );
    let (s, j, _, _) = send(&env.app, req).await;
    (s, j)
}

/// An unsigned GET.
pub fn get(path: &str) -> Request<Body> {
    Request::get(path)
        .header("host", "providera.com")
        .body(Body::empty())
        .unwrap()
}
