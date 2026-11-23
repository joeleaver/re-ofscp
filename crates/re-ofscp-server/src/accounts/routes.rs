//! HTTP endpoints for accounts and keys (spec §4.1–§4.7).
//!
//! | Route | Auth | Spec |
//! | --- | --- | --- |
//! | `POST /api/auth/register` | none | §4.1.1: refused, registration is by admin or invitation |
//! | `POST /api/auth/login` | none | §4.1.2 |
//! | `POST /api/auth/device-keys` | bootstrap token | §4.3.1 |
//! | `GET /api/auth/device-keys` | signed, local actor | §4.7 |
//! | `DELETE /api/auth/device-keys/{keyId}` | signed, local actor | §4.7 |
//! | `GET /.well-known/ofscp/users/{handle}/keys` | none | §4.6 |

use std::net::SocketAddr;

use axum::Json;
use axum::extract::{ConnectInfo, FromRequestParts, Path, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use re_ofscp_types::auth::{
    BOOTSTRAP_TOKEN_TYPE, BootstrapResponse, DeviceKeyCreated, DeviceKeyInfo,
    DeviceKeyRegistration, DeviceKeysResponse, ED25519, LoginRequest, PublicKey, UserKeysResponse,
};
use re_ofscp_types::is_valid_handle;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::{BOOTSTRAP_TTL_SECS, IssueError, MAX_DEVICE_KEYS, MAX_DEVICE_NAME_CHARS, Revocation};
use crate::AppState;
use crate::problem::Problem;
use crate::ratelimit::Limited;
use crate::signing::Authenticated;
use crate::signing::canonical::decode_public_key;

/// How long verifiers may cache a user's keys (§4.7.1: SHOULD be short).
pub const KEYS_CACHE_SECS: i64 = 300;

fn rfc3339(unix: i64) -> String {
    OffsetDateTime::from_unix_timestamp(unix)
        .ok()
        .and_then(|t| t.format(&Rfc3339).ok())
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_owned())
}

fn limited(l: Limited) -> Problem {
    Problem::too_many_requests(l.retry_after)
}

fn internal(e: impl std::fmt::Display) -> Problem {
    tracing::error!(error = %e, "account operation failed");
    Problem::internal()
}

/// The TCP peer address, when the server was started with connect info
/// (tests calling the router directly have none).
pub struct Peer(Option<SocketAddr>);

impl<S: Send + Sync> FromRequestParts<S> for Peer {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|c| c.0),
        ))
    }
}

/// The client's address for rate limiting: from the configured trusted
/// header (first hop) when set, else the TCP peer.
fn client_key(state: &AppState, headers: &HeaderMap, peer: &Peer) -> String {
    if let Some(name) = &state.config.client_ip_header
        && let Some(v) = headers.get(name.as_str()).and_then(|v| v.to_str().ok())
        && let Some(first) = v.split(',').next()
    {
        let first = first.trim();
        if !first.is_empty() {
            return first.to_owned();
        }
    }
    peer.0
        .map_or_else(|| "unknown".to_owned(), |a| a.ip().to_string())
}

/// `POST /api/auth/register`: open self-registration is not offered.
pub async fn register() -> Problem {
    Problem::registration_closed()
}

/// `POST /api/auth/login` (§4.1.2).
pub async fn login(
    State(state): State<AppState>,
    peer: Peer,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> Result<Json<BootstrapResponse>, Problem> {
    let accounts = &state.accounts;
    let now = state.verifier.now();
    accounts
        .per_source
        .check(&client_key(&state, &headers, &peer), now)
        .map_err(limited)?;
    accounts
        .login_backoff
        .check(&req.handle, now)
        .map_err(limited)?;

    // An invalid handle cannot exist; treat it exactly like an unknown one
    // (same work, same answer), so neither reveals anything.
    let user = if is_valid_handle(&req.handle) {
        accounts
            .store
            .find_user(&req.handle)
            .await
            .map_err(internal)?
    } else {
        None
    };
    let active = user.filter(|u| u.is_active());
    let ok = accounts
        .passwords
        .verify(
            &req.password,
            active.as_ref().map(|u| u.password_hash.as_str()),
        )
        .await
        .map_err(internal)?;
    let Some(user) = active.filter(|_| ok) else {
        accounts.login_backoff.fail(&req.handle, now);
        return Err(Problem::unauthorized().with_detail("invalid handle or password"));
    };
    accounts.login_backoff.succeed(&user.handle);
    let token = accounts
        .tokens
        .issue(&user.handle, now)
        .map_err(|e| match e {
            IssueError::Full => Problem::service_unavailable(BOOTSTRAP_TTL_SECS.unsigned_abs()),
            IssueError::Random(e) => internal(e),
        })?;
    Ok(Json(BootstrapResponse {
        bootstrap_token: token,
        token_type: BOOTSTRAP_TOKEN_TYPE.to_owned(),
        expires_in: BOOTSTRAP_TTL_SECS.unsigned_abs(),
    }))
}

/// The bootstrap token from `Authorization: Bearer …`.
fn bearer(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let (Some(v), None) = (values.next(), values.next()) else {
        return None;
    };
    let v = v.to_str().ok()?;
    let (scheme, token) = v.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then(|| token.trim())
}

/// `POST /api/auth/device-keys` (§4.3.1), authorized by a bootstrap token.
pub async fn register_device_key(
    State(state): State<AppState>,
    peer: Peer,
    headers: HeaderMap,
    Json(req): Json<DeviceKeyRegistration>,
) -> Result<Response, Problem> {
    let accounts = &state.accounts;
    let now = state.verifier.now();
    accounts
        .per_source
        .check(&client_key(&state, &headers, &peer), now)
        .map_err(limited)?;
    let unauthorized =
        || Problem::unauthorized().with_detail("a valid bootstrap token is required");
    let token = bearer(&headers).ok_or_else(unauthorized)?;
    let handle = accounts.tokens.peek(token, now).ok_or_else(unauthorized)?;

    // Validate the request before the token is consumed (it is consumed only
    // by a successful registration, §4.2).
    let algorithm = req.algorithm.as_deref().unwrap_or(ED25519);
    if algorithm != ED25519 {
        return Err(Problem::bad_request().with_detail("algorithm must be Ed25519 (§4.3.3)"));
    }
    if decode_public_key(&req.public_key).is_none() {
        return Err(
            Problem::bad_request().with_detail("public_key must be a base64 Ed25519 public key")
        );
    }
    let device_name = req.device_name.trim();
    if device_name.chars().count() > MAX_DEVICE_NAME_CHARS {
        return Err(Problem::bad_request().with_detail(format!(
            "device_name is limited to {MAX_DEVICE_NAME_CHARS} characters"
        )));
    }

    let _serial = accounts.key_registration.lock().await;
    let user = accounts
        .store
        .find_user(&handle)
        .await
        .map_err(internal)?
        .filter(|u| u.is_active())
        .ok_or_else(unauthorized)?;
    if accounts
        .store
        .active_keys(&handle)
        .await
        .map_err(internal)?
        .len()
        >= MAX_DEVICE_KEYS
    {
        return Err(Problem::conflict().with_detail(format!(
            "an account may hold at most {MAX_DEVICE_KEYS} active device keys; revoke one first"
        )));
    }
    // Still outstanding? (Registration is serialized, so nothing else can
    // consume it between this check and the consume below.)
    if accounts.tokens.peek(token, now).as_deref() != Some(handle.as_str()) {
        return Err(unauthorized());
    }
    let key = accounts
        .store
        .add_device_key(&user, &req.public_key, ED25519, device_name, now)
        .await
        .map_err(internal)?;
    if !accounts.tokens.consume(token, &handle, now) {
        // Revoked meanwhile (the account was disabled): undo.
        let _ = accounts.store.revoke_key(&handle, &key.key_id, now).await;
        return Err(unauthorized());
    }
    Ok((
        StatusCode::CREATED,
        Json(DeviceKeyCreated {
            key_id: key.key_id,
            created_at: key.created_at,
        }),
    )
        .into_response())
}

/// `GET /api/auth/device-keys` (§4.7): the caller's active keys.
pub async fn list_device_keys(
    State(state): State<AppState>,
    auth: Authenticated,
) -> Result<Json<DeviceKeysResponse>, Problem> {
    let actor = auth.local_actor(&state.accounts.domain)?;
    let keys = state
        .accounts
        .store
        .active_keys(actor.handle())
        .await
        .map_err(internal)?
        .into_iter()
        .map(|k| DeviceKeyInfo {
            key_id: k.key_id,
            algorithm: k.algorithm,
            public_key: k.public_key,
            device_name: k.device_name,
            created_at: k.created_at,
        })
        .collect();
    Ok(Json(DeviceKeysResponse { keys }))
}

/// `DELETE /api/auth/device-keys/{keyId}` (§4.7): revoke one of the
/// caller's keys, including the one signing this request.
pub async fn revoke_device_key(
    State(state): State<AppState>,
    auth: Authenticated,
    Path(key_id): Path<String>,
) -> Result<StatusCode, Problem> {
    let accounts = &state.accounts;
    let actor = auth.local_actor(&accounts.domain)?;
    let now = state.verifier.now();
    if !accounts
        .store
        .revoke_key(actor.handle(), &key_id, now)
        .await
        .map_err(internal)?
    {
        return Err(Problem::not_found().with_detail("no active key with that id belongs to you"));
    }
    accounts.keys.invalidate(actor.handle());
    accounts.announce(Revocation {
        handle: actor.handle().to_owned(),
        key_id: Some(key_id),
    });
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /.well-known/ofscp/users/{handle}/keys` (§4.6).
pub async fn user_keys(
    State(state): State<AppState>,
    Path(handle): Path<String>,
) -> Result<Response, Problem> {
    let accounts = &state.accounts;
    let not_found = || Problem::not_found().with_detail("no such user");
    if !is_valid_handle(&handle) {
        return Err(not_found());
    }
    let user = accounts
        .store
        .find_user(&handle)
        .await
        .map_err(internal)?
        .filter(|u| u.is_active())
        .ok_or_else(not_found)?;
    let keys = accounts
        .store
        .active_keys(&user.handle)
        .await
        .map_err(internal)?
        .into_iter()
        .map(|k| PublicKey {
            key_id: k.key_id,
            algorithm: k.algorithm,
            public_key: k.public_key,
            created_at: k.created_at,
        })
        .collect();
    let now = state.verifier.now();
    let body = UserKeysResponse {
        actor: format!("{}@{}", user.handle, accounts.domain),
        keys,
        cache_until: rfc3339(now + KEYS_CACHE_SECS),
    };
    Ok((
        [(
            header::CACHE_CONTROL,
            format!("public, max-age={KEYS_CACHE_SECS}"),
        )],
        Json(body),
    )
        .into_response())
}
