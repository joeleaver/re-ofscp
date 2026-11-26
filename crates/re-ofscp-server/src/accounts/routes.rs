//! HTTP endpoints for accounts and keys (spec §4.1–§4.7).
//!
//! | Route | Auth | Spec |
//! | --- | --- | --- |
//! | `POST /api/auth/register` | account invite | §4.1.1 (invite or closed mode) |
//! | `POST /api/auth/login` | none | §4.1.2 |
//! | `POST /api/auth/device-keys` | bootstrap token | §4.3.1 |
//! | `GET /api/auth/device-keys` | signed, local actor | §4.7 |
//! | `DELETE /api/auth/device-keys/{keyId}` | signed, local actor | §4.7 |
//! | `GET /.well-known/ofscp/users/{handle}/keys` | none | §4.6 |

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use re_ofscp_types::auth::{
    BOOTSTRAP_TOKEN_TYPE, BootstrapResponse, DeviceKeyCreated, DeviceKeyInfo,
    DeviceKeyRegistration, DeviceKeysResponse, ED25519, LoginRequest, PublicKey,
    RegistrationRequest, UserKeysResponse,
};
use re_ofscp_types::is_valid_handle;

use super::{
    BOOTSTRAP_TTL_SECS, IssueError, MAX_DEVICE_KEYS, MAX_DEVICE_NAME_CHARS, RegisterError,
    Revocation,
};
use crate::AppState;
use crate::client::{Peer, client_key};
use crate::problem::Problem;
use crate::ratelimit::Limited;
use crate::signing::Authenticated;
use crate::signing::canonical::decode_public_key;
use crate::timefmt::rfc3339;

/// How long verifiers may cache a user's keys (§4.7.1: SHOULD be short).
pub const KEYS_CACHE_SECS: i64 = 300;

/// Largest body accepted by the unauthenticated auth endpoints.
pub const AUTH_BODY_LIMIT: usize = 16 * 1024;

fn limited(l: Limited) -> Problem {
    Problem::too_many_requests(l.retry_after)
}

fn busy() -> Problem {
    Problem::service_unavailable(super::password::BUSY_RETRY_SECS)
        .with_detail("too many sign-ins in progress; retry shortly")
}

fn password_error(e: super::PasswordError) -> Problem {
    match e {
        super::PasswordError::Busy => busy(),
        other => internal(other),
    }
}

fn internal(e: impl std::fmt::Display) -> Problem {
    tracing::error!(error = %e, "account operation failed");
    Problem::internal()
}

/// `POST /api/auth/register` (§4.1.1): by account invite, or refused when
/// registration is closed. Answers `201` with a bootstrap token.
pub async fn register(
    State(state): State<AppState>,
    peer: Peer,
    headers: HeaderMap,
    Json(req): Json<RegistrationRequest>,
) -> Result<Response, Problem> {
    let accounts = &state.accounts;
    let now = state.verifier.now();
    accounts
        .per_source
        .check(&client_key(&state.config, &headers, &peer), now)
        .map_err(limited)?;
    let user = accounts.register(&req, now).await.map_err(|e| match e {
        RegisterError::Closed => Problem::registration_closed(),
        RegisterError::InviteRequired => Problem::invite_required(),
        RegisterError::Invalid(e) => Problem::bad_request().with_detail(e.to_string()),
        RegisterError::HandleTaken => {
            Problem::conflict().with_detail("that handle is already registered")
        }
        RegisterError::Busy => busy(),
        RegisterError::Internal(e) => internal(e),
    })?;
    let token = issue_bootstrap(accounts, &user.handle, now)?;
    Ok((StatusCode::CREATED, Json(token)).into_response())
}

fn issue_bootstrap(
    accounts: &super::Accounts,
    handle: &str,
    now: i64,
) -> Result<BootstrapResponse, Problem> {
    let token = accounts.tokens.issue(handle, now).map_err(|e| match e {
        IssueError::Full => Problem::service_unavailable(BOOTSTRAP_TTL_SECS.unsigned_abs()),
        IssueError::Random(e) => internal(e),
    })?;
    Ok(BootstrapResponse {
        bootstrap_token: token,
        token_type: BOOTSTRAP_TOKEN_TYPE.to_owned(),
        expires_in: BOOTSTRAP_TTL_SECS.unsigned_abs(),
    })
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
        .check(&client_key(&state.config, &headers, &peer), now)
        .map_err(limited)?;
    // An invalid handle cannot exist: it is answered exactly like an
    // unknown one (same work, same body) but not tracked for lockout, which
    // also keeps arbitrary strings out of the lockout table.
    let valid = is_valid_handle(&req.handle);
    if valid {
        // Counted as a failure before the password is checked, so concurrent
        // guesses cannot all get in ahead of the first recorded failure.
        accounts
            .login_backoff
            .attempt(&req.handle, now)
            .map_err(limited)?;
    }
    // A fault before the password is decided must not count against the
    // account (a flood that saturates hashing would otherwise lock real
    // users out): take the attempt back.
    let undecided = |p: Problem| {
        if valid {
            accounts.login_backoff.refund(&req.handle);
        }
        p
    };
    let user = if valid {
        accounts
            .store
            .find_user(&req.handle)
            .await
            .map_err(|e| undecided(internal(e)))?
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
        .map_err(|e| undecided(password_error(e)))?;
    let Some(user) = active.filter(|_| ok) else {
        return Err(Problem::unauthorized().with_detail("invalid handle or password"));
    };
    accounts.login_backoff.succeed(&user.handle);
    Ok(Json(issue_bootstrap(accounts, &user.handle, now)?))
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
        .check(&client_key(&state.config, &headers, &peer), now)
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
    if let Err(e) = decode_public_key(&req.public_key) {
        return Err(Problem::bad_request().with_detail(format!(
            "public_key must be a base64 Ed25519 public key ({e})"
        )));
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
        // Revoked meanwhile (the account was disabled): undo. The account
        // is disabled, so a key left behind would not verify, but it must
        // not linger as active: say so loudly.
        if let Err(e) = accounts.store.revoke_key(&handle, &key.key_id, now).await {
            tracing::error!(
                error = %e,
                handle = %handle,
                key_id = %key.key_id,
                "could not revoke a key registered while its account was being disabled"
            );
        }
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
///
/// A handle without an active account (unknown or disabled) gets `200` with
/// no keys rather than `404`, so this public, unthrottled endpoint does not
/// enumerate accounts (§4.1.2's spirit; Forumall answers the same way). An
/// invalid handle can never be an account and gets `404`.
pub async fn user_keys(
    State(state): State<AppState>,
    Path(handle): Path<String>,
) -> Result<Response, Problem> {
    let accounts = &state.accounts;
    if !is_valid_handle(&handle) {
        return Err(Problem::not_found().with_detail("not a valid handle"));
    }
    let active = accounts
        .store
        .find_user(&handle)
        .await
        .map_err(internal)?
        .is_some_and(|u| u.is_active());
    let keys = if active {
        accounts
            .store
            .active_keys(&handle)
            .await
            .map_err(internal)?
            .into_iter()
            .map(|k| PublicKey {
                key_id: k.key_id,
                algorithm: k.algorithm,
                public_key: k.public_key,
                created_at: k.created_at,
            })
            .collect()
    } else {
        Vec::new()
    };
    let now = state.verifier.now();
    let body = UserKeysResponse {
        actor: format!("{handle}@{}", accounts.domain),
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
