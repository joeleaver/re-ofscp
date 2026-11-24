//! Setup, sign-in, the session, and the admin's own TOTP and password.

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use re_ofscp_types::admin::{
    AdminLoginRequest, AdminSessionInfo, AdminSetupRequest, PasswordChange, TotpConfirm,
    TotpEnrollment,
};

use super::{SERVER_ERROR, busy, internal, limited, manage_problem, manage_why, password_problem};
use crate::AppState;
use crate::admin::audit::{Record, outcome};
use crate::admin::auth::{Restricted, check_origin, disabled};
use crate::admin::sessions::{clear_cookie, csrf_token, set_cookie};
use crate::admin::{Admin, LoginError, SetupError};
use crate::client::{Peer, client_key};
use crate::problem::Problem;
use crate::timefmt::rfc3339;

fn info(admin: &Admin, token: &str, expires_at: i64) -> AdminSessionInfo {
    AdminSessionInfo {
        username: admin.username.clone(),
        role: admin.role,
        totp_enabled: admin.totp_enabled(),
        password_change_required: admin.password_change_required,
        restricted: admin.restricted(),
        csrf_token: csrf_token(token),
        expires_at: rfc3339(expires_at),
    }
}

/// The checks every unauthenticated admin endpoint makes first: the API
/// is on, the request is same-origin, and the source is under its limit.
/// Returns the source.
fn admit(state: &AppState, headers: &HeaderMap, peer: &Peer, now: i64) -> Result<String, Problem> {
    let admins = &state.admins;
    if !admins.enabled() {
        return Err(disabled());
    }
    check_origin(headers, &admins.domain)?;
    let source = client_key(&state.config, headers, peer);
    admins.per_source.check(&source, now).map_err(limited)?;
    Ok(source)
}

/// `POST /api/admin/setup`: create the first admin (an owner) with the
/// one-time setup token. `201` with the admin; they then sign in and
/// enroll TOTP.
pub async fn setup(
    State(state): State<AppState>,
    peer: Peer,
    headers: HeaderMap,
    Json(req): Json<AdminSetupRequest>,
) -> Result<Response, Problem> {
    let now = state.verifier.now();
    let source = admit(&state, &headers, &peer, now)?;
    let admins = &state.admins;
    let admin = admins
        .setup(&req.setup_token, &req.username, &req.password, &source, now)
        .await
        .map_err(|e| match e {
            SetupError::NotConfigured => Problem::not_found()
                .with_detail("first-admin setup is not configured (ADMIN_SETUP_TOKEN)"),
            SetupError::BadToken => {
                tracing::warn!(source = %source, "admin setup with a wrong token");
                Problem::forbidden().with_detail("invalid setup token")
            }
            SetupError::Done => Problem::conflict().with_detail(e.to_string()),
            SetupError::InvalidUsername => Problem::bad_request().with_detail(e.to_string()),
            SetupError::Password(p) => password_problem(&p),
            SetupError::Audit(ref err) => {
                tracing::error!(target: "audit", error = %err, "audit log unavailable; refusing admin setup");
                Problem::service_unavailable(5)
                    .with_detail("the audit log is unavailable; retry shortly")
            }
            SetupError::Db(_) => internal(e),
        })?;
    Ok((StatusCode::CREATED, Json(super::admins::view(&admin))).into_response())
}

/// `POST /api/admin/login`: username, password and (once enrolled) a TOTP
/// code. `200` with the session and its CSRF token, and the session
/// cookie. An admin without TOTP gets a restricted session for enrolling.
pub async fn login(
    State(state): State<AppState>,
    peer: Peer,
    headers: HeaderMap,
    Json(req): Json<AdminLoginRequest>,
) -> Result<Response, Problem> {
    let now = state.verifier.now();
    let source = admit(&state, &headers, &peer, now)?;
    let admins = &state.admins;
    let record = |detail: &str| Record {
        admin: req.username.clone(),
        action: "session.login",
        target: String::new(),
        source: source.clone(),
        detail: detail.to_owned(),
    };
    let admin = match admins
        .login(
            &req.username,
            &req.password,
            req.code.as_deref(),
            &source,
            now,
        )
        .await
    {
        Ok(a) => a,
        Err(e) => {
            // Failures are audited for real admins only: recording every
            // made-up username would let anyone fill the log. The write is
            // not awaited, so a real admin's failure takes no longer to
            // answer than a made-up one's (no enumeration by timing).
            if matches!(
                e,
                LoginError::Invalid { known: true } | LoginError::Locked { known: true, .. }
            ) {
                let r = record(&e.to_string());
                let audit = admins.audit.clone();
                tokio::spawn(async move {
                    if let Err(err) = audit.record(&r, outcome::FAILED, now).await {
                        tracing::error!(target: "audit", error = %err, "could not record a failed admin sign-in");
                    }
                });
            }
            return Err(match e {
                LoginError::Invalid { .. } => {
                    Problem::unauthorized().with_detail("invalid username, password or code")
                }
                LoginError::Locked { limit, .. } => limited(limit),
                LoginError::Busy => busy(),
                LoginError::Internal(_) => internal(e),
            });
        }
    };
    let (token, expires_at) = admins.start_session(&admin, now).await.map_err(internal)?;
    let detail = if admin.restricted() {
        "restricted session"
    } else {
        "full session"
    };
    if let Err(e) = admins.audit.record(&record(detail), outcome::OK, now).await {
        // No unaudited sessions: end it and refuse.
        tracing::error!(target: "audit", error = %e, "audit log unavailable; refusing an admin sign-in");
        if let Some(hash) = crate::admin::sessions::token_hash(&token)
            && let Err(e) = admins.sessions.delete(&hash).await
        {
            tracing::error!(error = %e, "could not delete an unaudited admin session");
        }
        return Err(Problem::service_unavailable(5).with_detail("the audit log is unavailable"));
    }
    Ok((
        [(header::SET_COOKIE, set_cookie(&token))],
        Json(info(&admin, &token, expires_at)),
    )
        .into_response())
}

/// `POST /api/admin/logout`: end this session. `204`, clearing the cookie.
pub async fn logout(
    State(state): State<AppState>,
    Restricted(ctx): Restricted,
) -> Result<Response, Problem> {
    let entry = ctx.begin(&state, "session.logout", "", "").await?;
    match state.admins.sessions.delete(&ctx.session.token_hash).await {
        Ok(()) => entry.ok("").await,
        Err(e) => {
            entry.failed(SERVER_ERROR).await;
            return Err(internal(e));
        }
    }
    Ok((
        StatusCode::NO_CONTENT,
        [(header::SET_COOKIE, clear_cookie())],
    )
        .into_response())
}

/// `GET /api/admin/session`: who is signed in, and the CSRF token.
pub async fn session(Restricted(ctx): Restricted) -> Json<AdminSessionInfo> {
    Json(info(&ctx.admin, &ctx.token, ctx.session.expires_at))
}

/// `POST /api/admin/totp/enroll`: a fresh secret to add to an
/// authenticator, shown once. Confirm it with a code.
pub async fn totp_enroll(
    State(state): State<AppState>,
    Restricted(ctx): Restricted,
) -> Result<Json<TotpEnrollment>, Problem> {
    let entry = ctx
        .begin(&state, "totp.enroll", &ctx.admin.username, "")
        .await?;
    match state.admins.enroll_totp(&ctx.admin).await {
        Ok(enrollment) => {
            entry.ok("").await;
            Ok(Json(enrollment))
        }
        Err(e) => {
            entry.failed(&manage_why(&e)).await;
            Err(manage_problem(&e))
        }
    }
}

/// `POST /api/admin/totp/confirm`: finish enrollment with a current code.
/// `204`; the admin's other sessions end.
pub async fn totp_confirm(
    State(state): State<AppState>,
    Restricted(ctx): Restricted,
    Json(req): Json<TotpConfirm>,
) -> Result<StatusCode, Problem> {
    let entry = ctx
        .begin(&state, "totp.confirm", &ctx.admin.username, "")
        .await?;
    match state
        .admins
        .confirm_totp(&ctx.admin, &req.code, &ctx.session.token_hash, ctx.now)
        .await
    {
        Ok(()) => {
            entry.ok("").await;
            Ok(StatusCode::NO_CONTENT)
        }
        Err(e) => {
            entry.failed(&manage_why(&e)).await;
            Err(manage_problem(&e))
        }
    }
}

/// `POST /api/admin/password`: change one's own password. `204`; the
/// admin's other sessions end.
pub async fn change_password(
    State(state): State<AppState>,
    Restricted(ctx): Restricted,
    Json(req): Json<PasswordChange>,
) -> Result<StatusCode, Problem> {
    let entry = ctx
        .begin(&state, "password.change", &ctx.admin.username, "")
        .await?;
    match state
        .admins
        .change_password(
            &ctx.admin,
            &req.current_password,
            &req.new_password,
            &ctx.session.token_hash,
            ctx.now,
        )
        .await
    {
        Ok(()) => {
            entry.ok("").await;
            Ok(StatusCode::NO_CONTENT)
        }
        Err(e) => {
            entry.failed(&manage_why(&e)).await;
            Err(manage_problem(&e))
        }
    }
}
