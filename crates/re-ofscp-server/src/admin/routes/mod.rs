//! The admin API (`/api/admin/*`, docs/decisions/0005).
//!
//! | Route | Role | Audited as |
//! | --- | --- | --- |
//! | `POST /api/admin/setup` | setup token | `admin.setup` |
//! | `POST /api/admin/login` | none | `session.login` |
//! | `POST /api/admin/logout` | any session | `session.logout` |
//! | `GET /api/admin/session` | any session | — |
//! | `POST /api/admin/totp/enroll` | any session | `totp.enroll` |
//! | `POST /api/admin/totp/confirm` | any session | `totp.confirm` |
//! | `POST /api/admin/password` | any session | `password.change` |
//! | `GET /api/admin/accounts` | read_only | — |
//! | `POST /api/admin/accounts` | operator | `account.create` |
//! | `GET /api/admin/accounts/{handle}` | read_only | — |
//! | `POST /api/admin/accounts/{handle}/disable` | operator | `account.disable` |
//! | `GET /api/admin/invites` | read_only | — |
//! | `POST /api/admin/invites` | operator | `invite.create` |
//! | `DELETE /api/admin/invites/{id}` | operator | `invite.revoke` |
//! | `GET /api/admin/audit` | read_only | — |
//! | `GET /api/admin/admins` | owner | — |
//! | `POST /api/admin/admins` | owner | `admin.create` |
//! | `PATCH /api/admin/admins/{username}` | owner | `admin.update` |
//! | `POST /api/admin/admins/{username}/totp/reset` | owner | `admin.totp_reset` |
//! | `GET /api/admin/federation` | read_only | — |
//! | `PUT /api/admin/federation/mode` | owner | `federation.mode` |
//! | `POST /api/admin/federation/rules` | operator | `federation.rule_add` |
//! | `DELETE /api/admin/federation/rules/{id}` | operator | `federation.rule_remove` |
//!
//! "Any session" includes sessions still finishing setup; every other
//! route needs a full one. Refusals (role, CSRF, restricted session) are
//! audited as `denied`.

mod accounts;
mod admins;
mod federation;
mod session;

use axum::Router;
use axum::routing::{delete, get, patch, post, put};

use crate::AppState;
use crate::accounts::PasswordError;
use crate::accounts::password::BUSY_RETRY_SECS;
use crate::problem::Problem;
use crate::ratelimit::Limited;

/// Largest admin request body.
pub const ADMIN_BODY_LIMIT: usize = 16 * 1024;

/// The admin API's routes. They sit outside the OFSCP signature layer:
/// admin requests are authenticated by the admin session alone.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/admin/setup", post(session::setup))
        .route("/api/admin/login", post(session::login))
        .route("/api/admin/logout", post(session::logout))
        .route("/api/admin/session", get(session::session))
        .route("/api/admin/totp/enroll", post(session::totp_enroll))
        .route("/api/admin/totp/confirm", post(session::totp_confirm))
        .route("/api/admin/password", post(session::change_password))
        .route(
            "/api/admin/accounts",
            get(accounts::list_accounts).post(accounts::create_account),
        )
        .route("/api/admin/accounts/{handle}", get(accounts::get_account))
        .route(
            "/api/admin/accounts/{handle}/disable",
            post(accounts::disable_account),
        )
        .route(
            "/api/admin/invites",
            get(accounts::list_invites).post(accounts::create_invite),
        )
        .route("/api/admin/invites/{id}", delete(accounts::revoke_invite))
        .route("/api/admin/audit", get(accounts::audit))
        .route(
            "/api/admin/admins",
            get(admins::list_admins).post(admins::create_admin),
        )
        .route("/api/admin/admins/{username}", patch(admins::update_admin))
        .route(
            "/api/admin/admins/{username}/totp/reset",
            post(admins::reset_totp),
        )
        .route("/api/admin/federation", get(federation::get_policy))
        .route("/api/admin/federation/mode", put(federation::set_mode))
        .route("/api/admin/federation/rules", post(federation::add_rule))
        .route(
            "/api/admin/federation/rules/{id}",
            delete(federation::remove_rule),
        )
        .layer(axum::extract::DefaultBodyLimit::max(ADMIN_BODY_LIMIT))
}

fn internal(e: impl std::fmt::Display) -> Problem {
    tracing::error!(error = %e, "admin operation failed");
    Problem::internal()
}

fn limited(l: Limited) -> Problem {
    Problem::too_many_requests(l.retry_after)
}

fn busy() -> Problem {
    Problem::service_unavailable(BUSY_RETRY_SECS).with_detail("too many sign-ins in progress")
}

fn password_problem(e: &PasswordError) -> Problem {
    match e {
        PasswordError::Length => Problem::bad_request().with_detail(e.to_string()),
        PasswordError::Busy => busy(),
        PasswordError::Internal(_) => internal(e),
    }
}

fn manage_problem(e: &crate::admin::manage::ManageError) -> Problem {
    use crate::admin::manage::ManageError as E;
    match e {
        E::Invalid(d) | E::WrongCredential(d) => Problem::bad_request().with_detail(*d),
        E::Locked(l) => limited(*l),
        E::Conflict(d) => Problem::conflict().with_detail(*d),
        E::NotFound => Problem::not_found().with_detail("no such admin"),
        E::Password(p) => password_problem(p),
        E::Db(_) => internal(e),
    }
}

/// The outcome detail for the audit log. Server faults are summarized:
/// database messages can echo query text, which must not reach the log.
fn manage_why(e: &crate::admin::manage::ManageError) -> String {
    use crate::admin::manage::ManageError as E;
    match e {
        E::Db(_) | E::Password(PasswordError::Internal(_)) => SERVER_ERROR.to_owned(),
        other => other.to_string(),
    }
}

/// Audit detail for a server fault.
const SERVER_ERROR: &str = "server error";
