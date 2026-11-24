//! OFSCP accounts, account invites and the audit log, for admins.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use re_ofscp_types::admin::{
    AccountList, AccountView, AdminRole, AuditList, CreateAccount, CreateInvite, InviteCreated,
    InviteList, InviteView,
};
use serde::Deserialize;

use super::{SERVER_ERROR, internal, password_problem};
use crate::AppState;
use crate::accounts::{
    AccountSummary, CreateError, InviteError, PasswordError, Revoked, StoreError, invites,
};
use crate::admin::MAX_OUTSTANDING_INVITES;
use crate::admin::audit::{self, ListError};
use crate::admin::auth::AdminCtx;
use crate::problem::Problem;
use crate::timefmt::{rfc3339, unix};

/// Most accounts one listing returns.
pub const MAX_ACCOUNTS_LISTED: usize = 100;

/// Longest audit window one listing covers: 31 days.
pub const MAX_AUDIT_WINDOW_SECS: i64 = 31 * 86_400;

/// Default audit window: the last day.
pub const DEFAULT_AUDIT_WINDOW_SECS: i64 = 86_400;

fn view(a: AccountSummary) -> AccountView {
    AccountView {
        handle: a.handle,
        display_name: a.display_name,
        status: a.status,
        created_at: a.created_at,
    }
}

/// `GET /api/admin/accounts` query.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountQuery {
    /// Only handles containing this.
    #[serde(default)]
    q: Option<String>,
}

/// `GET /api/admin/accounts[?q=…]`: up to 100 accounts by handle.
pub async fn list_accounts(
    State(state): State<AppState>,
    ctx: AdminCtx,
    Query(query): Query<AccountQuery>,
) -> Result<Json<AccountList>, Problem> {
    ctx.require(&state, AdminRole::ReadOnly, "account.list", "")
        .await?;
    let q = query.q.as_deref().map(str::trim).filter(|q| !q.is_empty());
    if q.is_some_and(|q| q.len() > 64) {
        return Err(Problem::bad_request().with_detail("q is at most 64 bytes"));
    }
    let mut found = state
        .accounts
        .store
        .search(q, MAX_ACCOUNTS_LISTED + 1)
        .await
        .map_err(internal)?;
    let truncated = found.len() > MAX_ACCOUNTS_LISTED;
    found.sort_by(|a, b| a.handle.cmp(&b.handle));
    found.truncate(MAX_ACCOUNTS_LISTED);
    Ok(Json(AccountList {
        accounts: found.into_iter().map(view).collect(),
        truncated,
    }))
}

/// `GET /api/admin/accounts/{handle}`.
pub async fn get_account(
    State(state): State<AppState>,
    ctx: AdminCtx,
    Path(handle): Path<String>,
) -> Result<Json<AccountView>, Problem> {
    ctx.require(&state, AdminRole::ReadOnly, "account.get", &handle)
        .await?;
    state
        .accounts
        .store
        .summary(&handle)
        .await
        .map_err(internal)?
        .map(|a| Json(view(a)))
        .ok_or_else(|| Problem::not_found().with_detail("no such account"))
}

fn create_problem(e: &CreateError) -> Problem {
    match e {
        CreateError::InvalidHandle
        | CreateError::ReservedHandle
        | CreateError::InvalidDisplayName => Problem::bad_request().with_detail(e.to_string()),
        CreateError::Password(p) => password_problem(p),
        CreateError::Store(StoreError::HandleTaken) => {
            Problem::conflict().with_detail("that handle is already registered")
        }
        CreateError::Store(StoreError::Db(_)) => internal(e),
    }
}

fn create_why(e: &CreateError) -> String {
    match e {
        CreateError::Store(StoreError::Db(_))
        | CreateError::Password(PasswordError::Internal(_)) => SERVER_ERROR.to_owned(),
        other => other.to_string(),
    }
}

/// `POST /api/admin/accounts` (operator): create an active account. `201`.
pub async fn create_account(
    State(state): State<AppState>,
    ctx: AdminCtx,
    Json(req): Json<CreateAccount>,
) -> Result<Response, Problem> {
    ctx.require(&state, AdminRole::Operator, "account.create", &req.handle)
        .await?;
    let entry = ctx.begin(&state, "account.create", &req.handle, "").await?;
    let display_name = req.display_name.as_deref().unwrap_or(&req.handle);
    let result = state
        .accounts
        .create_account(&req.handle, display_name, &req.password, ctx.now)
        .await;
    match result {
        Ok(user) => {
            entry.ok("").await;
            let created = AccountView {
                handle: user.handle,
                display_name: user.display_name,
                status: user.status,
                created_at: rfc3339(ctx.now),
            };
            Ok((StatusCode::CREATED, Json(created)).into_response())
        }
        Err(e) => {
            entry.failed(&create_why(&e)).await;
            Err(create_problem(&e))
        }
    }
}

/// `POST /api/admin/accounts/{handle}/disable` (operator): the account can
/// no longer sign in, its keys stop verifying and are revoked. `204`.
/// Disabling a disabled account again finishes an interrupted revocation.
pub async fn disable_account(
    State(state): State<AppState>,
    ctx: AdminCtx,
    Path(handle): Path<String>,
) -> Result<StatusCode, Problem> {
    ctx.require(&state, AdminRole::Operator, "account.disable", &handle)
        .await?;
    let entry = ctx.begin(&state, "account.disable", &handle, "").await?;
    let user = match state.accounts.store.find_user(&handle).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            entry.failed("no such account").await;
            return Err(Problem::not_found().with_detail("no such account"));
        }
        Err(e) => {
            entry.failed(SERVER_ERROR).await;
            return Err(internal(e));
        }
    };
    match state.accounts.disable_account(&user, ctx.now).await {
        Ok(()) => {
            entry.ok("").await;
            Ok(StatusCode::NO_CONTENT)
        }
        Err(e) => {
            entry.failed(SERVER_ERROR).await;
            Err(internal(e))
        }
    }
}

/// `GET /api/admin/invites`: usable invites, newest first.
pub async fn list_invites(
    State(state): State<AppState>,
    ctx: AdminCtx,
) -> Result<Json<InviteList>, Problem> {
    ctx.require(&state, AdminRole::ReadOnly, "invite.list", "")
        .await?;
    let mut found = state
        .accounts
        .invites
        .list_usable(ctx.now, MAX_OUTSTANDING_INVITES)
        .await
        .map_err(internal)?;
    found.sort_by(|a, b| {
        (unix(&b.created_at), &b.token_hash).cmp(&(unix(&a.created_at), &a.token_hash))
    });
    Ok(Json(InviteList {
        invites: found
            .into_iter()
            .map(|i| InviteView {
                id: i.token_hash,
                handle: i.handle,
                created_by: i.created_by,
                created_at: i.created_at,
                expires_at: i.expires_at,
            })
            .collect(),
    }))
}

fn invite_problem(e: &InviteError) -> Problem {
    match e {
        InviteError::InvalidHandle(_) | InviteError::InvalidLifetime => {
            Problem::bad_request().with_detail(e.to_string())
        }
        InviteError::HandleTaken => {
            Problem::conflict().with_detail("that handle is already registered")
        }
        InviteError::Store(_) => internal(e),
    }
}

/// `POST /api/admin/invites` (operator): issue an invite. `201` with the
/// token and link, shown only here. At most 1000 are usable at once.
pub async fn create_invite(
    State(state): State<AppState>,
    ctx: AdminCtx,
    Json(req): Json<CreateInvite>,
) -> Result<Response, Problem> {
    let target = req.handle.clone().unwrap_or_default();
    ctx.require(&state, AdminRole::Operator, "invite.create", &target)
        .await?;
    let detail = req
        .ttl_secs
        .map(|t| format!("ttl {t}s"))
        .unwrap_or_default();
    let entry = ctx.begin(&state, "invite.create", &target, &detail).await?;
    let _issuing = state.admins.invite_issue.lock().await;
    let outstanding = match state
        .accounts
        .invites
        .list_usable(ctx.now, MAX_OUTSTANDING_INVITES)
        .await
    {
        Ok(v) => v.len(),
        Err(e) => {
            entry.failed(SERVER_ERROR).await;
            return Err(internal(e));
        }
    };
    if outstanding >= MAX_OUTSTANDING_INVITES {
        entry.failed("too many outstanding invites").await;
        return Err(Problem::conflict().with_detail(format!(
            "{MAX_OUTSTANDING_INVITES} invites are outstanding; revoke some first"
        )));
    }
    let result = state
        .accounts
        .create_invite(
            req.handle.as_deref(),
            req.ttl_secs,
            &ctx.admin.username,
            ctx.now,
        )
        .await;
    match result {
        Ok(issued) => {
            let Some(id) = invites::token_hash(&issued.token) else {
                entry.failed(SERVER_ERROR).await;
                return Err(internal("issued an unrecognisable invite token"));
            };
            // The id, never the token, goes in the log.
            entry.ok(&format!("id {id}")).await;
            let created = InviteCreated {
                id,
                token: issued.token,
                link: issued.link,
                handle: issued.handle,
                expires_at: rfc3339(issued.expires_at),
            };
            Ok((StatusCode::CREATED, Json(created)).into_response())
        }
        Err(e) => {
            let why = match &e {
                InviteError::Store(_) => SERVER_ERROR.to_owned(),
                other => other.to_string(),
            };
            entry.failed(&why).await;
            Err(invite_problem(&e))
        }
    }
}

/// `DELETE /api/admin/invites/{id}` (operator): revoke an invite. `204`;
/// `409` if it was already used; `404` if no unexpired invite has that id.
pub async fn revoke_invite(
    State(state): State<AppState>,
    ctx: AdminCtx,
    Path(id): Path<String>,
) -> Result<StatusCode, Problem> {
    ctx.require(&state, AdminRole::Operator, "invite.revoke", &id)
        .await?;
    if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Problem::not_found().with_detail("no such invite"));
    }
    let entry = ctx.begin(&state, "invite.revoke", &id, "").await?;
    match state.accounts.invites.revoke(&id, ctx.now).await {
        Ok(Revoked::Revoked) => {
            entry.ok("").await;
            Ok(StatusCode::NO_CONTENT)
        }
        Ok(Revoked::Used) => {
            entry.failed("already used").await;
            Err(Problem::conflict().with_detail("that invite was already used"))
        }
        Ok(Revoked::Unknown) => {
            entry.failed("no such invite").await;
            Err(Problem::not_found().with_detail("no such invite"))
        }
        Err(e) => {
            entry.failed(SERVER_ERROR).await;
            Err(internal(e))
        }
    }
}

/// `GET /api/admin/audit` query: RFC 3339 bounds and an optional admin.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditQuery {
    #[serde(default)]
    since: Option<String>,
    #[serde(default)]
    until: Option<String>,
    #[serde(default)]
    admin: Option<String>,
}

/// `GET /api/admin/audit[?since=…&until=…&admin=…]`: entries in
/// `[since, until)`, newest first. Defaults to the last day; at most 31
/// days, and at most 5000 entries (narrow the window beyond that).
pub async fn audit(
    State(state): State<AppState>,
    ctx: AdminCtx,
    Query(query): Query<AuditQuery>,
) -> Result<Json<AuditList>, Problem> {
    ctx.require(&state, AdminRole::ReadOnly, "audit.list", "")
        .await?;
    let bad = |what: &str| Problem::bad_request().with_detail(format!("{what} must be RFC 3339"));
    let until = match &query.until {
        Some(u) => unix(u).ok_or_else(|| bad("until"))?,
        // Inclusive of this second.
        None => ctx.now + 1,
    };
    let since = match &query.since {
        Some(s) => unix(s).ok_or_else(|| bad("since"))?,
        None => until - DEFAULT_AUDIT_WINDOW_SECS,
    };
    if since >= until || until - since > MAX_AUDIT_WINDOW_SECS {
        return Err(Problem::bad_request()
            .with_detail("since must be before until, and the window at most 31 days"));
    }
    let q = audit::Query {
        since,
        until,
        admin: query.admin.filter(|a| !a.is_empty()),
    };
    match state.admins.audit.list(&q).await {
        Ok(entries) => Ok(Json(AuditList { entries })),
        Err(ListError::TooMany) => {
            Err(Problem::bad_request().with_detail(ListError::TooMany.to_string()))
        }
        Err(ListError::Db(e)) => Err(internal(e)),
    }
}
