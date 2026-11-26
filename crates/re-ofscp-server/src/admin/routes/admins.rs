//! Managing admins (owners only).

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use re_ofscp_types::admin::{AdminList, AdminRole, AdminView, CreateAdmin, UpdateAdmin};

use super::{internal, manage_problem, manage_why};
use crate::AppState;
use crate::admin::Admin;
use crate::admin::auth::AdminCtx;
use crate::problem::Problem;

/// An admin as the API shows them (never a hash or secret).
pub fn view(a: &Admin) -> AdminView {
    AdminView {
        username: a.username.clone(),
        role: a.role,
        status: a.status.clone(),
        totp_enabled: a.totp_enabled(),
        password_change_required: a.password_change_required,
        created_by: a.created_by.clone(),
        created_at: a.created_at.clone(),
    }
}

/// `GET /api/admin/admins` (owner): every admin, by username.
pub async fn list_admins(
    State(state): State<AppState>,
    ctx: AdminCtx,
) -> Result<Json<AdminList>, Problem> {
    ctx.require(&state, AdminRole::Owner, "admin.list", "")
        .await?;
    let admins = state.admins.store.list().await.map_err(internal)?;
    Ok(Json(AdminList {
        admins: admins.iter().map(view).collect(),
    }))
}

/// `POST /api/admin/admins` (owner): create an admin, who must change the
/// password and enroll TOTP at first sign-in. `201`.
pub async fn create_admin(
    State(state): State<AppState>,
    ctx: AdminCtx,
    Json(req): Json<CreateAdmin>,
) -> Result<Response, Problem> {
    ctx.require(&state, AdminRole::Owner, "admin.create", &req.username)
        .await?;
    let entry = ctx
        .begin(
            &state,
            "admin.create",
            &req.username,
            &format!("role {}", req.role.as_str()),
        )
        .await?;
    match state
        .admins
        .create_admin(&ctx.admin, &req.username, &req.password, req.role, ctx.now)
        .await
    {
        Ok(a) => {
            entry.ok("").await;
            Ok((StatusCode::CREATED, Json(view(&a))).into_response())
        }
        Err(e) => {
            entry.failed(&manage_why(&e)).await;
            Err(manage_problem(&e))
        }
    }
}

/// `PATCH /api/admin/admins/{username}` (owner): change the role and/or
/// disable (final; ends their sessions). `200` with the admin. There is
/// always at least one active owner.
pub async fn update_admin(
    State(state): State<AppState>,
    ctx: AdminCtx,
    Path(username): Path<String>,
    Json(req): Json<UpdateAdmin>,
) -> Result<Json<AdminView>, Problem> {
    ctx.require(&state, AdminRole::Owner, "admin.update", &username)
        .await?;
    let disable = match req.disabled {
        None => false,
        Some(true) => true,
        Some(false) => {
            return Err(Problem::bad_request()
                .with_detail("disabling is final; create a new admin instead"));
        }
    };
    if req.role.is_none() && !disable {
        return Err(Problem::bad_request().with_detail("nothing to change"));
    }
    let mut detail = Vec::new();
    if let Some(r) = req.role {
        detail.push(format!("role {}", r.as_str()));
    }
    if disable {
        detail.push("disable".to_owned());
    }
    let entry = ctx
        .begin(&state, "admin.update", &username, &detail.join(", "))
        .await?;
    if let Err(e) = state
        .admins
        .update_admin(&username, req.role, disable)
        .await
    {
        entry.failed(&manage_why(&e)).await;
        return Err(manage_problem(&e));
    }
    entry.ok("").await;
    let updated = state
        .admins
        .store
        .find(&username)
        .await
        .map_err(internal)?
        .ok_or_else(|| internal("an updated admin vanished"))?;
    Ok(Json(view(&updated)))
}

/// `POST /api/admin/admins/{username}/totp/reset` (owner): remove another
/// admin's TOTP enrollment and end their sessions. `204`.
pub async fn reset_totp(
    State(state): State<AppState>,
    ctx: AdminCtx,
    Path(username): Path<String>,
) -> Result<StatusCode, Problem> {
    ctx.require(&state, AdminRole::Owner, "admin.totp_reset", &username)
        .await?;
    let entry = ctx.begin(&state, "admin.totp_reset", &username, "").await?;
    match state
        .admins
        .reset_totp(&ctx.admin, &username, ctx.now)
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
