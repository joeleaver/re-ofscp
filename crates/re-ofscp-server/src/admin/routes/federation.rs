//! The federation allow/deny policy, for admins (spec §8 *Authorization*,
//! docs/decisions/0008).
//!
//! Reading it needs `read_only`; adding and removing rules `operator` (a
//! deny rule is incident response); changing the mode `owner`, since one
//! switch to `allowlist` cuts federation with everyone not listed.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use re_ofscp_types::admin::AdminRole;
use re_ofscp_types::federation::{
    AddFederationRule, FederationPolicyView, FederationRuleView, SetFederationMode,
};

use super::{SERVER_ERROR, internal};
use crate::AppState;
use crate::admin::auth::AdminCtx;
use crate::federation::store::PolicyError;
use crate::federation::{Rule, RuleSet, UNKNOWN_RETRY_SECS};
use crate::problem::Problem;
use crate::timefmt::rfc3339;

fn rule_view(r: &Rule) -> FederationRuleView {
    FederationRuleView {
        id: r.id.clone(),
        list: r.list,
        scope: r.scope,
        value: r.value.clone(),
        note: r.note.clone(),
        created_by: r.created_by.clone(),
        created_at: rfc3339(r.created_at),
    }
}

fn list_view(set: &RuleSet) -> Vec<FederationRuleView> {
    set.sorted().into_iter().map(rule_view).collect()
}

fn not_loaded() -> Problem {
    Problem::service_unavailable(UNKNOWN_RETRY_SECS)
        .with_detail("the federation policy is still loading; retry shortly")
}

fn policy_problem(e: &PolicyError) -> Problem {
    match e {
        PolicyError::Invalid(d) => Problem::bad_request().with_detail(d.clone()),
        PolicyError::Duplicate | PolicyError::TooMany => {
            Problem::conflict().with_detail(e.to_string())
        }
        PolicyError::NotFound => Problem::not_found().with_detail(e.to_string()),
        PolicyError::NotLoaded => not_loaded(),
        PolicyError::Db(_) => internal(e),
    }
}

/// The audit detail for a failure: database messages can echo query text.
fn policy_why(e: &PolicyError) -> String {
    match e {
        PolicyError::Db(_) => SERVER_ERROR.to_owned(),
        other => other.to_string(),
    }
}

/// The audit target of a rule: `deny domain evil.example`.
fn rule_target(r: &Rule) -> String {
    format!("{} {} {}", r.list.as_str(), r.scope.as_str(), r.value)
}

/// `GET /api/admin/federation`: the mode and both lists.
pub async fn get_policy(
    State(state): State<AppState>,
    ctx: AdminCtx,
) -> Result<Json<FederationPolicyView>, Problem> {
    ctx.require(&state, AdminRole::ReadOnly, "federation.get", "")
        .await?;
    let snapshot = state
        .federation
        .policy()
        .snapshot()
        .ok_or_else(not_loaded)?;
    Ok(Json(FederationPolicyView {
        mode: snapshot.mode,
        mode_set_by: snapshot.mode_set.as_ref().map(|(by, _)| by.clone()),
        mode_set_at: snapshot.mode_set.as_ref().map(|(_, at)| rfc3339(*at)),
        allow: list_view(&snapshot.allow),
        deny: list_view(&snapshot.deny),
    }))
}

/// `PUT /api/admin/federation/mode` (owner). `204`.
pub async fn set_mode(
    State(state): State<AppState>,
    ctx: AdminCtx,
    Json(req): Json<SetFederationMode>,
) -> Result<StatusCode, Problem> {
    let mode = req.mode.as_str();
    ctx.require(&state, AdminRole::Owner, "federation.mode", mode)
        .await?;
    let entry = ctx.begin(&state, "federation.mode", mode, "").await?;
    match state
        .federation
        .set_mode(req.mode, &ctx.admin.username, ctx.now)
        .await
    {
        Ok(previous) => {
            entry.ok(&format!("was {}", previous.as_str())).await;
            Ok(StatusCode::NO_CONTENT)
        }
        Err(e) => {
            entry.failed(&policy_why(&e)).await;
            Err(policy_problem(&e))
        }
    }
}

/// `POST /api/admin/federation/rules` (operator). `201` with the rule.
pub async fn add_rule(
    State(state): State<AppState>,
    ctx: AdminCtx,
    Json(req): Json<AddFederationRule>,
) -> Result<Response, Problem> {
    let target = format!(
        "{} {} {}",
        req.list.as_str(),
        req.scope.as_str(),
        req.value.trim()
    );
    ctx.require(&state, AdminRole::Operator, "federation.rule_add", &target)
        .await?;
    let note = req.note.as_deref().unwrap_or("").trim().to_owned();
    let entry = ctx
        .begin(&state, "federation.rule_add", &target, &note)
        .await?;
    match state
        .federation
        .add_rule(&req, &ctx.admin.username, ctx.now)
        .await
    {
        Ok(rule) => {
            entry
                .ok(&format!("id {} ({})", rule.id, rule_target(&rule)))
                .await;
            Ok((StatusCode::CREATED, Json(rule_view(&rule))).into_response())
        }
        Err(e) => {
            entry.failed(&policy_why(&e)).await;
            Err(policy_problem(&e))
        }
    }
}

/// `DELETE /api/admin/federation/rules/{id}` (operator). `204`.
pub async fn remove_rule(
    State(state): State<AppState>,
    ctx: AdminCtx,
    Path(id): Path<String>,
) -> Result<StatusCode, Problem> {
    ctx.require(&state, AdminRole::Operator, "federation.rule_remove", &id)
        .await?;
    let entry = ctx.begin(&state, "federation.rule_remove", &id, "").await?;
    match state.federation.remove_rule(&id).await {
        Ok(rule) => {
            entry.ok(&rule_target(&rule)).await;
            Ok(StatusCode::NO_CONTENT)
        }
        Err(e) => {
            entry.failed(&policy_why(&e)).await;
            Err(policy_problem(&e))
        }
    }
}
