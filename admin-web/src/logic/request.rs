//! The admin API's requests (`/api/admin/*`, the route table in
//! `crates/re-ofscp-server/src/admin/routes/mod.rs`), built as plain
//! values. `crate::api` sends them.

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use re_ofscp_types::admin::{
    AdminLoginRequest, CreateAccount, CreateAdmin, CreateInvite, PasswordChange, TotpConfirm,
    UpdateAdmin,
};
use re_ofscp_types::federation::{AddFederationRule, SetFederationMode};
use serde::Serialize;

use super::problem::ApiError;

/// Where the admin API lives (same origin as the console).
pub const API_BASE: &str = "/api/admin";

/// The header carrying the session's CSRF token on every mutation.
pub const CSRF_HEADER: &str = "X-CSRF-Token";

/// Everything but the RFC 3986 unreserved characters is escaped.
const COMPONENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// An HTTP method the admin API uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// Reads.
    Get,
    /// Actions and creation.
    Post,
    /// Admin updates.
    Patch,
    /// Setting a value (the federation mode).
    Put,
    /// Invite revocation.
    Delete,
}

/// One admin API request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiCall {
    /// The method.
    pub method: Method,
    /// The URL, relative to the console's origin.
    pub url: String,
    /// A JSON body.
    pub body: Option<String>,
}

impl ApiCall {
    fn new(method: Method, path: &str) -> Self {
        Self {
            method,
            url: format!("{API_BASE}{path}"),
            body: None,
        }
    }

    fn with_json(mut self, body: &impl Serialize) -> Result<Self, ApiError> {
        let json = serde_json::to_string(body).map_err(|e| ApiError::Unreadable(e.to_string()))?;
        self.body = Some(json);
        Ok(self)
    }

    /// Whether this request changes state, and so needs `X-CSRF-Token`.
    pub fn is_mutation(&self) -> bool {
        self.method != Method::Get
    }
}

/// `segment` escaped for use as one path segment.
fn seg(segment: &str) -> String {
    utf8_percent_encode(segment, COMPONENT).to_string()
}

/// `?k=v&…` for the pairs whose value is present, or nothing.
fn query(pairs: &[(&str, Option<&str>)]) -> String {
    let parts: Vec<String> = pairs
        .iter()
        .filter_map(|(k, v)| v.map(|v| format!("{k}={}", utf8_percent_encode(v, COMPONENT))))
        .collect();
    if parts.is_empty() {
        String::new()
    } else {
        format!("?{}", parts.join("&"))
    }
}

/// `POST /login`.
pub fn login(req: &AdminLoginRequest) -> Result<ApiCall, ApiError> {
    ApiCall::new(Method::Post, "/login").with_json(req)
}

/// `POST /logout`.
pub fn logout() -> ApiCall {
    ApiCall::new(Method::Post, "/logout")
}

/// `GET /session`.
pub fn session() -> ApiCall {
    ApiCall::new(Method::Get, "/session")
}

/// `POST /totp/enroll`.
pub fn totp_enroll() -> ApiCall {
    ApiCall::new(Method::Post, "/totp/enroll")
}

/// `POST /totp/confirm`.
pub fn totp_confirm(req: &TotpConfirm) -> Result<ApiCall, ApiError> {
    ApiCall::new(Method::Post, "/totp/confirm").with_json(req)
}

/// `POST /password`.
pub fn change_password(req: &PasswordChange) -> Result<ApiCall, ApiError> {
    ApiCall::new(Method::Post, "/password").with_json(req)
}

/// `GET /accounts[?q=…]`.
pub fn list_accounts(q: Option<&str>) -> ApiCall {
    ApiCall::new(Method::Get, &format!("/accounts{}", query(&[("q", q)])))
}

/// `GET /accounts/{handle}`.
pub fn get_account(handle: &str) -> ApiCall {
    ApiCall::new(Method::Get, &format!("/accounts/{}", seg(handle)))
}

/// `POST /accounts`.
pub fn create_account(req: &CreateAccount) -> Result<ApiCall, ApiError> {
    ApiCall::new(Method::Post, "/accounts").with_json(req)
}

/// `POST /accounts/{handle}/disable`.
pub fn disable_account(handle: &str) -> ApiCall {
    ApiCall::new(Method::Post, &format!("/accounts/{}/disable", seg(handle)))
}

/// `GET /invites`.
pub fn list_invites() -> ApiCall {
    ApiCall::new(Method::Get, "/invites")
}

/// `POST /invites`.
pub fn create_invite(req: &CreateInvite) -> Result<ApiCall, ApiError> {
    ApiCall::new(Method::Post, "/invites").with_json(req)
}

/// `DELETE /invites/{id}`.
pub fn revoke_invite(id: &str) -> ApiCall {
    ApiCall::new(Method::Delete, &format!("/invites/{}", seg(id)))
}

/// The audit-log listing's filter: RFC 3339 bounds and an optional admin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditFilter {
    /// Start of the window (inclusive).
    pub since: String,
    /// End of the window (exclusive).
    pub until: String,
    /// Only this admin's entries.
    pub admin: Option<String>,
}

/// `GET /audit?since=…&until=…[&admin=…]`.
pub fn audit(filter: &AuditFilter) -> ApiCall {
    let q = query(&[
        ("since", Some(&filter.since)),
        ("until", Some(&filter.until)),
        ("admin", filter.admin.as_deref()),
    ]);
    ApiCall::new(Method::Get, &format!("/audit{q}"))
}

/// `GET /admins`.
pub fn list_admins() -> ApiCall {
    ApiCall::new(Method::Get, "/admins")
}

/// `POST /admins`.
pub fn create_admin(req: &CreateAdmin) -> Result<ApiCall, ApiError> {
    ApiCall::new(Method::Post, "/admins").with_json(req)
}

/// `PATCH /admins/{username}`.
pub fn update_admin(username: &str, req: &UpdateAdmin) -> Result<ApiCall, ApiError> {
    ApiCall::new(Method::Patch, &format!("/admins/{}", seg(username))).with_json(req)
}

/// `POST /admins/{username}/totp/reset`.
pub fn reset_totp(username: &str) -> ApiCall {
    ApiCall::new(
        Method::Post,
        &format!("/admins/{}/totp/reset", seg(username)),
    )
}

/// `GET /federation`.
pub fn get_federation() -> ApiCall {
    ApiCall::new(Method::Get, "/federation")
}

/// `PUT /federation/mode`.
pub fn set_federation_mode(req: &SetFederationMode) -> Result<ApiCall, ApiError> {
    ApiCall::new(Method::Put, "/federation/mode").with_json(req)
}

/// `POST /federation/rules`.
pub fn add_federation_rule(req: &AddFederationRule) -> Result<ApiCall, ApiError> {
    ApiCall::new(Method::Post, "/federation/rules").with_json(req)
}

/// `DELETE /federation/rules/{id}`.
pub fn remove_federation_rule(id: &str) -> ApiCall {
    ApiCall::new(Method::Delete, &format!("/federation/rules/{}", seg(id)))
}

#[cfg(test)]
mod tests {
    use re_ofscp_types::admin::AdminRole;

    use super::*;

    #[test]
    fn reads_are_gets_without_csrf() {
        for call in [
            session(),
            list_accounts(None),
            list_invites(),
            list_admins(),
            get_federation(),
        ] {
            assert_eq!(call.method, Method::Get);
            assert!(!call.is_mutation());
            assert!(call.body.is_none());
        }
        assert_eq!(session().url, "/api/admin/session");
    }

    #[test]
    fn mutations_need_csrf() {
        for call in [
            logout(),
            totp_enroll(),
            disable_account("alice"),
            revoke_invite("x"),
            reset_totp("ops"),
            remove_federation_rule("fr_1"),
        ] {
            assert!(call.is_mutation(), "{call:?}");
        }
        assert_eq!(revoke_invite("x").method, Method::Delete);
        let mode = SetFederationMode {
            mode: re_ofscp_types::federation::FederationMode::Denylist,
        };
        let call = set_federation_mode(&mode).unwrap();
        assert_eq!(call.method, Method::Put);
        assert!(call.is_mutation());
        assert_eq!(call.url, "/api/admin/federation/mode");
        assert_eq!(call.body.as_deref(), Some(r#"{"mode":"denylist"}"#));
        assert_eq!(
            remove_federation_rule("fr/../x").url,
            "/api/admin/federation/rules/fr%2F..%2Fx"
        );
    }

    #[test]
    fn query_values_and_path_segments_are_escaped() {
        assert_eq!(list_accounts(None).url, "/api/admin/accounts");
        assert_eq!(
            list_accounts(Some("a b&c=d/é")).url,
            "/api/admin/accounts?q=a%20b%26c%3Dd%2F%C3%A9"
        );
        assert_eq!(get_account("../x?y").url, "/api/admin/accounts/..%2Fx%3Fy");
        assert_eq!(
            disable_account("al-ice_1").url,
            "/api/admin/accounts/al-ice_1/disable"
        );
    }

    #[test]
    fn audit_query_includes_the_window_and_optional_admin() {
        let mut f = AuditFilter {
            since: "2026-11-23T10:00:00Z".into(),
            until: "2026-11-24T10:00:00Z".into(),
            admin: None,
        };
        assert_eq!(
            audit(&f).url,
            "/api/admin/audit?since=2026-11-23T10%3A00%3A00Z&until=2026-11-24T10%3A00%3A00Z"
        );
        f.admin = Some("ops".into());
        assert!(audit(&f).url.ends_with("&admin=ops"));
    }

    #[test]
    fn bodies_use_the_shared_wire_types() {
        let call = login(&AdminLoginRequest {
            username: "joe".into(),
            password: "pw".into(),
            code: None,
        })
        .unwrap();
        assert_eq!(
            call.body.as_deref(),
            Some(r#"{"username":"joe","password":"pw"}"#)
        );
        let call = update_admin(
            "ops",
            &UpdateAdmin {
                role: Some(AdminRole::ReadOnly),
                disabled: None,
            },
        )
        .unwrap();
        assert_eq!(call.method, Method::Patch);
        assert_eq!(call.url, "/api/admin/admins/ops");
        assert_eq!(call.body.as_deref(), Some(r#"{"role":"read_only"}"#));
    }
}
