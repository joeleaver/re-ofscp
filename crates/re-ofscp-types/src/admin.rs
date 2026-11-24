//! Admin API payloads (`/api/admin/*`, docs/decisions/0005).
//!
//! Admins are a separate identity system from OFSCP users: they are not
//! actors, are never federated and never sign OFSCP requests. These types
//! are not part of the OFSCP wire protocol; they use camelCase like the
//! rest of this provider's JSON (§2.5).

use serde::{Deserialize, Serialize};

/// Lifetime of an account invite when the issuer does not choose one: 7 days.
pub const DEFAULT_INVITE_TTL_SECS: i64 = 7 * 86_400;

/// Longest lifetime an issuer may choose for an account invite: 30 days.
pub const MAX_INVITE_TTL_SECS: i64 = 30 * 86_400;

/// Longest account search (`GET /api/admin/accounts?q=`), in bytes.
pub const MAX_ACCOUNT_QUERY_LEN: usize = 64;

/// Default audit-log window (`GET /api/admin/audit`): the last day.
pub const DEFAULT_AUDIT_WINDOW_SECS: i64 = 86_400;

/// Longest audit-log window one listing covers: 31 days.
pub const MAX_AUDIT_WINDOW_SECS: i64 = 31 * 86_400;

/// An admin's role. Each role can do everything the one before it can.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminRole {
    /// Reads accounts, invites and the audit log.
    ReadOnly,
    /// Also creates and disables accounts, and issues and revokes invites.
    Operator,
    /// Also manages admins.
    Owner,
}

impl AdminRole {
    /// The stored and wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::Operator => "operator",
            Self::Owner => "owner",
        }
    }

    /// Parse the stored spelling.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "read_only" => Some(Self::ReadOnly),
            "operator" => Some(Self::Operator),
            "owner" => Some(Self::Owner),
            _ => None,
        }
    }
}

/// Whether `name` is a valid admin username: `^[a-z0-9][a-z0-9_.-]{2,63}$`.
pub fn is_valid_admin_username(name: &str) -> bool {
    let b = name.as_bytes();
    (3..=64).contains(&b.len())
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"_.-".contains(c))
}

/// `POST /api/admin/setup`: create the first admin (an owner) with the
/// one-time setup token. Refused once any admin exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AdminSetupRequest {
    /// The value of the `ADMIN_SETUP_TOKEN` secret.
    pub setup_token: String,
    /// The new owner's username.
    pub username: String,
    /// The new owner's password.
    pub password: String,
}

/// `POST /api/admin/login`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AdminLoginRequest {
    /// Username.
    pub username: String,
    /// Password.
    pub password: String,
    /// The current TOTP code; required once the admin has enrolled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

/// The signed-in admin (`GET /api/admin/session`, and the login response).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminSessionInfo {
    /// Username.
    pub username: String,
    /// Role.
    pub role: AdminRole,
    /// Whether a TOTP second factor is enrolled.
    pub totp_enabled: bool,
    /// Whether the admin must choose a new password.
    pub password_change_required: bool,
    /// While true, only the session, TOTP enrollment, password change and
    /// logout endpoints are available: the admin must enroll TOTP and, if
    /// required, change their password first.
    pub restricted: bool,
    /// Send this as `X-CSRF-Token` on every state-changing request.
    pub csrf_token: String,
    /// RFC 3339 time at which the session ends, whatever the activity.
    pub expires_at: String,
}

/// `POST /api/admin/totp/enroll` response. The secret is shown once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpEnrollment {
    /// The shared secret, base32 without padding.
    pub secret: String,
    /// An `otpauth://totp/…` URI for authenticator apps.
    pub otpauth_uri: String,
}

/// `POST /api/admin/totp/confirm`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TotpConfirm {
    /// A current code from the authenticator.
    pub code: String,
}

/// `POST /api/admin/password`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PasswordChange {
    /// The current password.
    pub current_password: String,
    /// The new password.
    pub new_password: String,
}

/// An OFSCP account as admins see it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountView {
    /// Handle.
    pub handle: String,
    /// Display name.
    pub display_name: String,
    /// `"active"` or `"disabled"`.
    pub status: String,
    /// RFC 3339 creation time.
    pub created_at: String,
}

/// `GET /api/admin/accounts` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountList {
    /// Matching accounts, by handle.
    pub accounts: Vec<AccountView>,
    /// More accounts matched than were returned: refine the query.
    pub truncated: bool,
}

/// `POST /api/admin/accounts`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CreateAccount {
    /// Handle (§2.2.1).
    pub handle: String,
    /// Display name; the handle when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Initial password (§4.1.4).
    pub password: String,
}

/// `POST /api/admin/invites`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CreateInvite {
    /// Pin the invite to this handle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    /// Lifetime in seconds (default 7 days, at most 30 days).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<i64>,
}

/// A freshly issued invite. The token and link appear only here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteCreated {
    /// The invite's id (for listing and revoking; not the token).
    pub id: String,
    /// The token (`ai_…`).
    pub token: String,
    /// `https://{domain}/register?invite={token}`.
    pub link: String,
    /// The pinned handle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    /// RFC 3339 expiry.
    pub expires_at: String,
}

/// An outstanding invite (never its token).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteView {
    /// The invite's id.
    pub id: String,
    /// The pinned handle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    /// The admin who issued it.
    pub created_by: String,
    /// RFC 3339 issue time.
    pub created_at: String,
    /// RFC 3339 expiry.
    pub expires_at: String,
}

/// `GET /api/admin/invites` response: usable invites, newest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteList {
    /// The invites.
    pub invites: Vec<InviteView>,
}

/// An admin as owners see them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminView {
    /// Username.
    pub username: String,
    /// Role.
    pub role: AdminRole,
    /// `"active"` or `"disabled"`.
    pub status: String,
    /// Whether TOTP is enrolled.
    pub totp_enabled: bool,
    /// Whether the admin must choose a new password.
    pub password_change_required: bool,
    /// Who created this admin (`"setup"` for the first owner).
    pub created_by: String,
    /// RFC 3339 creation time.
    pub created_at: String,
}

/// `GET /api/admin/admins` response, by username.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminList {
    /// The admins.
    pub admins: Vec<AdminView>,
}

/// `POST /api/admin/admins`: the new admin must change this password and
/// enroll TOTP at first sign-in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CreateAdmin {
    /// Username.
    pub username: String,
    /// Initial password.
    pub password: String,
    /// Role.
    pub role: AdminRole,
}

/// `PATCH /api/admin/admins/{username}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UpdateAdmin {
    /// New role.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<AdminRole>,
    /// `true` disables the admin and ends their sessions. Disabling is
    /// final: there is no re-enabling (create a new admin instead).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,
}

/// One audit-log entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEntry {
    /// RFC 3339 time.
    pub at: String,
    /// The admin who acted (or tried to).
    pub admin: String,
    /// What they did, e.g. `"account.disable"`.
    pub action: String,
    /// What it was done to, e.g. a handle; empty when nothing.
    pub target: String,
    /// `"ok"`, `"denied"`, `"failed"`, or `"pending"` if the outcome was
    /// never recorded (the server failed mid-action).
    pub outcome: String,
    /// The client address the request came from (rate-limit key form).
    pub source: String,
    /// Extra context (never secrets).
    pub detail: String,
}

/// `GET /api/admin/audit` response, newest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditList {
    /// The entries.
    pub entries: Vec<AuditEntry>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usernames() {
        for ok in ["joe", "j.leaver", "ops-1", "a_b", "1st"] {
            assert!(is_valid_admin_username(ok), "{ok}");
        }
        for bad in ["jo", "Joe", ".joe", "-joe", "joe@x", "", &"a".repeat(65)] {
            assert!(!is_valid_admin_username(bad), "{bad}");
        }
    }

    #[test]
    fn roles_order_and_spell() {
        assert!(AdminRole::Owner > AdminRole::Operator);
        assert!(AdminRole::Operator > AdminRole::ReadOnly);
        for r in [AdminRole::ReadOnly, AdminRole::Operator, AdminRole::Owner] {
            assert_eq!(AdminRole::parse(r.as_str()), Some(r));
            assert_eq!(
                serde_json::to_value(r).unwrap(),
                serde_json::Value::String(r.as_str().to_owned())
            );
        }
        assert_eq!(AdminRole::parse("admin"), None);
    }
}
