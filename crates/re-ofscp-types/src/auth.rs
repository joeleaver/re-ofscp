//! Authentication and device-key payloads (spec §4.1–§4.7).
//!
//! These use snake_case field names on the wire, the deliberate exception in
//! §2.5 (OAuth conventions), except the login and registration requests,
//! whose fields are single words.

use serde::{Deserialize, Serialize};

/// `POST /api/auth/login` request (§4.1.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginRequest {
    /// The account's handle (§2.2.1).
    pub handle: String,
    /// The account's password.
    pub password: String,
}

/// `POST /api/auth/register` request (§4.1.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationRequest {
    /// The handle to register (§2.2.1).
    pub handle: String,
    /// The new account's password (§4.1.4).
    pub password: String,
    /// Address for password recovery (§4.1.3).
    #[serde(
        default,
        rename = "recoveryEmail",
        skip_serializing_if = "Option::is_none"
    )]
    pub recovery_email: Option<String>,
    /// Account invite, for a provider whose registration mode is
    /// [`RegistrationMode::Invite`].
    #[serde(
        default,
        rename = "inviteToken",
        skip_serializing_if = "Option::is_none"
    )]
    pub invite_token: Option<String>,
}

/// Who may register on a provider (§4.1.1), advertised in discovery as
/// `provider.authentication.registration`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RegistrationMode {
    /// Anyone may register.
    Open,
    /// Registration needs a provider-issued account invite.
    Invite,
    /// No self-registration.
    Closed,
}

impl RegistrationMode {
    /// The wire value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Invite => "invite",
            Self::Closed => "closed",
        }
    }
}

/// The bootstrap response to registration and login (§4.1, §4.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapResponse {
    /// Opaque, high-entropy, single-use token for `POST /api/auth/device-keys`.
    pub bootstrap_token: String,
    /// Always `"bootstrap"`.
    pub token_type: String,
    /// Lifetime in seconds.
    pub expires_in: u64,
}

/// `POST /api/auth/device-keys` request (§4.3.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceKeyRegistration {
    /// Base64 Ed25519 public key (32 bytes).
    pub public_key: String,
    /// Key algorithm; only `"Ed25519"` exists in v0.1 (§4.3.3). Absent means
    /// Ed25519.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    /// Human-readable device description.
    pub device_name: String,
}

/// `POST /api/auth/device-keys` response (§4.3.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceKeyCreated {
    /// The provider-assigned key id.
    pub key_id: String,
    /// RFC 3339 creation time.
    pub created_at: String,
}

/// One of the caller's own keys (§4.7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceKeyInfo {
    /// Key id.
    pub key_id: String,
    /// `"Ed25519"`.
    pub algorithm: String,
    /// Base64 public key.
    pub public_key: String,
    /// Device description.
    pub device_name: String,
    /// RFC 3339 creation time.
    pub created_at: String,
}

/// `GET /api/auth/device-keys` response (§4.7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceKeysResponse {
    /// The caller's active keys.
    pub keys: Vec<DeviceKeyInfo>,
}

/// One public key at the keys endpoint (§4.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey {
    /// Key id.
    pub key_id: String,
    /// `"Ed25519"`.
    pub algorithm: String,
    /// Base64 public key.
    pub public_key: String,
    /// RFC 3339 creation time.
    pub created_at: String,
}

/// `GET /.well-known/ofscp/users/{handle}/keys` response (§4.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserKeysResponse {
    /// The canonical actor.
    pub actor: String,
    /// Active (non-revoked) keys.
    pub keys: Vec<PublicKey>,
    /// RFC 3339: verifiers may cache until then.
    pub cache_until: String,
}

/// The only algorithm v0.1 defines (§4.3.3).
pub const ED25519: &str = "Ed25519";

/// `token_type` of a bootstrap response.
pub const BOOTSTRAP_TOKEN_TYPE: &str = "bootstrap";
