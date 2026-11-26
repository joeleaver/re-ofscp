//! Sign-in, device keys and the keys endpoint (spec §4.1–§4.7).
//!
//! These payloads use snake_case, the deliberate exception of §2.5 (OAuth
//! conventions), except the login and registration requests, whose fields
//! are single words or camelCase.
//!
//! A `public_key` is kept as the string received; decode it with
//! [`crate::signing::decode_public_key`]. It is the raw 32-byte key in
//! padded standard base64, never a DER `SubjectPublicKeyInfo` (§4.3.2,
//! lost-conn/ofscp#28); a key that is not is unusable.
//!
//! `Debug` never shows a password or a bearer token.

use core::fmt;

use serde::{Deserialize, Serialize};

use super::{KeyAlgorithm, Timestamp};
use crate::Actor;

/// Minimum password length in bytes (§4.1.4 RECOMMENDED).
pub const MIN_PASSWORD_LEN: usize = 8;

/// Maximum password length in bytes, bounding the work an attacker can ask
/// for and the size of the request.
pub const MAX_PASSWORD_LEN: usize = 1024;

/// The only algorithm v0.1 defines (§4.3.3).
pub const ED25519: &str = "Ed25519";

/// `token_type` of a bootstrap response.
pub const BOOTSTRAP_TOKEN_TYPE: &str = "bootstrap";

/// Shown in place of a secret by `Debug`.
pub(crate) const REDACTED: &str = "<redacted>";

/// `POST /api/auth/login` (§4.1.2).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginRequest {
    /// The account's handle, without the domain (§2.2.1).
    pub handle: String,
    /// The account's password.
    pub password: String,
}

/// `POST /api/auth/register` (§4.1.1).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationRequest {
    /// The handle to register (§2.2.1).
    pub handle: String,
    /// The new account's password (§4.1.4).
    pub password: String,
    /// An address for password recovery (§4.1.3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_email: Option<String>,
    /// An account invite, for a provider whose registration mode is
    /// [`RegistrationMode::Invite`](super::RegistrationMode::Invite).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_token: Option<String>,
}

impl fmt::Debug for LoginRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginRequest")
            .field("handle", &self.handle)
            .field("password", &REDACTED)
            .finish()
    }
}

impl fmt::Debug for RegistrationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegistrationRequest")
            .field("handle", &self.handle)
            .field("password", &REDACTED)
            .field("recovery_email", &self.recovery_email)
            .field(
                "invite_token",
                &self.invite_token.as_ref().map(|_| REDACTED),
            )
            .finish()
    }
}

/// The answer to login or registration: a one-use token for registering a
/// device key (§4.2).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapResponse {
    /// Opaque, high-entropy, single-use token for
    /// `POST /api/auth/device-keys`, sent as `Authorization: Bearer`.
    pub bootstrap_token: String,
    /// Always [`BOOTSTRAP_TOKEN_TYPE`].
    pub token_type: String,
    /// Seconds until the token expires (300 in v0.1).
    pub expires_in: u64,
}

impl fmt::Debug for BootstrapResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BootstrapResponse")
            .field("bootstrap_token", &REDACTED)
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

/// `POST /api/auth/device-keys` (§4.3.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceKeyRegistration {
    /// The device's public key, base64 (see the module docs).
    pub public_key: String,
    /// Always Ed25519 in v0.1 (§4.3.3). Absent means Ed25519.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<KeyAlgorithm>,
    /// A name the person recognises, such as "Firefox on Linux".
    pub device_name: String,
}

/// The answer to a device-key registration (§4.3.1,
/// `device-key-response`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceKeyCreated {
    /// The key's id, sent as `X-OFSCP-Key-ID` from now on.
    pub key_id: String,
    /// When the key was registered.
    pub created_at: Timestamp,
}

/// One of the caller's own device keys, as `GET /api/auth/device-keys`
/// lists it (§4.7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceKeyInfo {
    /// The key's id.
    pub key_id: String,
    /// The key's algorithm.
    pub algorithm: KeyAlgorithm,
    /// The public key, base64.
    pub public_key: String,
    /// The name given when it was registered.
    pub device_name: String,
    /// When it was registered.
    pub created_at: Timestamp,
}

/// `GET /api/auth/device-keys` (§4.7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceKeysResponse {
    /// The caller's registered, unrevoked keys.
    pub keys: Vec<DeviceKeyInfo>,
}

/// A user's published key, as the keys endpoint gives it (§4.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey {
    /// The key's id.
    pub key_id: String,
    /// The key's algorithm.
    pub algorithm: KeyAlgorithm,
    /// The public key, base64.
    pub public_key: String,
    /// When it was registered.
    pub created_at: Timestamp,
}

/// `GET /.well-known/ofscp/users/{handle}/keys` (§4.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserKeysResponse {
    /// Whose keys these are, canonical.
    pub actor: Actor,
    /// The keys currently valid (not revoked).
    pub keys: Vec<PublicKey>,
    /// Until when a verifier may cache the answer.
    pub cache_until: Timestamp,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_stay_out_of_debug() {
        let login = LoginRequest {
            handle: "alice".into(),
            password: "hunter22".into(),
        };
        let shown = format!("{login:?}");
        assert!(shown.contains("alice") && !shown.contains("hunter22"));

        let reg = RegistrationRequest {
            handle: "alice".into(),
            password: "hunter22".into(),
            recovery_email: None,
            invite_token: Some("inv_secret".into()),
        };
        let shown = format!("{reg:?}");
        assert!(!shown.contains("hunter22") && !shown.contains("inv_secret"));

        let token = BootstrapResponse {
            bootstrap_token: "tok_secret".into(),
            token_type: BOOTSTRAP_TOKEN_TYPE.into(),
            expires_in: 300,
        };
        assert!(!format!("{token:?}").contains("tok_secret"));
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let login: LoginRequest =
            serde_json::from_str(r#"{"handle":"a","password":"p","future":1}"#).unwrap();
        assert_eq!(login.handle, "a");
    }
}
