//! The provider discovery document, `GET /.well-known/ofscp-provider`
//! (§3.1), and its provider signing keys (§8.1).
//!
//! Field casing follows the spec exactly: the document is camelCase except
//! `provider.authentication` and the `provider.publicKeys` entries, which are
//! snake_case (§2.4).

use serde::{Deserialize, Serialize};

use crate::auth::RegistrationMode;

/// The whole discovery document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryDocument {
    /// Who the provider is and how to authenticate with it.
    pub provider: ProviderInfo,
    /// What it supports.
    pub capabilities: Capabilities,
}

/// `provider` in the discovery document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderInfo {
    /// The provider's canonical authority (§2.2), the value it signs as.
    /// Readers reject a document whose domain is not the authority they
    /// fetched it from (§3.1).
    pub domain: String,
    /// The OFSCP version implemented (SemVer).
    pub protocol_version: String,
    /// The implementation's name and version.
    pub software: Software,
    /// How to reach the operator (e.g. a `mailto:` URI).
    pub contact: String,
    /// Login and registration (§4.1).
    pub authentication: Authentication,
    /// Provider signing keys (§8.1); at least one.
    pub public_keys: Vec<ProviderPublicKey>,
}

/// `provider.software`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Software {
    /// Implementation name.
    pub name: String,
    /// Implementation version.
    pub version: String,
}

/// `provider.authentication` (snake_case on the wire).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authentication {
    /// `https://{domain}/api/auth/login`.
    pub login_endpoint: String,
    /// `https://{domain}/api/auth/register`; a closed provider omits it
    /// (§4.1.1 SHOULD).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,
    /// Who may register (§4.1.1). Absent means `open`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration: Option<RegistrationMode>,
}

/// One `provider.publicKeys` entry (snake_case on the wire, §2.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderPublicKey {
    /// The id provider-signed requests name in `X-OFSCP-Key-ID`.
    pub key_id: String,
    /// `"Ed25519"`.
    pub algorithm: String,
    /// Base64 (standard alphabet) Ed25519 public key.
    pub public_key: String,
    /// RFC 3339 creation time, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

/// `capabilities` in the discovery document. Every member is optional on
/// the wire; this provider states each one explicitly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Capabilities {
    /// Message types accepted (`memo`, `article`, `message`, `reaction`).
    pub message_types: Vec<String>,
    /// Access tiers supported (§11).
    pub tiers: Vec<String>,
    /// Cross-provider real-time delivery (§8.5).
    pub federation: FederationCapabilities,
    /// Optional discovery features (§8.6, §11.2).
    pub discovery: DiscoveryCapabilities,
}

/// `capabilities.federation`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FederationCapabilities {
    /// `direct-ws` or `none`.
    pub realtime_delivery: String,
}

/// `capabilities.discovery`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryCapabilities {
    /// Whether `GET /api/providers` shares the known-providers list (§8.6).
    pub shares_known_providers: bool,
    /// Whether `GET /api/discover` offers a discovery feed (§11.2).
    pub discover_feed: bool,
}
