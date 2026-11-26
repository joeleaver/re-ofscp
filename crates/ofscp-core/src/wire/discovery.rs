//! The provider discovery document, `GET /.well-known/ofscp-provider`
//! (§3.1), and its provider signing keys (§8.1).
//!
//! Field casing follows the spec exactly: the document is camelCase except
//! `provider.authentication` and the `provider.publicKeys` entries, which
//! are snake_case (§2.4).

use serde::{Deserialize, Serialize};

use serde_json::{Map, Value};

use super::{KeyAlgorithm, MessageType, Tier, Timestamp, open_enum};
use crate::Authority;

/// `GET https://{domain}/.well-known/ofscp-provider` (§3.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryDocument {
    /// Who the provider is and how to sign in.
    pub provider: ProviderInfo,
    /// What it supports.
    pub capabilities: Capabilities,
    /// Endpoint overrides, by name. The standard base path is `/api` (§3.2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoints: Option<Map<String, Value>>,
}

/// The `provider` block of discovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderInfo {
    /// The provider's canonical authority (§2.2), the value it signs as.
    /// Readers reject a document whose domain is not the authority they
    /// fetched it from (§3.1).
    pub domain: Authority,
    /// The protocol version it speaks (SemVer, §2.1).
    pub protocol_version: String,
    /// The server software.
    pub software: Software,
    /// How to reach its operator (often a `mailto:`).
    pub contact: String,
    /// Where to sign in and register.
    pub authentication: Authentication,
    /// The provider's own signing keys (§8.1).
    pub public_keys: Vec<ProviderPublicKey>,
}

/// Server software name and version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Software {
    /// Its name.
    pub name: String,
    /// Its version.
    pub version: String,
}

/// Sign-in endpoints and the registration mode (§4.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authentication {
    /// The login endpoint (HTTPS).
    pub login_endpoint: String,
    /// The registration endpoint (HTTPS), if registration is offered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,
    /// Who may register (§4.1.1). Absent means `open`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration: Option<RegistrationMode>,
}

open_enum! {
    /// Who may register on a provider (§4.1.1).
    pub enum RegistrationMode {
        /// Anyone.
        Open = "open",
        /// Only with an account invite.
        Invite = "invite",
        /// Nobody, by themselves.
        Closed = "closed",
    }
}

/// One of the provider's own signing keys (§8.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderPublicKey {
    /// The key's id.
    pub key_id: String,
    /// Its algorithm.
    pub algorithm: KeyAlgorithm,
    /// The public key, base64.
    pub public_key: String,
    /// When it was created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<Timestamp>,
}

/// The `capabilities` block of discovery.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Capabilities {
    /// The message types it accepts (`reaction` among them).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_types: Option<Vec<MessageType>>,
    /// The tiers it offers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tiers: Option<Vec<Tier>>,
    /// The metadata extensions it knows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_schemas: Option<Vec<MetadataSchema>>,
    /// Size limits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<Limits>,
    /// How it federates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation: Option<FederationCapabilities>,
    /// What it shares for discovery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery: Option<DiscoveryCapabilities>,
}

/// A metadata extension a provider knows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataSchema {
    /// Its short id.
    pub id: String,
    /// Its schema's URI.
    pub uri: String,
}

/// A provider's size limits.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Limits {
    /// The largest upload it takes, in bytes (§5.8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_upload_bytes: Option<u64>,
}

/// How a provider federates.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FederationCapabilities {
    /// How remote members get live channel events (§8.5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realtime_delivery: Option<RealtimeDelivery>,
}

open_enum! {
    /// How remote members get live channel events (§8.5).
    pub enum RealtimeDelivery {
        /// They connect straight to this provider's socket.
        DirectWs = "direct-ws",
        /// Not offered.
        None = "none",
    }
}

/// What a provider shares for discovery (§8.4, §8.6).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryCapabilities {
    /// Whether it serves its known-provider list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shares_known_providers: Option<bool>,
    /// Whether it serves a discovery feed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discover_feed: Option<bool>,
}
