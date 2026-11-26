//! The provider discovery document, `GET /.well-known/ofscp-provider`
//! (spec §3.1), and its provider signing keys (§8.1).
//!
//! The types are defined in [`crate::wire`]; this path is kept for
//! existing users.

pub use crate::wire::{
    Authentication, Capabilities, DiscoveryCapabilities, DiscoveryDocument, FederationCapabilities,
    Limits, MetadataSchema, ProviderInfo, ProviderPublicKey, RealtimeDelivery, Software,
};
