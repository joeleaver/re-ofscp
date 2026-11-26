//! Wire types shared by the re-ofscp server and its rinch admin UI.
//!
//! Keep this crate free of I/O and async runtimes: it compiles for both the
//! host (server) and `wasm32-unknown-unknown` (admin UI).
//!
//! The OFSCP protocol itself (identifiers, auth and discovery payloads,
//! `dmId`, signing) lives in [`ofscp_core`], which OFSCP clients share. Its
//! modules are re-exported here at their old paths, so `re_ofscp_types::actor`
//! and friends keep working. What is defined here is specific to this
//! provider: its admin API, its federation policy, and its health check.

pub mod admin;
pub mod federation;
pub mod profile;

pub use ofscp_core::{Actor, Authority, IdentError, dm_id, is_valid_handle};
pub use ofscp_core::{actor, auth, discovery, dm, ws};

use serde::{Deserialize, Serialize};

/// `GET /api/health` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Health {
    /// `"ok"` when the server and its database are reachable, `"degraded"` otherwise.
    pub status: String,
    /// The OFSCP protocol version this server implements.
    pub ofscp: String,
    /// The provider domain (the OFSCP authority, §4.4.2).
    pub domain: String,
    /// Whether the rhypedb database answered.
    pub database: bool,
}

/// The OFSCP protocol version implemented.
pub const OFSCP_VERSION: &str = "0.1.0";
