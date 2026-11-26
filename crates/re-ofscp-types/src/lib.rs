//! Wire types shared by the re-ofscp server and its rinch admin UI.
//!
//! Keep this crate free of I/O and async runtimes: it compiles for both the
//! host (server) and `wasm32-unknown-unknown` (admin UI).

pub mod actor;
pub mod admin;
pub mod auth;
pub mod discovery;
pub mod dm;
pub mod federation;
pub mod groups;
pub mod profile;

pub use actor::{Actor, Authority, IdentError, is_valid_handle};
pub use dm::dm_id;

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
