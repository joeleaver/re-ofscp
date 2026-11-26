//! The OFSCP protocol core, shared by the re-ofscp provider and OFSCP
//! clients.
//!
//! * [`actor`]: actor identifiers and provider authorities, with their
//!   canonical forms (§2.2). Identity is always `(handle, domain)`.
//! * [`auth`]: registration, login and device-key payloads (§4.1–§4.7).
//! * [`discovery`]: the provider discovery document (§3.1, §8.1).
//! * [`dm`]: direct-message conversation ids (§7.4).
//! * [`signing`]: the byte-exact canonical strings, content digest and
//!   Ed25519 sign/verify of §4.4, §7.1 and §8.1.
//! * [`ws`]: the §7.1 WebSocket envelope, close codes, `error` event (§7.3)
//!   and the handshake and subscription message data.
//!
//! The crate does no I/O, starts no runtime and never reads a clock: time is
//! always passed in. It builds for `wasm32-unknown-unknown`.

pub mod actor;
pub mod auth;
pub mod discovery;
pub mod dm;
pub mod signing;
pub mod ws;

pub use actor::{Actor, Authority, IdentError, is_valid_handle};
pub use dm::dm_id;
