//! The OFSCP protocol core, shared by the re-ofscp provider and OFSCP
//! clients.
//!
//! * [`actor`]: actor identifiers and provider authorities, with their
//!   canonical forms (§2.2). Identity is always `(handle, domain)`.
//! * [`auth`]: registration, login and device-key payloads (§4.1–§4.7).
//! * [`discovery`]: the provider discovery document (§3.1, §8.1).
//! * [`dm`]: direct-message conversation ids, [`DmId`] (§7.4).
//! * [`ids`]: local ids, object URIs and refs (§2.2).
//! * [`signing`]: the byte-exact canonical strings, content digest and
//!   Ed25519 sign/verify of §4.4, §7.1 and §8.1, and the client side:
//!   [`signing::DeviceKey`] and [`signing::Signer`].
//!
//! The crate does no I/O, starts no runtime and never reads a clock: time is
//! always passed in, and so is randomness (a `rand_core::CryptoRngCore`). It
//! builds for `wasm32-unknown-unknown`.
//!
//! Identifiers deserialize **strictly**: a non-canonical actor, authority or
//! object URI is refused. Where §2.2 lets a receiver convert instead, opt in
//! per field with [`actor::lenient`].

pub mod actor;
pub mod auth;
pub mod discovery;
pub mod dm;
pub mod ids;
pub mod signing;

pub use actor::{Actor, Authority, IdentError, is_valid_handle};
pub use dm::{DmId, DmIdError, dm_id};
pub use ids::{LocalId, ObjectRef, ObjectUri};

/// The OFSCP protocol version this crate speaks.
pub const PROTOCOL_VERSION: &str = "0.1.0";
