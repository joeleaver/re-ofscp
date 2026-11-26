//! Canonical strings and Ed25519 signing (spec §4.4.2, §7.1, §8.1).
//!
//! The byte-exact protocol code lives in [`ofscp_core::signing`], shared with
//! OFSCP clients; this module re-exports it at the path the server has always
//! used. The parts of verification that need this server's state (the clock,
//! the replay store, key lookup, federation policy) are in [`super::verify`].

pub use ofscp_core::signing::{
    CanonicalRequest, EMPTY_BODY_DIGEST, PublicKeyError, WS_AUTH_SEPARATOR, canonical_query,
    content_digest, decode_public_key, encode_public_key, sign, verify, ws_canonical_string,
};
