//! The signing side of §4.4 and §7.1: a device's key, and the `X-OFSCP-*`
//! headers of a request it signs.
//!
//! Everything is built on the parent module's [`CanonicalRequest`],
//! [`sign`] and [`content_digest`], so a client and the provider that
//! verifies its requests share one canonicalizer. Nothing here draws
//! randomness or reads a clock: the generator and the time are arguments.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

use super::{
    CanonicalError, CanonicalRequest, SigningKey, VerifyingKey, content_digest, encode_public_key,
    headers, sign, ws_canonical_string,
};
use crate::{Actor, Authority};

/// A device's private Ed25519 signing key (§4.3). It never leaves the
/// device (§4.3.2); the caller stores its [`seed`](Self::seed) somewhere
/// safe, such as the platform keychain.
pub struct DeviceKey(SigningKey);

impl DeviceKey {
    /// A fresh key from a cryptographically secure generator. The caller
    /// supplies the generator (for example `rand_core::OsRng` on a native
    /// target), so this crate never forces an entropy source on anyone.
    pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
        Self(SigningKey::generate(rng))
    }

    /// The key whose 32-byte seed is `seed`.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(seed))
    }

    /// The 32-byte seed, for storing the key. It is wiped from memory when
    /// the returned value is dropped.
    pub fn seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    /// The public half, registered with the home provider.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.0.verifying_key()
    }

    /// The public half as `public_key` carries it on the wire: the raw 32
    /// bytes in padded standard base64 (§4.3.2).
    pub fn public_key_base64(&self) -> String {
        encode_public_key(&self.0.verifying_key())
    }

    /// `base64(Ed25519_sign(key, utf8(canonical)))`.
    pub fn sign(&self, canonical: &str) -> String {
        sign(&self.0, canonical)
    }
}

impl fmt::Debug for DeviceKey {
    /// Shows the public key only, never the secret.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("DeviceKey")
            .field(&self.public_key_base64())
            .finish()
    }
}

/// Who signs: an actor and one of its registered device keys.
#[derive(Debug, Clone, Copy)]
pub struct Signer<'a> {
    /// The actor the key belongs to.
    pub actor: &'a Actor,
    /// The `key_id` the home provider gave the key.
    pub key_id: &'a str,
    /// The private key.
    pub key: &'a DeviceKey,
}

/// One HTTP request to be signed, as it will be sent.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    /// The provider the request goes to.
    pub authority: &'a Authority,
    /// The HTTP method.
    pub method: &'a str,
    /// The path exactly as in the request-target.
    pub path: &'a str,
    /// The raw query string without its `?`, if any.
    pub query: Option<&'a str>,
    /// The raw body bytes (empty for none).
    pub body: &'a [u8],
}

/// The six headers of one user-signed request (§4.4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedHeaders {
    /// `x-ofscp-actor`.
    pub actor: String,
    /// `x-ofscp-key-id`.
    pub key_id: String,
    /// `x-ofscp-timestamp`.
    pub timestamp: String,
    /// `x-ofscp-nonce`.
    pub nonce: String,
    /// `x-ofscp-content-digest`.
    pub content_digest: String,
    /// `x-ofscp-signature`.
    pub signature: String,
}

impl SignedHeaders {
    /// Each header's name and value, to add to the request. The names are
    /// the lowercase [`headers`] constants (header names are
    /// case-insensitive, and `http::HeaderName::from_static` needs
    /// lowercase).
    pub fn pairs(&self) -> [(&'static str, &str); 6] {
        [
            (headers::ACTOR, &self.actor),
            (headers::KEY_ID, &self.key_id),
            (headers::TIMESTAMP, &self.timestamp),
            (headers::NONCE, &self.nonce),
            (headers::CONTENT_DIGEST, &self.content_digest),
            (headers::SIGNATURE, &self.signature),
        ]
    }
}

impl Signer<'_> {
    /// Sign `request` at `timestamp` with `nonce` (see
    /// [`signing_timestamp`] and [`generate_nonce`]). A retry, such as after
    /// a `503`, must be signed again with a fresh nonce.
    ///
    /// Fails only if a component contains an LF (see
    /// [`CanonicalRequest::render`]).
    pub fn sign_request(
        &self,
        request: &Request<'_>,
        timestamp: &str,
        nonce: &str,
    ) -> Result<SignedHeaders, CanonicalError> {
        let content_digest = content_digest(request.body);
        let canonical = CanonicalRequest {
            authority: request.authority.as_str(),
            method: request.method,
            path: request.path,
            query: request.query,
            timestamp,
            nonce,
            content_digest: &content_digest,
        }
        .render()?;
        Ok(SignedHeaders {
            actor: self.actor.to_string(),
            key_id: self.key_id.to_owned(),
            timestamp: timestamp.to_owned(),
            nonce: nonce.to_owned(),
            signature: self.key.sign(&canonical),
            content_digest,
        })
    }

    /// The `signature` of a WebSocket `authenticate` command answering the
    /// challenge `challenge_nonce` from `authority`, sent at `timestamp`
    /// (§7.1). Fails only if a component contains an LF.
    pub fn sign_ws_authenticate(
        &self,
        authority: &Authority,
        challenge_nonce: &str,
        timestamp: &str,
    ) -> Result<String, CanonicalError> {
        let canonical = ws_canonical_string(authority.as_str(), challenge_nonce, timestamp)?;
        Ok(self.key.sign(&canonical))
    }
}

/// Bytes of entropy in a request nonce: 192 bits, above the 128 that §4.4.1
/// requires.
const NONCE_BYTES: usize = 24;

/// A fresh `x-ofscp-nonce` value: base64url, unpadded (§4.4.1).
pub fn generate_nonce(rng: &mut impl CryptoRngCore) -> String {
    let mut bytes = [0u8; NONCE_BYTES];
    rng.fill_bytes(&mut bytes);
    B64URL.encode(bytes)
}

/// The `x-ofscp-timestamp` (and `authenticate.timestamp`) for the moment
/// `now`: RFC 3339 in UTC with a `Z`, to the second (§4.4.1). The caller
/// reads its own clock.
pub fn signing_timestamp(now: jiff::Timestamp) -> String {
    // A Timestamp is always UTC, so its fields need no time zone.
    now.strftime("%Y-%m-%dT%H:%M:%SZ").to_string()
}

#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;
