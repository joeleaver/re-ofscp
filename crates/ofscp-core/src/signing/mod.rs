//! Canonical strings and Ed25519 signing (spec §4.4, §7.1, §8.1).
//!
//! These functions are byte-exact: they must reproduce
//! `ofscp/tests/signing-vector.json` and `ofscp/tests/ws-signing-vector.json`
//! exactly, or every signed request silently fails.
//!
//! Only the pure parts live here. Checking the timestamp against a clock,
//! the replay store, and finding the signer's key are the verifier's job:
//! it calls these functions with values it has already obtained.
//!
//! The client side, [`Signer`] and [`DeviceKey`], builds on the same
//! functions. The random generator and the time are passed in, so the crate
//! needs neither an OS entropy source nor a clock.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signature, Signer as _};
use sha2::{Digest, Sha256};

/// The key types these functions take, re-exported so a consumer uses the
/// same `ed25519-dalek` this crate was built against.
pub use ed25519_dalek::{SigningKey, VerifyingKey};

mod client;

pub use client::{DeviceKey, Request, SignedHeaders, Signer, generate_nonce, signing_timestamp};

/// Signing header names (§4.4.1, §8.1). Lowercase, as HTTP libraries store
/// them; header names are case-insensitive on the wire.
pub mod headers {
    /// User-signed requests: the signing actor.
    pub const ACTOR: &str = "x-ofscp-actor";
    /// Provider-signed requests: the signing provider's authority.
    pub const PROVIDER: &str = "x-ofscp-provider";
    /// The signing key's id.
    pub const KEY_ID: &str = "x-ofscp-key-id";
    /// RFC 3339 moment of signing.
    pub const TIMESTAMP: &str = "x-ofscp-timestamp";
    /// Per-request nonce.
    pub const NONCE: &str = "x-ofscp-nonce";
    /// `base64(SHA-256(body))`.
    pub const CONTENT_DIGEST: &str = "x-ofscp-content-digest";
    /// `base64(Ed25519 signature)`.
    pub const SIGNATURE: &str = "x-ofscp-signature";

    /// Every header that marks a request as an attempt to sign.
    pub const ALL: [&str; 7] = [
        ACTOR,
        PROVIDER,
        KEY_ID,
        TIMESTAMP,
        NONCE,
        CONTENT_DIGEST,
        SIGNATURE,
    ];
}

/// Why a base64 Ed25519 public key was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PublicKeyError {
    /// The value is not standard-alphabet, padded base64.
    #[error("public key is not valid base64")]
    Base64,
    /// The decoded key is not exactly 32 bytes.
    #[error("public key must be 32 bytes")]
    Length,
    /// The 32 bytes are not a valid compressed Edwards point.
    #[error("public key is not a valid Ed25519 point")]
    Point,
}

/// `X-OFSCP-Content-Digest` of an empty body (§4.4.1).
pub const EMPTY_BODY_DIGEST: &str = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";

/// Domain separator on the second line of the WebSocket canonical string.
pub const WS_AUTH_SEPARATOR: &str = "ofscp-ws-authenticate";

/// `base64(SHA-256(body))` (§4.4.1).
pub fn content_digest(body: &[u8]) -> String {
    B64.encode(Sha256::digest(body))
}

/// The `<query>` line: raw `name=value` pairs exactly as sent (no
/// percent-decoding), sorted ascending by bytes, joined with `&`. Empty pairs
/// produced by stray `&`s are dropped. `None` and `""` both give `""`.
pub fn canonical_query(raw: Option<&str>) -> String {
    let mut pairs: Vec<&str> = raw
        .unwrap_or("")
        .split('&')
        .filter(|p| !p.is_empty())
        .collect();
    pairs.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    pairs.join("&")
}

/// The components of a §4.4.2 canonical string.
#[derive(Debug, Clone, Copy)]
pub struct CanonicalRequest<'a> {
    /// Canonical authority of the target provider.
    pub authority: &'a str,
    /// HTTP method (uppercased when rendered).
    pub method: &'a str,
    /// Path exactly as in the request-target; `""` becomes `/`.
    pub path: &'a str,
    /// Raw query string without the `?`.
    pub query: Option<&'a str>,
    /// Exact `X-OFSCP-Timestamp` value.
    pub timestamp: &'a str,
    /// Exact `X-OFSCP-Nonce` value.
    pub nonce: &'a str,
    /// Exact `X-OFSCP-Content-Digest` value.
    pub content_digest: &'a str,
}

impl CanonicalRequest<'_> {
    /// Render the seven LF-joined lines, with no trailing newline.
    ///
    /// A component that itself contains an LF is refused: it would make the
    /// string ambiguous (two different inputs, one canonical string), so a
    /// signature over it could be replayed as a signature over the other.
    pub fn render(&self) -> Result<String, CanonicalError> {
        let path = if self.path.is_empty() { "/" } else { self.path };
        let query = canonical_query(self.query);
        join_lines(&[
            self.authority,
            &self.method.to_ascii_uppercase(),
            path,
            &query,
            self.timestamp,
            self.nonce,
            self.content_digest,
        ])
    }
}

/// Why a canonical string could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CanonicalError {
    /// A component contains an LF, the line separator (§4.4.2, §7.1).
    #[error("a signed component contains a line break")]
    LineBreak,
}

/// LF-join `lines`, refusing any line that contains an LF itself.
fn join_lines(lines: &[&str]) -> Result<String, CanonicalError> {
    if lines.iter().any(|line| line.contains('\n')) {
        return Err(CanonicalError::LineBreak);
    }
    Ok(lines.join("\n"))
}

/// The four-line WebSocket `authenticate` canonical string (§7.1).
///
/// Refuses a component containing an LF, as [`CanonicalRequest::render`]
/// does.
pub fn ws_canonical_string(
    authority: &str,
    challenge_nonce: &str,
    timestamp: &str,
) -> Result<String, CanonicalError> {
    join_lines(&[authority, WS_AUTH_SEPARATOR, challenge_nonce, timestamp])
}

/// `base64(Ed25519_sign(key, utf8(canonical)))`.
pub fn sign(key: &SigningKey, canonical: &str) -> String {
    B64.encode(key.sign(canonical.as_bytes()).to_bytes())
}

/// Verify a base64 signature over `canonical`. Uses strict verification
/// (rejects small-order keys and non-canonical `s`), which every honestly
/// produced Ed25519 signature passes.
pub fn verify(key: &VerifyingKey, canonical: &str, signature_b64: &str) -> bool {
    let Ok(bytes) = B64.decode(signature_b64) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(&bytes) else {
        return false;
    };
    key.verify_strict(canonical.as_bytes(), &sig).is_ok()
}

/// Decode a base64 Ed25519 public key (32 raw bytes, §4.3.3).
pub fn decode_public_key(b64: &str) -> Result<VerifyingKey, PublicKeyError> {
    let bytes: [u8; 32] = B64
        .decode(b64)
        .map_err(|_| PublicKeyError::Base64)?
        .try_into()
        .map_err(|_| PublicKeyError::Length)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| PublicKeyError::Point)
}

/// The base64 (standard alphabet) form of a public key, as published at
/// the keys endpoints and in discovery (§4.6, §8.1).
pub fn encode_public_key(key: &VerifyingKey) -> String {
    B64.encode(key.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_digest() {
        assert_eq!(content_digest(b""), EMPTY_BODY_DIGEST);
    }

    #[test]
    fn query_sorting() {
        assert_eq!(canonical_query(None), "");
        assert_eq!(canonical_query(Some("")), "");
        assert_eq!(canonical_query(Some("b=2&a=1")), "a=1&b=2");
        // Raw, not decoded; byte order puts upper case before lower.
        assert_eq!(canonical_query(Some("q=a%20b&Z=1&&a=")), "Z=1&a=&q=a%20b");
        // Duplicate names keep both pairs.
        assert_eq!(canonical_query(Some("x=2&x=1")), "x=1&x=2");
    }

    #[test]
    fn public_keys() {
        let key = SigningKey::from_bytes(&[7; 32]).verifying_key();
        let b64 = encode_public_key(&key);
        assert_eq!(decode_public_key(&b64), Ok(key));
        assert_eq!(
            decode_public_key("not base64!"),
            Err(PublicKeyError::Base64)
        );
        assert_eq!(
            decode_public_key(&B64.encode([0u8; 31])),
            Err(PublicKeyError::Length)
        );
        // y = 2 has no matching x on the curve, so it does not decompress.
        let mut not_a_point = [0u8; 32];
        not_a_point[0] = 2;
        assert_eq!(
            decode_public_key(&B64.encode(not_a_point)),
            Err(PublicKeyError::Point)
        );
    }

    /// The raw key inside the spec's negative SPKI sample
    /// (`device-key-registration.spki.invalid.json`).
    const RAW_KEY: &str = "Gb9ECWmYfAJ6tS1j/Mdc6rjxPXK5+f6tcyLn4Bv7B1M=";

    /// §4.3.2 (spec #28): the key is padded standard base64. The same key
    /// without its `=` is refused, not quietly accepted.
    #[test]
    fn unpadded_public_key_is_refused() {
        assert!(decode_public_key(RAW_KEY).is_ok());
        assert_eq!(
            decode_public_key(RAW_KEY.trim_end_matches('=')),
            Err(PublicKeyError::Base64)
        );
    }

    /// §4.3.2 (spec #28): the key is the raw 32 bytes, so a DER
    /// `SubjectPublicKeyInfo` wrapping (44 bytes) is refused.
    #[test]
    fn spki_public_key_is_refused() {
        let spki = "MCowBQYDK2VwAyEAGb9ECWmYfAJ6tS1j/Mdc6rjxPXK5+f6tcyLn4Bv7B1M=";
        assert_eq!(decode_public_key(spki), Err(PublicKeyError::Length));
    }

    #[test]
    fn sign_verify_round_trip() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let sig = sign(&key, "hello");
        assert!(verify(&key.verifying_key(), "hello", &sig));
        assert!(!verify(&key.verifying_key(), "hello!", &sig));
        assert!(!verify(&key.verifying_key(), "hello", "not base64!"));
        assert!(!verify(
            &key.verifying_key(),
            "hello",
            &B64.encode([0u8; 63])
        ));
    }

    #[test]
    fn ws_string_has_four_lines() {
        assert_eq!(
            ws_canonical_string("a.example", "n", "t"),
            Ok("a.example\nofscp-ws-authenticate\nn\nt".to_owned())
        );
    }

    /// An LF inside a component would let two inputs share one canonical
    /// string, so both builders refuse it.
    #[test]
    fn line_breaks_in_components_are_refused() {
        assert_eq!(
            ws_canonical_string("a.example", "n", "2026-01-01T00:00:00Z\nX"),
            Err(CanonicalError::LineBreak)
        );
        let base = CanonicalRequest {
            authority: "a.example",
            method: "GET",
            path: "/x",
            query: None,
            timestamp: "t",
            nonce: "n",
            content_digest: EMPTY_BODY_DIGEST,
        };
        assert!(base.render().is_ok());
        for bad in [
            CanonicalRequest {
                path: "/x\nGET",
                ..base
            },
            CanonicalRequest {
                nonce: "n\n",
                ..base
            },
            CanonicalRequest {
                query: Some("a=1\n"),
                ..base
            },
            CanonicalRequest {
                method: "GET\n",
                ..base
            },
        ] {
            assert_eq!(bad.render(), Err(CanonicalError::LineBreak));
        }
    }

    #[test]
    fn empty_path_is_slash() {
        let c = CanonicalRequest {
            authority: "a.example",
            method: "get",
            path: "",
            query: None,
            timestamp: "t",
            nonce: "n",
            content_digest: EMPTY_BODY_DIGEST,
        };
        assert_eq!(
            c.render(),
            Ok(format!("a.example\nGET\n/\n\nt\nn\n{EMPTY_BODY_DIGEST}"))
        );
    }
}
