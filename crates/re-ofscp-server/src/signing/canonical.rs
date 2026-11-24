//! Canonical strings and Ed25519 signing (spec §4.4.2, §7.1).
//!
//! These functions are byte-exact: they must reproduce
//! `ofscp/tests/signing-vector.json` and `ofscp/tests/ws-signing-vector.json`
//! exactly, or every signed request silently fails.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

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
    pub fn render(&self) -> String {
        let path = if self.path.is_empty() { "/" } else { self.path };
        [
            self.authority,
            &self.method.to_ascii_uppercase(),
            path,
            &canonical_query(self.query),
            self.timestamp,
            self.nonce,
            self.content_digest,
        ]
        .join("\n")
    }
}

/// The four-line WebSocket `authenticate` canonical string (§7.1).
pub fn ws_canonical_string(authority: &str, challenge_nonce: &str, timestamp: &str) -> String {
    [authority, WS_AUTH_SEPARATOR, challenge_nonce, timestamp].join("\n")
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

/// Decode a base64 Ed25519 public key (32 raw bytes).
pub fn decode_public_key(b64: &str) -> Option<VerifyingKey> {
    let bytes: [u8; 32] = B64.decode(b64).ok()?.try_into().ok()?;
    VerifyingKey::from_bytes(&bytes).ok()
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
            format!("a.example\nGET\n/\n\nt\nn\n{EMPTY_BODY_DIGEST}")
        );
    }
}
