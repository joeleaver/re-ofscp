//! The admin second factor: TOTP (RFC 6238) with HMAC-SHA1, 6 digits and
//! 30-second steps, the parameters every authenticator app supports.
//!
//! Secrets are 160 random bits (RFC 4226 §4 recommends at least that). At
//! rest they are sealed with [`SecretBox`] (XChaCha20-Poly1305 under the
//! `ADMIN_SECRET_KEY` secret, bound to the admin's username), so a copy of
//! the database alone does not yield anyone's second factor.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use subtle::ConstantTimeEq;

/// Seconds per time step.
pub const STEP_SECS: i64 = 30;

/// Digits per code.
pub const DIGITS: u32 = 6;

/// Steps accepted either side of the current one, for clock drift and the
/// time it takes to type a code.
pub const SKEW_STEPS: i64 = 1;

/// Secret length in bytes.
pub const SECRET_LEN: usize = 20;

/// Prefix of a sealed value, naming the format so it can change later.
const SEALED_PREFIX: &str = "v1:";

/// Domain separation for the AEAD's associated data.
const AAD_CONTEXT: &[u8] = b"re-ofscp admin totp v1\0";

/// A fresh random secret.
pub fn new_secret() -> Result<Vec<u8>, String> {
    let mut s = vec![0u8; SECRET_LEN];
    getrandom::fill(&mut s).map_err(|e| format!("random source: {e}"))?;
    Ok(s)
}

/// The secret in base32 without padding, as authenticator apps take it.
pub fn base32(secret: &[u8]) -> String {
    data_encoding::BASE32_NOPAD.encode(secret)
}

/// The step containing unix time `now`.
pub fn step_at(now: i64) -> i64 {
    now.div_euclid(STEP_SECS)
}

/// The HOTP value (RFC 4226 §5.3) of `secret` for counter `step`.
pub fn code_at(secret: &[u8], step: i64) -> u32 {
    // HMAC accepts keys of any length, so this cannot fail.
    let Ok(mut mac) = <Hmac<Sha1> as Mac>::new_from_slice(secret) else {
        return u32::MAX;
    };
    mac.update(&step.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[19] & 0x0f);
    let bin = u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]);
    bin % 10u32.pow(DIGITS)
}

/// The step at which `code` is valid for `secret` around `now`, if any.
/// Only steps after `after` count, so a code (or an earlier one) cannot be
/// replayed. Every candidate is compared in constant time.
pub fn verify(secret: &[u8], code: &str, now: i64, after: i64) -> Option<i64> {
    let code = code.trim();
    if code.len() != DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let current = step_at(now);
    let mut matched = None;
    for step in (current - SKEW_STEPS)..=(current + SKEW_STEPS) {
        let expected = format!("{:0width$}", code_at(secret, step), width = DIGITS as usize);
        let equal: bool = expected.as_bytes().ct_eq(code.as_bytes()).into();
        if equal && step > after {
            matched = Some(step);
        }
    }
    matched
}

/// An `otpauth://` URI for authenticator apps. `issuer` and `username` are
/// a canonical authority and an admin username, whose characters need no
/// escaping.
pub fn otpauth_uri(issuer: &str, username: &str, secret: &[u8]) -> String {
    format!(
        "otpauth://totp/{issuer}:{username}?secret={}&issuer={issuer}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECS}",
        base32(secret)
    )
}

/// Seals and opens secrets at rest with XChaCha20-Poly1305.
pub struct SecretBox {
    cipher: XChaCha20Poly1305,
}

impl std::fmt::Debug for SecretBox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretBox(..)")
    }
}

/// A sealed value could not be opened (wrong key, wrong owner, tampered).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("sealed secret could not be opened")]
pub struct OpenError;

fn aad(owner: &str) -> Vec<u8> {
    let mut a = AAD_CONTEXT.to_vec();
    a.extend_from_slice(owner.as_bytes());
    a
}

impl SecretBox {
    /// A box under the 32-byte `key`.
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: XChaCha20Poly1305::new(key.into()),
        }
    }

    /// Seal `plain` for `owner`: `v1:` + base64(nonce ‖ ciphertext).
    pub fn seal(&self, plain: &[u8], owner: &str) -> Result<String, String> {
        let mut nonce = [0u8; 24];
        getrandom::fill(&mut nonce).map_err(|e| format!("random source: {e}"))?;
        let aad = aad(owner);
        let ct = self
            .cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plain,
                    aad: &aad,
                },
            )
            .map_err(|_| "sealing failed".to_owned())?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ct);
        Ok(format!("{SEALED_PREFIX}{}", B64.encode(out)))
    }

    /// Open a value sealed for `owner`.
    pub fn open(&self, sealed: &str, owner: &str) -> Result<Vec<u8>, OpenError> {
        let raw = sealed
            .strip_prefix(SEALED_PREFIX)
            .and_then(|b| B64.decode(b).ok())
            .ok_or(OpenError)?;
        if raw.len() < 24 {
            return Err(OpenError);
        }
        let (nonce, ct) = raw.split_at(24);
        let aad = aad(owner);
        self.cipher
            .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: &aad })
            .map_err(|_| OpenError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn rfc_6238_sha1_vectors_truncated_to_six_digits() {
        // RFC 6238 Appendix B (8-digit values; the last six digits are the
        // 6-digit codes, since both are the same value mod 10^n).
        for (t, eight) in [
            (59, 94_287_082),
            (1_111_111_109, 7_081_804),
            (1_111_111_111, 14_050_471),
            (1_234_567_890, 89_005_924),
            (2_000_000_000, 69_279_037),
            (20_000_000_000, 65_353_130),
        ] {
            assert_eq!(code_at(RFC_SECRET, step_at(t)), eight % 1_000_000, "t={t}");
        }
    }

    #[test]
    fn verification_allows_one_step_of_drift_and_never_a_replay() {
        let now = 1_111_111_109;
        let step = step_at(now);
        let code = |s: i64| format!("{:06}", code_at(RFC_SECRET, s));
        assert_eq!(verify(RFC_SECRET, &code(step), now, 0), Some(step));
        assert_eq!(verify(RFC_SECRET, &code(step - 1), now, 0), Some(step - 1));
        assert_eq!(verify(RFC_SECRET, &code(step + 1), now, 0), Some(step + 1));
        assert_eq!(verify(RFC_SECRET, &code(step - 2), now, 0), None);
        // Used already (or a later code was).
        assert_eq!(verify(RFC_SECRET, &code(step), now, step), None);
        assert_eq!(verify(RFC_SECRET, &code(step - 1), now, step), None);
        // Malformed.
        assert_eq!(verify(RFC_SECRET, "12345", now, 0), None);
        assert_eq!(verify(RFC_SECRET, "abcdef", now, 0), None);
        assert_eq!(verify(RFC_SECRET, " 081804 ", now, 0), Some(step));
    }

    #[test]
    fn secrets_are_random_and_encode_for_apps() {
        let a = new_secret().unwrap();
        assert_eq!(a.len(), SECRET_LEN);
        assert_ne!(a, new_secret().unwrap());
        assert_eq!(
            base32(b"12345678901234567890"),
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        );
        let uri = otpauth_uri("social.example", "joe", RFC_SECRET);
        assert_eq!(
            uri,
            "otpauth://totp/social.example:joe?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\
             &issuer=social.example&algorithm=SHA1&digits=6&period=30"
        );
    }

    #[test]
    fn sealed_secrets_open_only_for_their_owner_and_key() {
        let b = SecretBox::new(&[7u8; 32]);
        let sealed = b.seal(b"secret", "joe").unwrap();
        assert!(sealed.starts_with("v1:"));
        assert_ne!(sealed, b.seal(b"secret", "joe").unwrap(), "fresh nonce");
        assert_eq!(b.open(&sealed, "joe").unwrap(), b"secret");
        assert_eq!(b.open(&sealed, "eve"), Err(OpenError));
        assert_eq!(
            SecretBox::new(&[8u8; 32]).open(&sealed, "joe"),
            Err(OpenError)
        );
        assert_eq!(b.open("v1:AAAA", "joe"), Err(OpenError));
        assert_eq!(b.open("", "joe"), Err(OpenError));
    }
}
