//! Direct-message conversation ids (spec §7.4, "Conversation id", byte-exact).

use sha2::{Digest, Sha256};

use crate::Actor;

/// Derive the `dmId` for a two-party conversation.
///
/// Both actors are already canonical (the [`Actor`] type guarantees it), so
/// step 1's lowercasing is a no-op: a canonical actor is all-lowercase. The
/// participants are sorted by code point (byte order is the same for ASCII),
/// LF-joined, hashed with SHA-256 and hex-encoded behind `dm_`.
pub fn dm_id(a: &Actor, b: &Actor) -> String {
    let (a, b) = (a.to_string(), b.to_string());
    let (first, second) = if a <= b { (a, b) } else { (b, a) };
    let digest = Sha256::digest(format!("{first}\n{second}").as_bytes());
    let mut out = String::with_capacity(3 + 64);
    out.push_str("dm_");
    for byte in digest {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

const HEX: &[u8; 16] = b"0123456789abcdef";

#[cfg(test)]
mod tests {
    use super::*;

    /// The published example in §7.4.
    #[test]
    fn spec_vector() {
        let alice = Actor::parse_canonical("alice@a.com").unwrap();
        let bob = Actor::parse_canonical("bob@b.com").unwrap();
        let want = "dm_c2a3a0d4bc7aa54700d2f412c42fc0155df6071e502977e4988933eef7e46868";
        assert_eq!(dm_id(&alice, &bob), want);
        assert_eq!(
            dm_id(&bob, &alice),
            want,
            "order of arguments is irrelevant"
        );
    }

    #[test]
    fn spellings_converge() {
        let a1 = Actor::canonicalize("alice@A.com.").unwrap();
        let a2 = Actor::parse_canonical("alice@a.com").unwrap();
        let bob = Actor::parse_canonical("bob@b.com").unwrap();
        assert_eq!(dm_id(&a1, &bob), dm_id(&a2, &bob));
    }
}
