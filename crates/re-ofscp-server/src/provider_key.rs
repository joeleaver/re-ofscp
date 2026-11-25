//! The provider's own signing key (§8.1).
//!
//! Provider-signed requests (e.g. notification webhooks, §10) are signed with
//! this key, and discovery publishes its public half under
//! `provider.publicKeys` (§3.1). The seed comes from the
//! `PROVIDER_SIGNING_KEY` secret (docs/decisions/0007); the private half is
//! never serialized, logged or printed.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use re_ofscp_types::discovery::ProviderPublicKey;
use sha2::{Digest as _, Sha256};

/// Prefix of a provider key id (`psk-…`, after the spec's example).
pub const KEY_ID_PREFIX: &str = "psk-";

/// How many bytes of the public key's SHA-256 name the key (128 bits).
const KEY_ID_HASH_BYTES: usize = 16;

/// The provider signing key and its id.
#[derive(Clone)]
pub struct ProviderKey {
    signing: SigningKey,
    key_id: String,
}

impl ProviderKey {
    /// The key whose Ed25519 seed is `seed`.
    ///
    /// Its id is derived from the public key, `psk-` + base64url of the
    /// first 16 bytes of its SHA-256, so the same secret always publishes
    /// the same id and a new secret always publishes a new one.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(seed);
        let digest = Sha256::digest(signing.verifying_key().as_bytes());
        let key_id = format!(
            "{KEY_ID_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(&digest[..KEY_ID_HASH_BYTES])
        );
        Self { signing, key_id }
    }

    /// The id provider-signed requests carry in `X-OFSCP-Key-ID`.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The private key, for signing provider requests.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing
    }

    /// Every key this provider publishes, as (key id, public key), for
    /// verifying its own provider signatures. One today; a rotation window
    /// would add the previous key (docs/decisions/0007).
    pub fn published(&self) -> Vec<(String, ed25519_dalek::VerifyingKey)> {
        vec![(self.key_id.clone(), self.signing.verifying_key())]
    }

    /// The published keys as discovery lists them (`provider.publicKeys`),
    /// from the same list as [`ProviderKey::published`], so what peers see
    /// and what this provider accepts cannot drift apart.
    pub fn public_entries(&self) -> Vec<ProviderPublicKey> {
        self.published()
            .into_iter()
            .map(|(key_id, key)| ProviderPublicKey {
                key_id,
                algorithm: "Ed25519".to_owned(),
                public_key: STANDARD.encode(key.as_bytes()),
                created_at: None,
            })
            .collect()
    }
}

impl std::fmt::Debug for ProviderKey {
    /// The key id only: never the private key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderKey")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::canonical::decode_public_key;

    #[test]
    fn id_is_stable_and_derived_from_the_public_key() {
        let a = ProviderKey::from_seed(&[7; 32]);
        let again = ProviderKey::from_seed(&[7; 32]);
        let b = ProviderKey::from_seed(&[8; 32]);
        assert_eq!(a.key_id(), again.key_id());
        assert_ne!(a.key_id(), b.key_id());
        assert!(a.key_id().starts_with(KEY_ID_PREFIX));
        // psk- + 16 bytes in unpadded base64url.
        assert_eq!(a.key_id().len(), KEY_ID_PREFIX.len() + 22);
    }

    #[test]
    fn public_entries_round_trip_and_debug_hides_the_seed() {
        let key = ProviderKey::from_seed(&[7; 32]);
        let entries = key.public_entries();
        assert_eq!(entries.len(), key.published().len());
        let entry = &entries[0];
        assert_eq!(entry.key_id, key.key_id());
        let decoded = decode_public_key(&entry.public_key).unwrap();
        assert_eq!(decoded, key.signing_key().verifying_key());
        assert_eq!(entry.algorithm, "Ed25519");
        let shown = format!("{key:?}");
        assert!(shown.contains(key.key_id()));
        assert!(!shown.contains("signing"));
    }
}
