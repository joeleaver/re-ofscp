//! The WebSocket `authenticate` handshake (spec §7.1), and re-confirming
//! the key of a live connection.
//!
//! The client signs the four-line string of
//! [`canonical::ws_canonical_string`]: our authority, the literal
//! `ofscp-ws-authenticate`, the challenge nonce this connection was issued,
//! and its timestamp. The provider runs §4.5 steps 3, 6 and 7 on it (skew,
//! key, signature). The challenge nonce is ours and dies with the
//! connection, but the use is still checked against and recorded in the one
//! provider-wide replay store (security requirement 2), under the actor
//! namespace and its quotas, so handshakes and signed requests share one
//! budget per signer. Handshakes are exempt from the restart warm-up and
//! are not written to the persistent ledger (§4.5 "Restarts").

use ed25519_dalek::VerifyingKey;
use re_ofscp_types::Actor;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::canonical;
use super::keys::{Lifetime, Reconfirmed, Requester};
use super::verify::{MAX_TOKEN_LEN, Signer, Verifier, VerifyError, replay_error};
use crate::replay::{NonceUse, SignerKind, Surface};

/// The fields of an `authenticate` command (`ws/authenticate.json`).
#[derive(Debug, Clone, Copy)]
pub struct WsAuthenticate<'a> {
    /// `actor`: who claims to be connecting, in canonical form.
    pub actor: &'a str,
    /// `keyId`: the device key that signed.
    pub key_id: &'a str,
    /// `timestamp` (RFC 3339).
    pub timestamp: &'a str,
    /// `signature`: base64 Ed25519 over the canonical string.
    pub signature: &'a str,
}

/// An `authenticate` that passed the checks needing no key (actor form,
/// lengths, skew, replay). Finish with [`Verifier::ws_complete`].
#[derive(Debug, Clone)]
pub struct WsPrecheck {
    actor: Actor,
    actor_id: String,
    key_id: String,
    canonical: String,
    signature: String,
    challenge_nonce: String,
    signed_at: i64,
}

impl WsPrecheck {
    /// The claimed actor (canonical). Federation policy is applied to its
    /// provider before any key is fetched (§4.6).
    pub fn actor(&self) -> &Actor {
        &self.actor
    }

    fn nonce_use(&self) -> NonceUse<'_> {
        NonceUse {
            kind: SignerKind::Actor,
            signer: &self.actor_id,
            domain: self.actor.domain().as_str(),
            key_id: &self.key_id,
            nonce: &self.challenge_nonce,
            signed_at: self.signed_at,
        }
    }
}

/// A verified handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsVerified {
    /// The authenticated actor, `(handle, domain)`.
    pub actor: Actor,
    /// The device key that signed.
    pub key_id: String,
    /// That key, so a re-confirmation can tell it from a replacement
    /// published under the same id.
    pub key: VerifyingKey,
    /// How long the key may be relied on before it must be re-confirmed.
    pub lifetime: Lifetime,
}

impl Verifier {
    /// The checks of an `authenticate` that need no key: the actor is
    /// canonical (§2.2, a non-canonical spelling is rejected), the key id
    /// is of sane length, the timestamp is within the skew window (§4.5
    /// step 3), and the replay store would accept the use (step 4: a
    /// replay of this connection's challenge, or a signer over its quota).
    pub fn ws_precheck(
        &self,
        auth: &WsAuthenticate<'_>,
        challenge_nonce: &str,
    ) -> Result<WsPrecheck, VerifyError> {
        let actor = Actor::parse_canonical(auth.actor)
            .map_err(|_| VerifyError::Headers("authenticate actor is not a canonical actor"))?;
        if auth.key_id.is_empty() || auth.key_id.len() > MAX_TOKEN_LEN {
            return Err(VerifyError::Headers("keyId has an invalid length"));
        }
        let signed_at = OffsetDateTime::parse(auth.timestamp, &Rfc3339)
            .map_err(|_| VerifyError::Timestamp("authenticate timestamp is not RFC 3339"))?
            .unix_timestamp();
        let now = self.now();
        if (now - signed_at).abs() > self.skew_secs {
            return Err(VerifyError::Timestamp(
                "authenticate timestamp is outside the allowed clock skew",
            ));
        }
        // The authority and challenge are ours and the timestamp parsed as
        // RFC 3339, so no component can hold a line break; refusing one
        // anyway keeps the canonical string one-to-one with its inputs, and
        // the refusal is an ordinary §7.1 authentication failure.
        let canonical = canonical::ws_canonical_string(
            self.authority.as_str(),
            challenge_nonce,
            auth.timestamp,
        )
        .map_err(|_| VerifyError::Headers("an authenticate component contains a line break"))?;
        let pre = WsPrecheck {
            actor_id: actor.to_string(),
            actor,
            key_id: auth.key_id.to_owned(),
            canonical,
            signature: auth.signature.to_owned(),
            challenge_nonce: challenge_nonce.to_owned(),
            signed_at,
        };
        self.replay
            .check(Surface::WsHandshake, &pre.nonce_use(), now)
            .map_err(replay_error)?;
        Ok(pre)
    }

    /// Judge a remote actor's provider by the federation policy, then
    /// resolve the actor's key and verify the signature (§4.5 steps 6 and
    /// 7, re-fetching once after a cached miss), then record the use in
    /// the replay store atomically. Remote key fetches are charged to
    /// `requester`.
    pub async fn ws_complete(
        &self,
        pre: WsPrecheck,
        requester: &Requester,
    ) -> Result<WsVerified, VerifyError> {
        let signer = Signer::Actor(pre.actor.clone());
        self.check_policy(&signer)?;
        let resolved = self
            .resolve_and_check(
                &signer,
                &pre.key_id,
                &pre.signature,
                &pre.canonical,
                requester,
            )
            .await?;
        let key = resolved.key.ok_or(VerifyError::UnknownKey)?;
        self.replay
            .record(Surface::WsHandshake, &pre.nonce_use(), self.now())
            .map_err(replay_error)?;
        Ok(WsVerified {
            actor: pre.actor,
            key_id: pre.key_id,
            key,
            lifetime: resolved.lifetime,
        })
    }

    /// Re-confirm the key of a live connection that has relied on it for
    /// `held` (§7.1): whether the actor still publishes it.
    pub async fn reconfirm(
        &self,
        verified: &WsVerified,
        held: Lifetime,
        requester: &Requester,
    ) -> Reconfirmed {
        let signer = Signer::Actor(verified.actor.clone());
        self.keys
            .reconfirm(&signer, &verified.key_id, &verified.key, held, requester)
            .await
    }
}
