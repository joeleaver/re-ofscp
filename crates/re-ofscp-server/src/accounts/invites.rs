//! Account invites (spec §4.1.1, lost-conn/ofscp#18).
//!
//! An invite is `ai_` + 256 random bits (base64url), single-use and
//! time-limited, and may pin a handle. It is shared as the link
//! `https://{authority}/register?invite={token}`. Only the token's SHA-256
//! is stored (`RegistrationInvite` in `schema.rhype`), and tokens are never
//! logged.
//!
//! Claiming is one conditional update (`used == false && expires_at > now`)
//! made while registration is serialized (see `Accounts::register`), so of
//! two registrations presenting the same invite exactly one claims it.

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::db::{Db, DbError, Ql};

/// Prefix of every account invite.
pub const INVITE_PREFIX: &str = "ai_";

/// Lifetime of an invite when the issuer does not choose one: 7 days.
pub const DEFAULT_INVITE_TTL_SECS: i64 = 7 * 86_400;

/// Longest lifetime an issuer may choose: 30 days.
pub const MAX_INVITE_TTL_SECS: i64 = 30 * 86_400;

/// Longest token accepted from a client. Ours are 46 characters; anything
/// much longer is not one of ours and is refused without a lookup.
const MAX_TOKEN_LEN: usize = 128;

/// A usable invite, as read from the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    /// SHA-256 of the token, hex.
    pub token_hash: String,
    /// The pinned handle, if any.
    pub handle: Option<String>,
}

/// What [`InviteStore::revoke`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Revoked {
    /// It was usable and is now expired.
    Revoked,
    /// It was already used (or claimed by a registration in flight); it is
    /// expired now regardless.
    Used,
    /// No unexpired invite has that id.
    Unknown,
}

/// A freshly issued invite. The token appears only here: it is not stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedInvite {
    /// The token (`ai_…`).
    pub token: String,
    /// `https://{authority}/register?invite={token}`.
    pub link: String,
    /// The pinned handle, if any.
    pub handle: Option<String>,
    /// Unix seconds after which it is no longer usable.
    pub expires_at: i64,
}

/// A usable invite as the admin API lists it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct InviteSummary {
    /// SHA-256 of the token, hex: the invite's id.
    pub token_hash: String,
    /// The pinned handle, if any.
    #[serde(default)]
    pub handle: Option<String>,
    /// The issuing admin.
    pub created_by: String,
    /// RFC 3339 issue time.
    pub created_at: String,
    /// RFC 3339 expiry.
    pub expires_at: String,
}

#[derive(Deserialize)]
struct InviteRow {
    token_hash: String,
    #[serde(default)]
    handle: Option<String>,
}

/// The stored form of `token`: SHA-256, hex. `None` if `token` cannot be
/// one of ours (wrong prefix or implausibly long), so it is never looked up.
pub fn token_hash(token: &str) -> Option<String> {
    if !token.starts_with(INVITE_PREFIX) || token.len() > MAX_TOKEN_LEN {
        return None;
    }
    Some(
        Sha256::digest(token.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    )
}

/// A fresh token: `ai_` + 256 random bits, base64url.
pub fn new_token() -> Result<String, DbError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| DbError::Query(format!("random source: {e}")))?;
    Ok(format!("{INVITE_PREFIX}{}", B64URL.encode(bytes)))
}

/// Invite storage.
#[derive(Debug, Clone)]
pub struct InviteStore {
    db: Arc<Db>,
}

impl InviteStore {
    /// A store over `db`.
    pub fn new(db: Arc<Db>) -> Self {
        Self { db }
    }

    /// Store an invite with the given token hash.
    pub async fn create(
        &self,
        token_hash: &str,
        handle: Option<&str>,
        created_by: &str,
        now: i64,
        expires_at: i64,
    ) -> Result<(), DbError> {
        let q = Ql::new("RegistrationInvite.create({ token_hash: ").str(token_hash);
        let q = match handle {
            Some(h) => q.raw(", handle: ").str(h),
            None => q,
        };
        let q = q
            .raw(", created_by: ")
            .str(created_by)
            .raw(", created_at: ")
            .unix_seconds(now)
            .raw(", expires_at: ")
            .unix_seconds(expires_at)
            .raw(", used: false })");
        self.db.write_one::<InviteRow>(&q).await.map(|_| ())
    }

    /// The invite with `token_hash`, if it is unused and unexpired at `now`.
    pub async fn find_usable(&self, token_hash: &str, now: i64) -> Result<Option<Invite>, DbError> {
        let q = Ql::new("RegistrationInvite.filter(.token_hash == ")
            .str(token_hash)
            .raw(" && .used == false && .expires_at > ")
            .unix_seconds(now)
            .raw(")");
        Ok(self
            .db
            .fetch::<InviteRow>(&q)
            .await?
            .into_iter()
            .next()
            .map(|r| Invite {
                token_hash: r.data.token_hash,
                handle: r.data.handle,
            }))
    }

    /// Mark the invite used by `handle`, if it is still unused and
    /// unexpired at `now`. `false` if it was not (used meanwhile, expired).
    pub async fn claim(&self, token_hash: &str, handle: &str, now: i64) -> Result<bool, DbError> {
        let q = Ql::new("RegistrationInvite.filter(.token_hash == ")
            .str(token_hash)
            .raw(" && .used == false && .expires_at > ")
            .unix_seconds(now)
            .raw(").update({ used: true, used_at: ")
            .unix_seconds(now)
            .raw(", used_by: ")
            .str(handle)
            .raw(" })");
        Ok(!self.db.write_rows(&q).await?.into_objects().is_empty())
    }

    /// Up to `limit` invites usable at `now`, in no particular order.
    pub async fn list_usable(&self, now: i64, limit: usize) -> Result<Vec<InviteSummary>, DbError> {
        let q = Ql::new("RegistrationInvite.filter(.used == false && .expires_at > ")
            .unix_seconds(now)
            .raw(").limit(")
            .uint(limit as u64)
            .raw(")");
        Ok(self
            .db
            .fetch::<InviteSummary>(&q)
            .await?
            .into_iter()
            .map(|r| r.data)
            .collect())
    }

    /// Revoke the invite with `token_hash` by expiring it at `now`.
    /// [`Revoked::Unknown`] if no unexpired invite has that hash.
    ///
    /// The invite is expired even when it is claimed: a registration in
    /// flight may still complete, but if it fails and releases the claim the
    /// invite stays dead. ([`Revoked::Used`] then says it was already used
    /// or being used.)
    pub async fn revoke(&self, token_hash: &str, now: i64) -> Result<Revoked, DbError> {
        #[derive(Deserialize)]
        struct UsedRow {
            used: bool,
        }
        let q = Ql::new("RegistrationInvite.filter(.token_hash == ")
            .str(token_hash)
            .raw(" && .expires_at > ")
            .unix_seconds(now)
            .raw(").update({ expires_at: ")
            .unix_seconds(now)
            .raw(" })");
        let rows = self.db.write_many::<UsedRow>(&q).await?;
        Ok(match rows.first() {
            None => Revoked::Unknown,
            Some(r) if r.data.used => Revoked::Used,
            Some(_) => Revoked::Revoked,
        })
    }

    /// Undo [`InviteStore::claim`] after the account could not be created,
    /// so the invite stays usable.
    pub async fn release(&self, token_hash: &str) -> Result<(), DbError> {
        let q = Ql::new("RegistrationInvite.filter(.token_hash == ")
            .str(token_hash)
            .raw(" && .used == true).update({ used: false })");
        self.db.write_rows(&q).await.map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_prefixed_high_entropy_and_hashed() {
        let a = new_token().unwrap();
        let b = new_token().unwrap();
        assert!(a.starts_with(INVITE_PREFIX));
        assert_eq!(a.len(), INVITE_PREFIX.len() + 43);
        assert_ne!(a, b);
        let h = token_hash(&a).unwrap();
        assert_eq!(h.len(), 64);
        assert_eq!(token_hash(&a), Some(h));
        assert_ne!(token_hash(&a), token_hash(&b));
    }

    #[test]
    fn foreign_tokens_are_never_looked_up() {
        assert_eq!(token_hash("bt_abc"), None);
        assert_eq!(token_hash(""), None);
        assert_eq!(token_hash(&format!("ai_{}", "x".repeat(200))), None);
        assert!(token_hash("ai_x").is_some());
    }
}
