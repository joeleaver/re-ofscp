//! Account invites (spec §4.1.1, lost-conn/ofscp#18).
//!
//! An invite is `ai_` + 256 random bits (base64url), single-use and
//! time-limited, and may pin a handle. It is shared as the link
//! `https://{authority}/register?invite={token}`. Only the token's SHA-256
//! is stored (`RegistrationInvite` in `schema.rhype`), and tokens are never
//! logged.
//!
//! Redeeming creates an `InviteRedemption` row, `@unique` on the token
//! hash and recording the handle, before the account is created
//! (docs/decisions/0012). The row is never updated, deleted or taken over:
//! whatever happens to the registration, that invite can only ever make an
//! account with that handle, and handles are unique, so one invite makes at
//! most one account. A registration for the same handle may resume a
//! redemption whose account was never made (its request crashed or
//! failed); one for any other handle is refused. `RegistrationInvite.used`
//! mirrors the redemption, and every read that says an invite is usable
//! also checks that no redemption exists.

use std::collections::HashSet;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::db::{Db, DbError, Ql};

/// Prefix of every account invite.
pub const INVITE_PREFIX: &str = "ai_";

pub use re_ofscp_types::admin::{DEFAULT_INVITE_TTL_SECS, MAX_INVITE_TTL_SECS};

/// Attempts at one redemption before giving up (failing closed).
const REDEEM_PASSES: usize = 4;

/// Token hashes per query when checking invites for redemptions.
const REDEMPTION_CHECK_CHUNK: usize = 50;

/// Longest token accepted from a client. Ours are 46 characters; anything
/// much longer is not one of ours and is refused without a lookup.
const MAX_TOKEN_LEN: usize = 128;

/// An unexpired invite, as read from the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    /// SHA-256 of the token, hex.
    pub token_hash: String,
    /// The pinned handle, if any.
    pub handle: Option<String>,
    /// The handle it was redeemed for, if it is marked used.
    pub used_by: Option<String>,
}

/// What [`InviteStore::revoke`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Revoked {
    /// It was usable and is now expired.
    Revoked,
    /// It was already used (or redeemed by a registration in flight); it is
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
struct RedemptionRow {
    token_hash: String,
    handle: String,
}

#[derive(Deserialize)]
struct InviteRow {
    token_hash: String,
    #[serde(default)]
    handle: Option<String>,
    used: bool,
    #[serde(default)]
    used_by: Option<String>,
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

    /// The invite with `token_hash`, if it is unexpired at `now`, used or
    /// not. Registration reads this first: an unused invite, or one used by
    /// the registering handle (which may resume it), goes on.
    pub async fn find_live(&self, token_hash: &str, now: i64) -> Result<Option<Invite>, DbError> {
        let q = Ql::new("RegistrationInvite.filter(.token_hash == ")
            .str(token_hash)
            .raw(" && .expires_at > ")
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
                // `used_by` outlives a release by an earlier version, which
                // set `used` back to false; only `used` says it is spent.
                used_by: r.data.used.then_some(r.data.used_by).flatten(),
            }))
    }

    /// The invite with `token_hash`, if it is unused and unexpired at `now`
    /// and has no redemption.
    pub async fn find_usable(&self, token_hash: &str, now: i64) -> Result<Option<Invite>, DbError> {
        match self.find_live(token_hash, now).await? {
            Some(i) if i.used_by.is_none() && self.redeemed_by(token_hash).await?.is_none() => {
                Ok(Some(i))
            }
            _ => Ok(None),
        }
    }

    /// Redeem the invite with `token_hash` for `handle` at `now`: `true` if
    /// the caller may now create the account `handle` under it, `false` if
    /// the invite is spent on another handle, expired or revoked.
    ///
    /// The `used == false` guard alone is not compare-and-set (decision
    /// 0012), so the redemption is an `InviteRedemption` row, `@unique` on
    /// the token hash: of any number of registrations presenting the
    /// invite, in this process or another, exactly one creates it, and it
    /// names the only handle the invite can ever make an account for. It is
    /// never deleted, so a slow or crashed request can never let a second
    /// handle through. A registration for the same handle finding it
    /// resumes it (`true`): if the first request's account exists, the
    /// account create then fails as the handle is taken, and if it never
    /// came to be, this one makes it. Either way one account at most.
    pub async fn redeem(&self, token_hash: &str, handle: &str, now: i64) -> Result<bool, DbError> {
        let create = Ql::new("InviteRedemption.create({ token_hash: ")
            .str(token_hash)
            .raw(", handle: ")
            .str(handle)
            .raw(", redeemed_at: ")
            .unix_seconds(now)
            .raw(" })");
        // Several passes: a create aborted by a concurrent one (`Contended`:
        // nothing written) before that one is visible.
        for _ in 0..REDEEM_PASSES {
            match self.db.execute(&create).await {
                Ok(()) => return self.mark_used(token_hash, handle, now).await,
                Err(DbError::Conflict(_) | DbError::Contended(_)) => {}
                Err(e) => return Err(e),
            }
            match self.redeemed_by(token_hash).await? {
                Some(by) if by == handle => return self.mark_used(token_hash, handle, now).await,
                Some(_) => return Ok(false),
                None => {}
            }
        }
        // Never decided: neither ours nor a visible holder's. Fail closed.
        Err(DbError::Contended(
            "invite redemption stayed contended".to_owned(),
        ))
    }

    /// Mark the invite used by `handle`, the handle of its redemption, if it
    /// is unexpired at `now`. `false` if it expired or was revoked (the
    /// redemption stays: the invite is dead anyway).
    ///
    /// Only callers holding the redemption for `handle` write here, and a
    /// redemption's handle never changes, so concurrent writers (a resumed
    /// registration beside the first) all write the same `used_by`; the
    /// `expires_at` guard narrows, it decides no race.
    async fn mark_used(&self, token_hash: &str, handle: &str, now: i64) -> Result<bool, DbError> {
        let q = Ql::new("RegistrationInvite.filter(.token_hash == ")
            .str(token_hash)
            .raw(" && .expires_at > ")
            .unix_seconds(now)
            .raw(").update({ used: true, used_at: ")
            .unix_seconds(now)
            .raw(", used_by: ")
            .str(handle)
            .raw(" })");
        // A concurrent write to the invite (a resumer marking it too, or a
        // revocation) can abort ours with `Contended`, which wrote nothing:
        // write again.
        for _ in 0..REDEEM_PASSES {
            match self.db.write_rows(&q).await {
                Ok(rows) => return Ok(!rows.into_objects().is_empty()),
                Err(DbError::Contended(_)) => {}
                Err(e) => return Err(e),
            }
        }
        Err(DbError::Contended(
            "marking an invite used stayed contended".to_owned(),
        ))
    }

    /// The handle the invite with `token_hash` was redeemed for, if any.
    async fn redeemed_by(&self, token_hash: &str) -> Result<Option<String>, DbError> {
        let q = Ql::new("InviteRedemption.filter(.token_hash == ")
            .str(token_hash)
            .raw(")");
        Ok(self
            .db
            .fetch::<RedemptionRow>(&q)
            .await?
            .into_iter()
            .next()
            .map(|r| r.data.handle))
    }

    /// Which of `hashes` have a redemption. A redemption is created before
    /// its invite is marked used, so an invite can read unused with one
    /// beside it (its request crashed in between); this is what keeps the
    /// usable lists exact.
    async fn redeemed(&self, hashes: &[&str]) -> Result<HashSet<String>, DbError> {
        let mut found = HashSet::new();
        for chunk in hashes.chunks(REDEMPTION_CHECK_CHUNK) {
            let Some((first, rest)) = chunk.split_first() else {
                continue;
            };
            let mut q = Ql::new("InviteRedemption.filter(.token_hash == ").str(first);
            for h in rest {
                q = q.raw(" || .token_hash == ").str(h);
            }
            let q = q.raw(")");
            found.extend(
                self.db
                    .fetch::<RedemptionRow>(&q)
                    .await?
                    .into_iter()
                    .map(|r| r.data.token_hash),
            );
        }
        Ok(found)
    }

    /// Up to `limit` invites usable at `now` (unused, unexpired, and with no
    /// redemption), in no particular order.
    pub async fn list_usable(&self, now: i64, limit: usize) -> Result<Vec<InviteSummary>, DbError> {
        // Redeemed invites still reading unused are rare (a crash between
        // two statements); fetch past them until `limit` usable ones are
        // found or there are no more.
        let mut want = limit;
        loop {
            let q = Ql::new("RegistrationInvite.filter(.used == false && .expires_at > ")
                .unix_seconds(now)
                .raw(").limit(")
                .uint(want as u64)
                .raw(")");
            let candidates: Vec<InviteSummary> = self
                .db
                .fetch::<InviteSummary>(&q)
                .await?
                .into_iter()
                .map(|r| r.data)
                .collect();
            let fetched = candidates.len();
            let hashes: Vec<&str> = candidates.iter().map(|i| i.token_hash.as_str()).collect();
            let redeemed = self.redeemed(&hashes).await?;
            let mut usable: Vec<InviteSummary> = candidates
                .into_iter()
                .filter(|i| !redeemed.contains(&i.token_hash))
                .collect();
            if usable.len() >= limit || fetched < want || redeemed.is_empty() {
                usable.truncate(limit);
                return Ok(usable);
            }
            want = fetched + redeemed.len();
        }
    }

    /// Revoke the invite with `token_hash` by expiring it at `now`.
    /// [`Revoked::Unknown`] if no unexpired invite has that hash.
    ///
    /// The invite is expired even when it is redeemed: a registration in
    /// flight may still complete (a revocation racing it is too late), and
    /// [`Revoked::Used`] then says it was already used or being used.
    ///
    /// The `expires_at > now` guard is not compare-and-set (decision 0012),
    /// and needs not be: concurrent revocations all write the same expiry.
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
            Some(_) if self.redeemed_by(token_hash).await?.is_some() => Revoked::Used,
            Some(_) => Revoked::Revoked,
        })
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
