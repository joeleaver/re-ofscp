//! Account invites (spec §4.1.1, lost-conn/ofscp#18).
//!
//! An invite is `ai_` + 256 random bits (base64url), single-use and
//! time-limited, and may pin a handle. It is shared as the link
//! `https://{authority}/register?invite={token}`. Only the token's SHA-256
//! is stored (`RegistrationInvite` in `schema.rhype`), and tokens are never
//! logged.
//!
//! Claiming creates an `InviteClaim` row, `@unique` on the token hash, and
//! only its creator marks the invite used (docs/decisions/0012), so of any
//! number of registrations presenting the same invite exactly one claims
//! it. Registration is also serialized in-process (see
//! `Accounts::register`), so a failed registration releases its claim
//! before anyone else looks.
//!
//! A claim is a lease ([`INVITE_CLAIM_LEASE_SECS`]). A claim left beside an
//! invite that is still unused (its holder crashed before marking it, or
//! could not delete the claim when releasing it) would otherwise block the
//! invite forever; once the lease has expired, the invite is still usable
//! and no account has the claim's handle, the next registration takes it
//! over.

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::db::{Db, DbError, Ql};

/// Prefix of every account invite.
pub const INVITE_PREFIX: &str = "ai_";

pub use re_ofscp_types::admin::{DEFAULT_INVITE_TTL_SECS, MAX_INVITE_TTL_SECS};

/// How long an invite claim (a lease) lives. Its holder marks the invite
/// used in one guarded update, which the data layer times out after 10 s,
/// and creates the account in the next statement; a claim older than this
/// was abandoned, and may be taken over (docs/decisions/0012).
pub const INVITE_CLAIM_LEASE_SECS: i64 = 120;

/// Attempts at one claim before giving up (failing closed).
const CLAIM_PASSES: usize = 4;

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

/// A claim this registration holds on an invite, returned by
/// [`InviteStore::claim`] and given back to [`InviteStore::release`] so that
/// exactly this claim, and no later one, is dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteClaim {
    id: u64,
    token_hash: String,
    handle: String,
}

/// Any row (only its id matters).
#[derive(Deserialize)]
struct Exists {}

#[derive(Deserialize)]
struct ClaimRow {
    handle: String,
    expires_at: String,
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
    /// unexpired at `now`. `None` if it was not (used meanwhile, expired, or
    /// claimed by a registration in flight).
    ///
    /// The `used == false` guard alone is not compare-and-set (decision
    /// 0012), so the claim is made first as an `InviteClaim` row, `@unique`
    /// on the token hash: of any number of registrations presenting the
    /// invite, in this process or another, only the one that creates it
    /// goes on to mark the invite used.
    pub async fn claim(
        &self,
        token_hash: &str,
        handle: &str,
        now: i64,
    ) -> Result<Option<InviteClaim>, DbError> {
        let Some(claim) = self.take_claim(token_hash, handle, now).await? else {
            return Ok(None);
        };
        // Ours alone from here: no other request writes `used: true`.
        let q = Ql::new("RegistrationInvite.filter(.token_hash == ")
            .str(token_hash)
            .raw(" && .used == false && .expires_at > ")
            .unix_seconds(now)
            .raw(").update({ used: true, used_at: ")
            .unix_seconds(now)
            .raw(", used_by: ")
            .str(handle)
            .raw(" })");
        match self.db.write_rows(&q).await.map(|r| r.into_objects().len()) {
            Ok(1..) => Ok(Some(claim)),
            // Unusable (expired, revoked, or used before claims existed):
            // drop our claim, which guards nothing.
            Ok(_) => {
                self.drop_claim(claim.id).await?;
                Ok(None)
            }
            // Failed, or perhaps landed with its reply lost. Either way no
            // account is made under this claim, so drop it rather than
            // leave it beside an invite that may still read as unused. (Had
            // the update landed, the invite reads as used and a later claim
            // finds it so.) Should the drop fail too, the lease frees it.
            Err(e) => {
                if let Err(d) = self.drop_claim(claim.id).await {
                    tracing::warn!(
                        error = %d,
                        "could not drop an invite claim after a failed update; \
                         its lease will free it"
                    );
                }
                Err(e)
            }
        }
    }

    /// Create the claim on `token_hash` for `handle`, taking over an
    /// abandoned one. `None` if a live claim holds it, or an expired one
    /// that is not abandoned (see [`InviteStore::abandoned`]).
    ///
    /// Race-safe as in `Claims::claim`: the winner is decided only by the
    /// `@unique` create, never by the read or the delete. A taker deletes
    /// the expired claim **by id**, so it can never delete a fresh claim
    /// another taker created meanwhile (that delete is `NotFound`, treated
    /// as "someone else deleted it"); of any number of takers, exactly one
    /// create then succeeds, and the rest conflict, read the new claim, find
    /// it live and lose.
    async fn take_claim(
        &self,
        token_hash: &str,
        handle: &str,
        now: i64,
    ) -> Result<Option<InviteClaim>, DbError> {
        let create = Ql::new("InviteClaim.create({ token_hash: ")
            .str(token_hash)
            .raw(", handle: ")
            .str(handle)
            .raw(", claimed_at: ")
            .unix_seconds(now)
            .raw(", expires_at: ")
            .unix_seconds(now + INVITE_CLAIM_LEASE_SECS)
            .raw(" })");
        // Several passes: another follows a takeover, a holder that dropped
        // its claim between our create and our read, or a create aborted by
        // a concurrent one (`Contended`: nothing written) before that one is
        // visible.
        for _ in 0..CLAIM_PASSES {
            match self.db.write_one::<Exists>(&create).await {
                Ok(row) => {
                    return Ok(Some(InviteClaim {
                        id: row.id,
                        token_hash: token_hash.to_owned(),
                        handle: handle.to_owned(),
                    }));
                }
                Err(DbError::Conflict(_) | DbError::Contended(_)) => {}
                Err(e) => return Err(e),
            }
            let q = Ql::new("InviteClaim.filter(.token_hash == ")
                .str(token_hash)
                .raw(")");
            let Some(held) = self.db.fetch::<ClaimRow>(&q).await?.into_iter().next() else {
                continue;
            };
            let held_until = OffsetDateTime::parse(&held.data.expires_at, &Rfc3339)
                .map_err(|e| DbError::Decode(format!("invite claim expiry: {e}")))?
                .unix_timestamp();
            if held_until > now || !self.abandoned(token_hash, &held.data.handle, now).await? {
                return Ok(None);
            }
            let delete = Ql::new("InviteClaim.get(").uint(held.id).raw(").delete()");
            match self.db.execute(&delete).await {
                // Deleted (or being deleted) by a concurrent taker.
                Ok(()) | Err(DbError::NotFound(_) | DbError::Contended(_)) => {}
                Err(e) => return Err(e),
            }
        }
        // Never decided: neither ours nor a visible holder's. Fail closed.
        Err(DbError::Contended(
            "invite claim stayed contended".to_owned(),
        ))
    }

    /// Whether an expired claim by `handle` on `token_hash` was abandoned:
    /// the invite is still usable at `now` (its holder never marked it, or
    /// marked it and released it) and no account has `handle` (it made
    /// none). A claim whose invite reads used is the record of a
    /// registration, and is kept. An account with `handle` made some other
    /// way also keeps it, conservatively: the owner then revokes the invite.
    async fn abandoned(&self, token_hash: &str, handle: &str, now: i64) -> Result<bool, DbError> {
        if self.find_usable(token_hash, now).await?.is_none() {
            return Ok(false);
        }
        let q = Ql::new("User.filter(.handle == ")
            .str(handle)
            .raw(").limit(1)");
        Ok(self.db.fetch::<Exists>(&q).await?.is_empty())
    }

    /// Delete exactly the claim `id` (a claim is never updated, and a later
    /// one has another id). Already gone is fine.
    async fn drop_claim(&self, id: u64) -> Result<(), DbError> {
        let drop = Ql::new("InviteClaim.get(").uint(id).raw(").delete()");
        match self.db.execute(&drop).await {
            Ok(()) | Err(DbError::NotFound(_)) => Ok(()),
            Err(e) => Err(e),
        }
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
    ///
    /// The `expires_at > now` guard is not compare-and-set (decision 0012),
    /// and needs not be: concurrent revocations all write the same expiry,
    /// and a claim racing a revocation is the in-flight registration above.
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
    /// so the invite stays usable. Only the claim's holder calls this, with
    /// the claim it was given. The invite is marked unused before the claim
    /// is dropped, so a new claim always finds it unused; the `used == true`
    /// guard is idempotent. The claim is dropped by id, so a release can
    /// never drop a later registration's claim. If the drop fails, the
    /// claim's lease frees the invite.
    pub async fn release(&self, claim: &InviteClaim) -> Result<(), DbError> {
        let q = Ql::new("RegistrationInvite.filter(.token_hash == ")
            .str(&claim.token_hash)
            .raw(" && .used == true && .used_by == ")
            .str(&claim.handle)
            .raw(").update({ used: false })");
        self.db.write_rows(&q).await?;
        self.drop_claim(claim.id).await
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
