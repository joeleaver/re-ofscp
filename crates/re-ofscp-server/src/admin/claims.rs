//! Claims: `@unique` rows (`AdminClaim` in `schema.rhype`) that serialize
//! security-relevant admin writes (docs/decisions/0012).
//!
//! Since rhypedb #59 (in 7b78190) a single guarded `update` is
//! compare-and-set per object, so a guard alone would now settle either race
//! below; these claims predate that and could become guarded updates (see
//! docs/decisions/0012, "Update"). They are kept because a claim also covers
//! a sequence of statements, and its expiry recovers from a holder that
//! died. A `create` on a `@unique` field is atomic, so the competing paths
//! first create a claim row under a key that names exactly what they
//! compete for, and only the creator proceeds:
//!
//! - **TOTP steps** (`totp-step:{username}:{step}`): a code is accepted only
//!   by the sign-in (or enrollment) that claims its step, so each code works
//!   once, however many requests carry it at the same moment.
//! - **Credential epochs** (`epoch:{username}:{epoch}`): a credential change
//!   (password changed, TOTP confirmed or reset) moves the admin from epoch
//!   `e` to `e + 1`, and only the holder of the claim on `e + 1` may write it.
//!   Without this, two changes read at `e` could both apply and both stamp
//!   their sessions `e + 1`, so a TOTP reset would not end the session of a
//!   password change racing it.
//!
//! Claims are never updated, so a filter over them is exact. Each has an
//! expiry: a TOTP claim outlives every moment its code could still verify,
//! and an epoch claim is a lease that frees the next epoch if its holder
//! died before writing it. An expired claim may be taken over by deleting
//! it (by id) and claiming again; [`Claims::purge`] deletes the rest.

use std::sync::Arc;

use serde::Deserialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::db::{Db, DbError, Ql};

/// How long a TOTP step claim lives. A code verifies for at most
/// `(2 * SKEW_STEPS + 1) * STEP_SECS` seconds (90); a day leaves room for a
/// wall clock stepped back by hours, while `Admin.totp_last_step` (kept
/// as the highest step used) refuses older steps beyond that.
pub const TOTP_CLAIM_SECS: i64 = 24 * 60 * 60;

/// How long an epoch claim (a lease) lives. It is held across one guarded
/// update, which the data layer times out after 10 s; once it has expired
/// unused, the next change may take it over.
pub const EPOCH_LEASE_SECS: i64 = 120;

/// Attempts at one claim before giving up (failing closed).
const CLAIM_PASSES: usize = 4;

/// Claims deleted per purge statement, and statements per purge run.
const PURGE_BATCH: u64 = 1_000;
const PURGE_MAX_BATCHES: usize = 100;

/// The claim key for `username`'s TOTP time step `step`. Usernames cannot
/// contain `:` (`^[a-z0-9][a-z0-9_.-]{2,63}$`), and a step is a number, so
/// no two (username, step) pairs share a key.
pub fn totp_step_key(username: &str, step: i64) -> String {
    format!("totp-step:{username}:{step}")
}

/// The claim key for `username`'s credential epoch `epoch`.
pub fn epoch_key(username: &str, epoch: i64) -> String {
    format!("epoch:{username}:{epoch}")
}

#[derive(Deserialize)]
struct ClaimRow {
    expires_at: String,
}

/// Any row (only its existence matters).
#[derive(Deserialize)]
struct Exists {}

/// Claim storage.
#[derive(Debug, Clone)]
pub struct Claims {
    db: Arc<Db>,
}

impl Claims {
    /// Claims over `db`.
    pub fn new(db: Arc<Db>) -> Self {
        Self { db }
    }

    /// Claim `key` for `username` until `expires_at`. `true` if this call
    /// created the claim; `false` if a live claim already holds the key.
    /// An expired one is taken over.
    pub async fn claim(
        &self,
        key: &str,
        username: &str,
        expires_at: i64,
        now: i64,
    ) -> Result<bool, DbError> {
        // Several passes: another follows a takeover of an expired claim, a
        // purge that removed the holder between our create and our read, or
        // a create aborted by a concurrent one (`Contended`: nothing was
        // written) before that one is visible.
        for _ in 0..CLAIM_PASSES {
            let create = Ql::new("AdminClaim.create({ key: ")
                .str(key)
                .raw(", username: ")
                .str(username)
                .raw(", created_at: ")
                .unix_seconds(now)
                .raw(", expires_at: ")
                .unix_seconds(expires_at)
                .raw(" })");
            match self.db.execute(&create).await {
                Ok(()) => return Ok(true),
                Err(DbError::Conflict(_) | DbError::Contended(_)) => {}
                Err(e) => return Err(e),
            }
            let q = Ql::new("AdminClaim.filter(.key == ").str(key).raw(")");
            let Some(held) = self.db.fetch::<ClaimRow>(&q).await?.into_iter().next() else {
                continue;
            };
            let held_until = OffsetDateTime::parse(&held.data.expires_at, &Rfc3339)
                .map_err(|e| DbError::Decode(format!("claim expiry: {e}")))?
                .unix_timestamp();
            if held_until > now {
                return Ok(false);
            }
            // Expired: delete exactly that row (by id, so a fresh claim made
            // meanwhile is untouched; a concurrent taker deleting it first
            // leaves nothing to find), then compete for the key again.
            let delete = Ql::new("AdminClaim.get(").uint(held.id).raw(").delete()");
            match self.db.execute(&delete).await {
                // Deleted (or being deleted) by a concurrent taker.
                Ok(()) | Err(DbError::Vanished(_) | DbError::Contended(_)) => {}
                Err(e) => return Err(e),
            }
        }
        // Never decided: neither ours nor a visible holder's. Fail closed.
        Err(DbError::Contended(format!(
            "claim {key:?} stayed contended"
        )))
    }

    /// Delete claims expired by `now`, in bounded batches (a backlog drains
    /// over successive runs). Claims are never updated, so the filter's
    /// snapshot is exact: no live claim is deleted.
    pub async fn purge(&self, now: i64) -> Result<(), DbError> {
        for _ in 0..PURGE_MAX_BATCHES {
            let q = Ql::new("AdminClaim.filter(.expires_at <= ")
                .unix_seconds(now)
                .raw(").limit(")
                .uint(PURGE_BATCH)
                .raw(").delete()");
            match self.db.execute(&q).await {
                // A claim it selected was deleted meanwhile (taken over):
                // the statement stopped there; the next batch goes on.
                Ok(()) | Err(DbError::Vanished(_) | DbError::Contended(_)) => {}
                Err(e) => return Err(e),
            }
            let probe = Ql::new("AdminClaim.filter(.expires_at <= ")
                .unix_seconds(now)
                .raw(").limit(1)");
            if self.db.fetch::<Exists>(&probe).await?.is_empty() {
                break;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_name_the_kind_the_admin_and_the_number() {
        assert_eq!(totp_step_key("alice", 7), "totp-step:alice:7");
        assert_eq!(epoch_key("alice", 7), "epoch:alice:7");
        assert_ne!(totp_step_key("alice", 7), epoch_key("alice", 7));
        assert_ne!(totp_step_key("alice", 17), totp_step_key("alice1", 7));
    }
}
