//! Revision claims (`GroupClaim` in `schema.rhype`): `@unique` rows that
//! make an edit of a group or channel the only edit of its revision
//! (docs/decisions/0014).
//!
//! Since rhypedb #59 (in 7b78190) a guarded `update` is compare-and-set per
//! object: the filter is re-checked inside each object's write transaction,
//! so of two PATCHes that both read revision `n` only one
//! `filter(.revision == n).update(...)` writes. The claim predates that and
//! could become a plain guarded update (docs/decisions/0012, 0014); it is
//! kept for now, and still backs the guard if a holder's statement is late.
//! A `create` on a `@unique` field is atomic, so an edit from revision `n`
//! first claims revision `n + 1` and writes only if it created the claim.
//! Every other edit read at `n` loses the claim, reads again and edits the
//! newer revision.
//!
//! A claim is a lease, stamped with the clock when it is created. Its
//! holder writes once, at once, in one statement that is never retried.
//! A claim that outlived [`LEASE_SECS`] unused is taken to belong to a
//! writer that died, and the next edit takes it over. This assumes that
//! the server applies the holder's statement within the lease. The data
//! layer's 10 s timeout only stops the client waiting; it does not cancel
//! the statement on the server (docs/decisions/0014). Claims are never
//! updated, so a filter over them is exact; [`GroupStore::purge_claims`]
//! deletes the expired ones.
//!
//! A holder whose one write wrote nothing (its compare-and-set missed, or
//! it lost a conflict, or the object was gone) releases its claim
//! ([`GroupStore::release`]) before it retries. Otherwise a retry that
//! reads the same revision again (nothing moved it) would find its own
//! claim still leased and give up, and every edit of the object would wait
//! out the lease. Releasing is safe because the write's compare-and-set on
//! the revision, not the claim, is what refuses a stale edit.

use serde::Deserialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::store::GroupStore;
use crate::db::{DbError, Ql};

/// How long a claim is held. Its holder writes in one statement right after
/// claiming, so a claim past this is taken to be a dead writer's, and its
/// revision is free again. The data layer stops waiting for the statement
/// after 10 s; the server is assumed to apply it well within this.
pub const LEASE_SECS: i64 = 120;

/// Claims deleted per purge statement, and statements per purge run.
const PURGE_BATCH: u64 = 1_000;
const PURGE_MAX_BATCHES: usize = 100;

/// The claim on revision `revision` of group `group_id`. Ids are base64url
/// (§2.2: no `:`) and a revision is a number, so no two (kind, id,
/// revision) triples share a key.
pub fn group_key(group_id: &str, revision: i64) -> String {
    format!("group:{group_id}:{revision}")
}

/// The claim on revision `revision` of channel `channel_id`.
pub fn channel_key(channel_id: &str, revision: i64) -> String {
    format!("channel:{channel_id}:{revision}")
}

#[derive(Deserialize)]
struct ClaimRow {
    expires_at: String,
}

impl GroupStore {
    /// Claim `key` at `now` for the lease (`LEASE_SECS`). `true` if this
    /// call holds the claim; `false` if a live claim already does. An
    /// expired claim is taken over.
    pub async fn claim(&self, key: &str, now: i64) -> Result<bool, DbError> {
        // Two passes: the second follows a takeover of an expired claim, or
        // a purge that removed the holder between our create and our read.
        for _ in 0..2 {
            let create = Ql::new("GroupClaim.create({ key: ")
                .str(key)
                .raw(", created_at: ")
                .unix_seconds(now)
                .raw(", expires_at: ")
                .unix_seconds(now.saturating_add(LEASE_SECS))
                .raw(" })");
            match self.db.execute(&create).await {
                Ok(()) => return Ok(true),
                // Taken (`@unique`), or lost the race to create it.
                Err(DbError::Conflict(_) | DbError::Contended(_)) => {}
                Err(e) => return Err(e),
            }
            let q = Ql::new("GroupClaim.filter(.key == ").str(key).raw(")");
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
            // meanwhile is untouched), then compete for the key again.
            let delete = Ql::new("GroupClaim.get(").uint(held.id).raw(").delete()");
            match self.db.execute(&delete).await {
                // Gone already, or going: another taker or the purge deleted
                // it (claims are never updated, so a write that conflicts
                // with this delete is another delete).
                Ok(()) | Err(DbError::Vanished(_) | DbError::Contended(_)) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(false)
    }

    /// Release the claim on `key` made at `claimed_at` (the `now` passed
    /// to [`Self::claim`]), after its holder's one write wrote nothing.
    /// Only that claim is deleted: one taken over since was made at a later
    /// time. A claim already gone is fine.
    pub async fn release(&self, key: &str, claimed_at: i64) -> Result<(), DbError> {
        let q = Ql::new("GroupClaim.filter(.key == ")
            .str(key)
            .raw(" && .created_at == ")
            .unix_seconds(claimed_at)
            .raw(").delete()");
        match self.db.execute(&q).await {
            // Deleted meanwhile by the purge (claims are never updated).
            Ok(()) | Err(DbError::Vanished(_) | DbError::Contended(_)) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Delete claims expired by `now`, in bounded batches (a backlog drains
    /// over successive runs). Claims are never updated, so the filter's
    /// snapshot is exact: no live claim is deleted.
    pub async fn purge_claims(&self, now: i64) -> Result<(), DbError> {
        for _ in 0..PURGE_MAX_BATCHES {
            let q = Ql::new("GroupClaim.filter(.expires_at <= ")
                .unix_seconds(now)
                .raw(").limit(")
                .uint(PURGE_BATCH)
                .raw(").delete()");
            match self.db.execute(&q).await {
                // A row deleted meanwhile is skipped (rhypedb 7b78190); a
                // conflict that outlasts rhypedb's own retries is left to the
                // next batch. `Vanished` remains for an older server.
                Ok(()) | Err(DbError::Vanished(_) | DbError::Contended(_)) => {}
                Err(e) => return Err(e),
            }
            let probe = Ql::new("GroupClaim.filter(.expires_at <= ")
                .unix_seconds(now)
                .raw(").limit(1)");
            if self
                .db
                .fetch::<serde::de::IgnoredAny>(&probe)
                .await?
                .is_empty()
            {
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
    fn keys_name_the_kind_the_object_and_the_revision() {
        assert_eq!(group_key("grp_a", 7), "group:grp_a:7");
        assert_eq!(channel_key("chn_a", 7), "channel:chn_a:7");
        assert_ne!(group_key("grp_a", 17), group_key("grp_a1", 7));
        assert_ne!(group_key("x", 1), channel_key("x", 1));
    }
}
