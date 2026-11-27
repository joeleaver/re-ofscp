//! Group invites in rhypedb (`GroupInvite` and `GroupInviteUse` in
//! `schema.rhype`; spec §5.6, docs/decisions/0019).
//!
//! Only the token's SHA-256 is stored, so the token cannot be read back.
//! A limited invite's uses are slot rows: slot `n` of invite `i` is a
//! `GroupInviteUse` whose `@unique` `slot` is `"{i} {n}"`, for `n <
//! max_uses`. Creating a slot is the one serialized step (decision 0012),
//! so concurrent redemptions never use more slots than exist. A slot is
//! only ever created and deleted (given back), never updated. An unlimited
//! invite has no slots. Every invite's `uses` counter is a guarded
//! increment after each join, compare-and-set per object since rhypedb
//! #59, and counts only for display: the list reads it rather than the
//! slot rows.

use re_ofscp_types::Actor;
use serde::Deserialize;

use super::store::GroupStore;
use crate::db::doc::new_id;
use crate::db::{DbError, Ql};
use crate::timefmt;

/// How many times an unlimited invite's counter is re-read and bumped
/// before giving up. A bump loses only to another that landed, so this
/// many concurrent redemptions all count. The count is for display;
/// nothing depends on it.
const BUMP_ATTEMPTS: usize = 64;

#[derive(Deserialize)]
struct InviteRow {
    invite_id: String,
    group_id: String,
    #[serde(default)]
    channel_id: Option<String>,
    role: String,
    #[serde(default)]
    max_uses: Option<i64>,
    uses: i64,
    #[serde(default)]
    expires_at: Option<String>,
    created_by: String,
    created_at: String,
}

impl InviteRow {
    fn decode(self) -> Result<StoredInvite, DbError> {
        let bad = |what: &str| DbError::Decode(format!("invite {}: bad {what}", self.invite_id));
        let max_uses = match self.max_uses {
            None => None,
            Some(n) => Some(u32::try_from(n).map_err(|_| bad("max_uses"))?),
        };
        let expires_at = match &self.expires_at {
            None => None,
            Some(t) => Some(timefmt::unix(t).ok_or_else(|| bad("expires_at"))?),
        };
        Ok(StoredInvite {
            created_by: Actor::parse_canonical(&self.created_by).map_err(|_| bad("created_by"))?,
            created_at: timefmt::unix(&self.created_at).ok_or_else(|| bad("created_at"))?,
            counter: u32::try_from(self.uses).map_err(|_| bad("uses"))?,
            max_uses,
            expires_at,
            id: self.invite_id,
            group_id: self.group_id,
            channel_id: self.channel_id,
            role: self.role,
        })
    }
}

/// An invite, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredInvite {
    /// Local id (`inv_…`).
    pub id: String,
    /// The group.
    pub group_id: String,
    /// The channel to land in, if any.
    pub channel_id: Option<String>,
    /// The role a redemption gives.
    pub role: String,
    /// How many redemptions it allows; `None` is unlimited.
    pub max_uses: Option<u32>,
    /// Joins by this invite so far, for display (`uses`). A limited
    /// invite's limit is enforced by its slots ([`GroupStore::slots_taken`]),
    /// never by this count.
    pub counter: u32,
    /// Unix seconds from which it no longer works; `None` is never.
    pub expires_at: Option<i64>,
    /// Who made it.
    pub created_by: Actor,
    /// When (unix seconds).
    pub created_at: i64,
}

impl StoredInvite {
    /// Whether it has expired at `now` (unix seconds).
    pub fn expired(&self, now: i64) -> bool {
        self.expires_at.is_some_and(|at| at <= now)
    }
}

/// A new invite's terms, validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteTerms {
    /// The channel to land in.
    pub channel_id: Option<String>,
    /// The role it gives.
    pub role: String,
    /// How many uses it allows; `None` is unlimited.
    pub max_uses: Option<u32>,
    /// When it expires (unix seconds); `None` is never.
    pub expires_at: Option<i64>,
}

#[derive(Deserialize)]
struct SlotRow {
    slot: String,
}

/// The `@unique` key of slot `n` of `invite_id`.
fn slot_key(invite_id: &str, n: u32) -> String {
    format!("{invite_id} {n}")
}

/// The slot number of a slot row of `invite_id`, if it is one.
fn slot_number(row: &SlotRow, invite_id: &str) -> Option<u32> {
    row.slot
        .strip_prefix(invite_id)?
        .strip_prefix(' ')?
        .parse()
        .ok()
}

fn decode_all(rows: Vec<rhypedb_client::Row<InviteRow>>) -> Result<Vec<StoredInvite>, DbError> {
    rows.into_iter().map(|r| r.data.decode()).collect()
}

impl GroupStore {
    /// Record an invite of `group_id` by `creator`, whose token hashes to
    /// `token_hash`. The caller has checked the group and the terms.
    pub async fn create_invite(
        &self,
        group_id: &str,
        creator: &Actor,
        terms: &InviteTerms,
        token_hash: &str,
        now: i64,
    ) -> Result<StoredInvite, DbError> {
        // One retry covers a (vanishingly unlikely) id collision. The
        // token is fresh too, so a clash there is the same accident.
        for _ in 0..2 {
            let id = new_id("inv_")?;
            let mut q = Ql::new("GroupInvite.create({ invite_id: ")
                .str(&id)
                .raw(", token_hash: ")
                .str(token_hash)
                .raw(", group_id: ")
                .str(group_id)
                .raw(", role: ")
                .str(&terms.role)
                .raw(", uses: 0, created_by: ")
                .str(&creator.to_string())
                .raw(", created_at: ")
                .unix_seconds(now);
            if let Some(c) = &terms.channel_id {
                q = q.raw(", channel_id: ").str(c);
            }
            if let Some(n) = terms.max_uses {
                q = q.raw(", max_uses: ").uint(u64::from(n));
            }
            if let Some(at) = terms.expires_at {
                q = q.raw(", expires_at: ").unix_seconds(at);
            }
            match self.db.execute(&q.raw(" })")).await {
                Ok(()) => {
                    return Ok(StoredInvite {
                        id,
                        group_id: group_id.to_owned(),
                        channel_id: terms.channel_id.clone(),
                        role: terms.role.clone(),
                        max_uses: terms.max_uses,
                        counter: 0,
                        expires_at: terms.expires_at,
                        created_by: creator.clone(),
                        created_at: now,
                    });
                }
                Err(DbError::Conflict(_) | DbError::Contended(_)) => {}
                Err(e) => return Err(e),
            }
        }
        Err(DbError::Query(
            "could not allocate a unique invite id".to_owned(),
        ))
    }

    /// The invite whose token hashes to `token_hash`, if any (expired
    /// ones included).
    pub async fn invite_by_token(&self, token_hash: &str) -> Result<Option<StoredInvite>, DbError> {
        let q = Ql::new("GroupInvite.filter(.token_hash == ")
            .str(token_hash)
            .raw(")");
        Ok(decode_all(self.db.fetch::<InviteRow>(&q).await?)?
            .into_iter()
            .next())
    }

    /// Invite `invite_id` of `group_id`, if any (expired ones included).
    pub async fn invite(
        &self,
        group_id: &str,
        invite_id: &str,
    ) -> Result<Option<StoredInvite>, DbError> {
        let q = Ql::new("GroupInvite.filter(.invite_id == ")
            .str(invite_id)
            .raw(")");
        Ok(decode_all(self.db.fetch::<InviteRow>(&q).await?)?
            .into_iter()
            .find(|i| i.group_id == group_id))
    }

    /// The invites of `group_id` (expired ones included), at most `cap`,
    /// in no order.
    pub async fn invites(&self, group_id: &str, cap: usize) -> Result<Vec<StoredInvite>, DbError> {
        let q = Ql::new("GroupInvite.filter(.group_id == ")
            .str(group_id)
            .raw(").limit(")
            .uint(cap as u64)
            .raw(")");
        decode_all(self.db.fetch::<InviteRow>(&q).await?)
    }

    /// Delete invite `invite_id` and its slots (a no-op if it is gone).
    /// The invite goes first, so a slot taken meanwhile finds it gone and
    /// gives itself back (`invites.rs`). A slot left by a failure between
    /// the two deletes is inert (no invite can name it again) and goes
    /// with the group.
    pub async fn delete_invite(&self, invite_id: &str) -> Result<(), DbError> {
        let invite = Ql::new("GroupInvite.filter(.invite_id == ")
            .str(invite_id)
            .raw(").delete()");
        self.db.write_one_object(&invite).await?;
        let slots = Ql::new("GroupInviteUse.filter(.invite_id == ")
            .str(invite_id)
            .raw(").delete()");
        self.db.execute(&slots).await
    }

    /// Up to `limit` ids of invites that expired by `now` (unix seconds).
    /// An invite without `expires_at` never matches.
    pub async fn expired_invites(&self, now: i64, limit: usize) -> Result<Vec<String>, DbError> {
        #[derive(Deserialize)]
        struct IdRow {
            invite_id: String,
        }
        let q = Ql::new("GroupInvite.filter(.expires_at <= ")
            .unix_seconds(now)
            .raw(").limit(")
            .uint(limit as u64)
            .raw(")");
        Ok(self
            .db
            .fetch::<IdRow>(&q)
            .await?
            .into_iter()
            .map(|r| r.data.invite_id)
            .collect())
    }

    /// Delete every invite of `group_id`, and their slots (the group's
    /// purge).
    pub(super) async fn purge_invites(&self, group_id: &str) -> Result<(), DbError> {
        let invites = Ql::new("GroupInvite.filter(.group_id == ")
            .str(group_id)
            .raw(").delete()");
        self.db.execute(&invites).await?;
        let slots = Ql::new("GroupInviteUse.filter(.group_id == ")
            .str(group_id)
            .raw(").delete()");
        self.db.execute(&slots).await
    }

    /// The slot numbers taken of limited invite `invite`.
    pub async fn slots_taken(&self, invite: &StoredInvite) -> Result<Vec<u32>, DbError> {
        let cap = invite.max_uses.unwrap_or(0);
        let q = Ql::new("GroupInviteUse.filter(.invite_id == ")
            .str(&invite.id)
            .raw(").limit(")
            .uint(u64::from(cap))
            .raw(")");
        Ok(self
            .db
            .fetch::<SlotRow>(&q)
            .await?
            .iter()
            .filter_map(|r| slot_number(&r.data, &invite.id))
            .filter(|n| *n < cap)
            .collect())
    }

    /// Take a free slot of limited invite `invite` for `actor`: the slot
    /// number taken, or `None` when every slot is taken. Of concurrent
    /// takers of one slot, exactly one creates it; the others move on. A
    /// create that lost a write conflict wrote nothing, so the same slot is
    /// tried again (`write_one_object`) rather than counted as taken: a
    /// free slot is never mistaken for an exhausted invite.
    pub async fn take_slot(
        &self,
        invite: &StoredInvite,
        actor: &Actor,
        now: i64,
    ) -> Result<Option<u32>, DbError> {
        let cap = invite.max_uses.unwrap_or(0);
        let taken = self.slots_taken(invite).await?;
        for n in (0..cap).filter(|n| !taken.contains(n)) {
            let q = Ql::new("GroupInviteUse.create({ slot: ")
                .str(&slot_key(&invite.id, n))
                .raw(", invite_id: ")
                .str(&invite.id)
                .raw(", group_id: ")
                .str(&invite.group_id)
                .raw(", actor: ")
                .str(&actor.to_string())
                .raw(", used_at: ")
                .unix_seconds(now)
                .raw(" })");
            match self.db.write_one_object(&q).await {
                Ok(_) => return Ok(Some(n)),
                // Taken by a concurrent redemption: try the next.
                Err(DbError::Conflict(_)) => {}
                // Still contended after the retries: the slot's fate is
                // unknown to us, so this is an error, never a `409`.
                Err(e) => return Err(e),
            }
        }
        Ok(None)
    }

    /// Give slot `n` of `invite_id` back (a no-op if it is gone).
    pub async fn give_back_slot(&self, invite_id: &str, n: u32) -> Result<(), DbError> {
        let q = Ql::new("GroupInviteUse.filter(.slot == ")
            .str(&slot_key(invite_id, n))
            .raw(").delete()");
        self.db.write_one_object(&q).await.map(|_| ())
    }

    /// Count one more use of unlimited invite `invite_id`. `false` if the
    /// count kept moving (or the invite is gone); the count is for display
    /// only, so that is not an error.
    pub async fn bump_uses(&self, invite_id: &str) -> Result<bool, DbError> {
        for _ in 0..BUMP_ATTEMPTS {
            let Some(current) = self.invite_counter(invite_id).await? else {
                return Ok(false);
            };
            // Compare-and-set per object (rhypedb #59): of concurrent bumps
            // from one value, exactly one applies.
            let q = Ql::new("GroupInvite.filter(.invite_id == ")
                .str(invite_id)
                .raw(" && .uses == ")
                .int(current)
                .raw(").update({ uses: ")
                .int(current.saturating_add(1))
                .raw(" })");
            match self.db.write_rows(&q).await {
                Ok(r) => {
                    if !r.into_objects().is_empty() {
                        return Ok(true);
                    }
                }
                Err(DbError::Contended(_) | DbError::Vanished(_)) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(false)
    }

    async fn invite_counter(&self, invite_id: &str) -> Result<Option<i64>, DbError> {
        #[derive(Deserialize)]
        struct UsesRow {
            uses: i64,
        }
        let q = Ql::new("GroupInvite.filter(.invite_id == ")
            .str(invite_id)
            .raw(")");
        Ok(self
            .db
            .fetch::<UsesRow>(&q)
            .await?
            .into_iter()
            .next()
            .map(|r| r.data.uses))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_numbers_belong_to_their_invite() {
        let row = |slot: &str| SlotRow {
            slot: slot.to_owned(),
        };
        assert_eq!(slot_key("inv_a", 3), "inv_a 3");
        assert_eq!(slot_number(&row("inv_a 3"), "inv_a"), Some(3));
        assert_eq!(slot_number(&row("inv_ab 3"), "inv_a"), None);
        assert_eq!(slot_number(&row("inv_a x"), "inv_a"), None);
    }
}
