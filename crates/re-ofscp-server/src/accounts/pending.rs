//! Registration's pending accounts (docs/decisions/0012).
//!
//! rhypedb's filtered updates are not compare-and-set; a `@unique` create
//! is. Registration therefore takes the handle **first**, by creating the
//! account with `pending: true` (handles are `@unique`), and only then
//! redeems the invite for that handle ([`InviteStore::redeem`]) and
//! activates the account. Two invites racing for one handle are decided by
//! the account create, before either invite is touched, so the loser's
//! invite stays usable for another handle; an admin creating the handle is
//! decided the same way.
//!
//! A pending row ends in exactly one of two ways, decided by an
//! `AccountSettlement` row, `@unique` on the row's random `pending_key` and
//! never updated or deleted:
//!
//! - **activate**: created by the registration whose redemption names this
//!   handle. Its holder (or anyone finding it settled so, after the holder
//!   crashed) sets `pending: false`. Nothing sets it back, and nothing else
//!   writes `pending`, so a late activation write is harmless.
//! - **discard**: created by the registration itself when its invite turns
//!   out spent on another handle, or by a create that finds the row stale
//!   (older than [`PENDING_LEASE_SECS`]). Then anyone may delete the row, by
//!   id (object ids are never reused).
//!
//! The two outcomes exclude each other, so a row being activated is never
//! deleted, and a deleted row is never activated, however requests race,
//! stall or crash.
//!
//! **Resuming.** A registration meeting a live pending row made with its
//! own invite, whose password matches that row's, *joins* it: it redeems
//! (for the same handle) and activates the same row, so a retried or
//! duplicated request finishes the registration rather than racing it. A
//! different password is another contender: the handle is taken until the
//! row goes stale.

use serde::Deserialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::invites::InviteStore;
use super::register::RegisterError;
use super::store::{AccountStore, CREATE_PASSES, StoreError, User, status};
use crate::db::{DbError, Ql};

/// How long a pending registration is left to its own request before
/// another invite (or an admin) may discard it to take the handle. This is
/// fairness, not safety (the settlement decides every race): it is much
/// longer than a registration's few statements after the create.
pub const PENDING_LEASE_SECS: i64 = 300;

/// Attempts at one settlement or activation before giving up (fail closed).
const SETTLE_PASSES: usize = 4;

/// How a pending row was settled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Settlement {
    /// It becomes the account.
    Activate,
    /// It is deleted, freeing the handle.
    Discard,
}

impl Settlement {
    fn as_str(self) -> &'static str {
        match self {
            Self::Activate => "activate",
            Self::Discard => "discard",
        }
    }

    fn parse(s: &str) -> Result<Self, DbError> {
        match s {
            "activate" => Ok(Self::Activate),
            "discard" => Ok(Self::Discard),
            other => Err(DbError::Decode(format!("settlement outcome {other:?}"))),
        }
    }
}

/// A pending row, as the registration that made it (or a create meeting
/// it) holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingAccount {
    /// rhypedb object id.
    pub id: u64,
    /// The handle it holds.
    pub handle: String,
    /// Its `AccountSettlement` key.
    pub key: String,
    /// The invite it registers with.
    pub invite_hash: Option<String>,
    /// Unix seconds it was made (`None` if unreadable: never stale).
    pub created_at: Option<i64>,
}

#[derive(Deserialize)]
struct PendingRow {
    handle: String,
    password_hash: String,
    created_at: String,
    #[serde(default)]
    pending: Option<bool>,
    #[serde(default)]
    pending_key: Option<String>,
    #[serde(default)]
    invite_hash: Option<String>,
}

#[derive(Deserialize)]
struct ActiveRow {
    handle: String,
    display_name: String,
    password_hash: String,
    status: String,
}

#[derive(Deserialize)]
struct SettlementRow {
    outcome: String,
}

/// What a create that met `Conflict` found.
pub(super) enum Resolution {
    /// The handle may be free now: look again and retry.
    Free,
    /// An account, or another registration, holds it.
    Taken,
    /// A live pending row made with the caller's own invite, which it may
    /// join if it proves the row's password (`.1`, its hash).
    Joinable(PendingAccount, String),
}

/// What [`AccountStore::create_pending`] got.
pub enum Held {
    /// A new pending row, made by this call.
    Created(PendingAccount),
    /// A live pending row made with the same invite (another request of the
    /// same registration, or one that crashed), and its password hash.
    Joinable(PendingAccount, String),
}

/// What holds a handle.
enum Holder {
    /// Nothing (it was deleted meanwhile).
    Nothing,
    /// An account, or a pending row this code cannot settle.
    Account,
    /// A pending registration, and its password hash.
    Pending(PendingAccount, String),
}

/// A fresh settlement key: 128 random bits, hex.
fn new_pending_key() -> Result<String, DbError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| DbError::Query(format!("random source: {e}")))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

impl AccountStore {
    /// Hold `handle` for a registration with the invite `invite_hash`: a
    /// pending row, invisible to every account read. `HandleTaken` if an
    /// account, or another live registration, holds it; a stale or
    /// discarded pending row is discarded first. A live one made with this
    /// same invite is returned to be joined.
    pub async fn create_pending(
        &self,
        handle: &str,
        display_name: &str,
        password_hash: &str,
        invite_hash: &str,
        now: i64,
    ) -> Result<Held, StoreError> {
        let key = new_pending_key()?;
        let q = Ql::new("User.create({ handle: ")
            .str(handle)
            .raw(", display_name: ")
            .str(display_name)
            .raw(", password_hash: ")
            .str(password_hash)
            .raw(", status: ")
            .str(status::ACTIVE)
            .raw(", created_at: ")
            .unix_seconds(now)
            .raw(", pending: true, pending_key: ")
            .str(&key)
            .raw(", invite_hash: ")
            .str(invite_hash)
            .raw(" })");
        for _ in 0..CREATE_PASSES {
            match self.db.write_one::<PendingRow>(&q).await {
                Ok(row) => {
                    return Ok(Held::Created(PendingAccount {
                        id: row.id,
                        handle: row.data.handle,
                        key,
                        invite_hash: Some(invite_hash.to_owned()),
                        created_at: Some(now),
                    }));
                }
                Err(DbError::Conflict(_)) => {
                    match self.resolve_taken(handle, Some(invite_hash), now).await? {
                        Resolution::Free => {}
                        Resolution::Taken => return Err(StoreError::HandleTaken),
                        Resolution::Joinable(p, hash) => return Ok(Held::Joinable(p, hash)),
                    }
                }
                Err(DbError::Contended(_)) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err(DbError::Contended("pending account create stayed contended".to_owned()).into())
    }

    /// A create of `handle` met `Conflict` (`invite` is the creator's, if
    /// it is a registration): what holds the handle now.
    ///
    /// - A pending row settled `activate` is an account: its activation is
    ///   finished here (its holder may have crashed), and it is taken, or
    ///   joinable by its own invite (which then proves the password).
    /// - One settled `discard` is deleted: free.
    /// - An unsettled one is joinable by its own invite; otherwise it is
    ///   taken while live, and discarded once stale.
    pub(super) async fn resolve_taken(
        &self,
        handle: &str,
        invite: Option<&str>,
        now: i64,
    ) -> Result<Resolution, StoreError> {
        let (p, hash) = match self.holder(handle).await? {
            Holder::Nothing => return Ok(Resolution::Free),
            Holder::Account => return Ok(Resolution::Taken),
            Holder::Pending(p, hash) => (p, hash),
        };
        let same_invite = invite.is_some() && p.invite_hash.as_deref() == invite;
        let outcome = match self.settlement(&p.key).await? {
            Some(o) => o,
            None => {
                let stale = p
                    .created_at
                    .is_some_and(|t| t.saturating_add(PENDING_LEASE_SECS) <= now);
                if !stale {
                    return Ok(if same_invite {
                        Resolution::Joinable(p, hash)
                    } else {
                        Resolution::Taken
                    });
                }
                self.settle(&p.key, Settlement::Discard, now).await?
            }
        };
        match outcome {
            Settlement::Activate => {
                self.activate(&p).await?;
                Ok(if same_invite {
                    Resolution::Joinable(p, hash)
                } else {
                    Resolution::Taken
                })
            }
            Settlement::Discard => {
                self.delete_pending(&p).await?;
                Ok(Resolution::Free)
            }
        }
    }

    /// Settle `key` as `want`, unless it is already settled: the outcome
    /// that holds. Only a caller given `want` back may act on it.
    pub async fn settle(
        &self,
        key: &str,
        want: Settlement,
        now: i64,
    ) -> Result<Settlement, DbError> {
        let create = Ql::new("AccountSettlement.create({ key: ")
            .str(key)
            .raw(", outcome: ")
            .str(want.as_str())
            .raw(", settled_at: ")
            .unix_seconds(now)
            .raw(" })");
        // Several passes: a create aborted by a concurrent one (`Contended`:
        // nothing written) before that one is visible.
        for _ in 0..SETTLE_PASSES {
            match self.db.execute(&create).await {
                Ok(()) => return Ok(want),
                Err(DbError::Conflict(_) | DbError::Contended(_)) => {}
                Err(e) => return Err(e),
            }
            if let Some(held) = self.settlement(key).await? {
                return Ok(held);
            }
        }
        Err(DbError::Contended(
            "account settlement stayed contended".to_owned(),
        ))
    }

    /// Make the pending row `p`, settled [`Settlement::Activate`], the
    /// account. Idempotent: it only ever sets `pending` to false.
    pub async fn activate(&self, p: &PendingAccount) -> Result<User, StoreError> {
        let q = Ql::new("User.get(")
            .uint(p.id)
            .raw(").update({ pending: false })");
        for _ in 0..SETTLE_PASSES {
            match self.db.write_one::<ActiveRow>(&q).await {
                Ok(row) => {
                    return Ok(User {
                        id: row.id,
                        handle: row.data.handle,
                        display_name: row.data.display_name,
                        password_hash: row.data.password_hash,
                        status: row.data.status,
                    });
                }
                // A concurrent finisher's write: nothing of ours written.
                Err(DbError::Contended(_)) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err(DbError::Contended("account activation stayed contended".to_owned()).into())
    }

    /// Settle `p` [`Settlement::Discard`] and delete it. `false` if it was
    /// already settled to activate (then it is left alone).
    pub async fn discard(&self, p: &PendingAccount, now: i64) -> Result<bool, StoreError> {
        match self.settle(&p.key, Settlement::Discard, now).await? {
            Settlement::Discard => {
                self.delete_pending(p).await?;
                Ok(true)
            }
            Settlement::Activate => Ok(false),
        }
    }

    /// Delete `p`, settled [`Settlement::Discard`], by id. Object ids are
    /// never reused, so this deletes that row or nothing.
    async fn delete_pending(&self, p: &PendingAccount) -> Result<(), StoreError> {
        let q = Ql::new("User.get(").uint(p.id).raw(").delete()");
        match self.db.execute(&q).await {
            // Deleted (or being deleted) by another who found it discarded;
            // a caller that retries its create reads the handle again.
            Ok(()) | Err(DbError::Vanished(_) | DbError::Contended(_)) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// The settlement of `key`, if any.
    async fn settlement(&self, key: &str) -> Result<Option<Settlement>, DbError> {
        let q = Ql::new("AccountSettlement.filter(.key == ")
            .str(key)
            .raw(")");
        match self.db.fetch::<SettlementRow>(&q).await?.into_iter().next() {
            Some(r) => Settlement::parse(&r.data.outcome).map(Some),
            None => Ok(None),
        }
    }

    /// What holds `handle`.
    async fn holder(&self, handle: &str) -> Result<Holder, DbError> {
        let q = Ql::new("User.filter(.handle == ").str(handle).raw(")");
        let Some(row) = self.db.fetch::<PendingRow>(&q).await?.into_iter().next() else {
            return Ok(Holder::Nothing);
        };
        if row.data.pending != Some(true) {
            return Ok(Holder::Account);
        }
        // A pending row without a key cannot be settled: fail closed (the
        // handle stays taken) rather than guess.
        let Some(key) = row.data.pending_key else {
            return Ok(Holder::Account);
        };
        let p = PendingAccount {
            id: row.id,
            handle: row.data.handle,
            key,
            invite_hash: row.data.invite_hash,
            created_at: OffsetDateTime::parse(&row.data.created_at, &Rfc3339)
                .ok()
                .map(OffsetDateTime::unix_timestamp),
        };
        Ok(Holder::Pending(p, row.data.password_hash))
    }
}

/// Finish registering `handle` with the invite `invite_hash` on `held`,
/// the pending row the caller made, or joined after proving its password
/// ([`AccountStore::create_pending`], [`super::Accounts::register`]):
/// redeem the invite for the handle, then activate.
///
/// - The invite spent on another handle (or expired): the pending row is
///   discarded and `InviteRequired`.
/// - The row discarded meanwhile (reclaimed as stale): `HandleTaken`; the
///   invite stays unredeemed unless the discard came after it redeemed.
///
/// A crash anywhere leaves a pending row, invisible: a retry with the same
/// handle, invite and password joins and finishes it, and anyone may
/// reclaim it once stale.
pub async fn complete(
    store: &AccountStore,
    invites: &InviteStore,
    invite_hash: &str,
    held: &PendingAccount,
    now: i64,
) -> Result<User, RegisterError> {
    // A row already discarded (reclaimed while this request stalled) is
    // gone: leave the invite unredeemed. A discard landing after this read
    // is caught by the settlement below, the invite then spent on the
    // handle (failing closed).
    if store.settlement(&held.key).await? == Some(Settlement::Discard) {
        return Err(RegisterError::HandleTaken);
    }
    if !invites.redeem(invite_hash, &held.handle, now).await? {
        // Spent on another handle (or expired): this row can never be
        // activated, as only a redemption for its handle activates it.
        store.discard(held, now).await?;
        return Err(RegisterError::InviteRequired);
    }
    match store.settle(&held.key, Settlement::Activate, now).await? {
        Settlement::Activate => Ok(store.activate(held).await?),
        Settlement::Discard => Err(RegisterError::HandleTaken),
    }
}
