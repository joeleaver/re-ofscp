//! Accounts and device keys in rhypedb (`User`, `DeviceKey` in
//! `schema.rhype`). Every query goes through [`Ql`].
//!
//! A `User` row with `pending: true` is a registration in flight
//! ([`super::pending`], docs/decisions/0012). It is not an account: every
//! read here that returns a [`User`] skips it, and the admin listings show
//! it with the status [`status::PENDING`].

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use serde::Deserialize;

use super::pending::Resolution;
use crate::db::{Db, DbError, Ql};

/// Attempts at an account create aborted by a concurrent one
/// (`Contended`), or freed by discarding a pending registration.
pub(super) const CREATE_PASSES: usize = 6;

/// Account status values stored in `User.status`.
pub mod status {
    /// Can log in; keys verify.
    pub const ACTIVE: &str = "active";
    /// Cannot log in; keys do not verify.
    pub const DISABLED: &str = "disabled";
    /// Shown by the admin listings for a registration in flight (a row
    /// with `pending: true`); never stored in `User.status`.
    pub const PENDING: &str = "pending";
}

/// An account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    /// rhypedb object id.
    pub id: u64,
    /// The handle (§2.2.1).
    pub handle: String,
    /// Display name.
    pub display_name: String,
    /// Argon2id PHC string.
    pub password_hash: String,
    /// [`status::ACTIVE`] or [`status::DISABLED`].
    pub status: String,
}

impl User {
    /// Whether the account may log in and sign.
    pub fn is_active(&self) -> bool {
        self.status == status::ACTIVE
    }
}

/// A device key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceKey {
    /// Key id (`dk_…`).
    pub key_id: String,
    /// Owner's handle.
    pub handle: String,
    /// Base64 Ed25519 public key.
    pub public_key: String,
    /// `"Ed25519"`.
    pub algorithm: String,
    /// Device description.
    pub device_name: String,
    /// RFC 3339 creation time.
    pub created_at: String,
}

/// An account-store failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    /// The handle is already registered.
    #[error("handle already taken")]
    HandleTaken,
    /// The database failed.
    #[error(transparent)]
    Db(#[from] DbError),
}

#[derive(Deserialize)]
struct UserRow {
    handle: String,
    display_name: String,
    password_hash: String,
    status: String,
    // Absent on accounts made by admins or before registrations were
    // pending first.
    #[serde(default)]
    pending: Option<bool>,
}

impl UserRow {
    fn into_user(self, id: u64) -> Option<User> {
        (self.pending != Some(true)).then_some(User {
            id,
            handle: self.handle,
            display_name: self.display_name,
            password_hash: self.password_hash,
            status: self.status,
        })
    }
}

#[derive(Deserialize)]
struct SummaryRow {
    handle: String,
    display_name: String,
    status: String,
    created_at: String,
    #[serde(default)]
    pending: Option<bool>,
}

impl From<SummaryRow> for AccountSummary {
    fn from(r: SummaryRow) -> Self {
        Self {
            handle: r.handle,
            display_name: r.display_name,
            status: if r.pending == Some(true) {
                status::PENDING.to_owned()
            } else {
                r.status
            },
            created_at: r.created_at,
        }
    }
}

/// An account as the admin API lists it (no password hash).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountSummary {
    /// The handle.
    pub handle: String,
    /// Display name.
    pub display_name: String,
    /// [`status::ACTIVE`] or [`status::DISABLED`], or [`status::PENDING`]
    /// for a registration in flight (not an account yet).
    pub status: String,
    /// RFC 3339 creation time.
    pub created_at: String,
}

#[derive(Deserialize)]
struct KeyRow {
    key_id: String,
    handle: String,
    public_key: String,
    algorithm: String,
    device_name: String,
    created_at: String,
}

impl From<KeyRow> for DeviceKey {
    fn from(r: KeyRow) -> Self {
        Self {
            key_id: r.key_id,
            handle: r.handle,
            public_key: r.public_key,
            algorithm: r.algorithm,
            device_name: r.device_name,
            created_at: r.created_at,
        }
    }
}

/// A fresh key id: `dk_` + 128 random bits, base64url (a valid local id,
/// §2.2).
fn new_key_id() -> Result<String, DbError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| DbError::Query(format!("random source: {e}")))?;
    Ok(format!("dk_{}", B64URL.encode(bytes)))
}

/// Account and device-key storage.
#[derive(Debug, Clone)]
pub struct AccountStore {
    pub(super) db: Arc<Db>,
}

impl AccountStore {
    /// A store over `db`.
    pub fn new(db: Arc<Db>) -> Self {
        Self { db }
    }

    /// Create an active account (an admin's). The caller has validated the
    /// handle and hashed the password.
    ///
    /// A pending registration holding the handle makes it taken, unless it
    /// is stale or settled discarded, when it is discarded and the create
    /// retried ([`AccountStore::resolve_taken`]).
    pub async fn create_user(
        &self,
        handle: &str,
        display_name: &str,
        password_hash: &str,
        now: i64,
    ) -> Result<User, StoreError> {
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
            .raw(" })");
        // A create racing another of the same handle can abort with
        // `Contended`, which wrote nothing; a retry then succeeds or meets
        // the winner's `Conflict` (docs/decisions/0012).
        for _ in 0..CREATE_PASSES {
            match self.db.write_one::<UserRow>(&q).await {
                Ok(row) => {
                    let id = row.id;
                    return row.data.into_user(id).ok_or_else(|| {
                        DbError::Decode("a created account reads pending".to_owned()).into()
                    });
                }
                Err(DbError::Conflict(_)) => {
                    // With no invite, nothing is joinable: taken.
                    match self.resolve_taken(handle, None, now).await? {
                        Resolution::Free => {}
                        Resolution::Taken | Resolution::Joinable(..) => {
                            return Err(StoreError::HandleTaken);
                        }
                    }
                }
                Err(DbError::Contended(_)) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err(DbError::Contended("account create stayed contended".to_owned()).into())
    }

    /// The account with `handle`, if any. A pending registration is not
    /// one: `None`.
    pub async fn find_user(&self, handle: &str) -> Result<Option<User>, StoreError> {
        let q = Ql::new("User.filter(.handle == ").str(handle).raw(")");
        let rows = self.db.fetch::<UserRow>(&q).await?;
        Ok(rows.into_iter().next().and_then(|r| r.data.into_user(r.id)))
    }

    /// Up to `limit` accounts whose handle contains `contains` (every
    /// account when `None`), in no particular order. Pending registrations
    /// are included, marked [`status::PENDING`].
    pub async fn search(
        &self,
        contains: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AccountSummary>, StoreError> {
        let q = match contains {
            Some(c) => Ql::new("User.filter(.handle.contains(")
                .str(c)
                .raw(")).limit("),
            None => Ql::new("User.limit("),
        };
        let q = q.uint(limit as u64).raw(")");
        Ok(self
            .db
            .fetch::<SummaryRow>(&q)
            .await?
            .into_iter()
            .map(|r| r.data.into())
            .collect())
    }

    /// The account with `handle`, without its password hash (a pending
    /// registration is marked [`status::PENDING`]).
    pub async fn summary(&self, handle: &str) -> Result<Option<AccountSummary>, StoreError> {
        let q = Ql::new("User.filter(.handle == ").str(handle).raw(")");
        Ok(self
            .db
            .fetch::<SummaryRow>(&q)
            .await?
            .into_iter()
            .next()
            .map(|r| r.data.into()))
    }

    /// Set an account's status.
    pub async fn set_status(&self, user: &User, status: &str) -> Result<(), StoreError> {
        let q = Ql::new("User.get(")
            .uint(user.id)
            .raw(").update({ status: ")
            .str(status)
            .raw(" })");
        Ok(self.db.execute(&q).await?)
    }

    /// Register a key for `user`. Returns the new key.
    pub async fn add_device_key(
        &self,
        user: &User,
        public_key: &str,
        algorithm: &str,
        device_name: &str,
        now: i64,
    ) -> Result<DeviceKey, StoreError> {
        // A random 128-bit id colliding is astronomically unlikely; the
        // @unique constraint makes it harmless, and one retry covers it.
        for _ in 0..2 {
            let key_id = new_key_id()?;
            let q = Ql::new("DeviceKey.create({ key_id: ")
                .str(&key_id)
                .raw(", handle: ")
                .str(&user.handle)
                .raw(", public_key: ")
                .str(public_key)
                .raw(", algorithm: ")
                .str(algorithm)
                .raw(", device_name: ")
                .str(device_name)
                .raw(", created_at: ")
                .unix_seconds(now)
                .raw(", revoked: false })");
            match self.db.write_one::<KeyRow>(&q).await {
                Ok(row) => return Ok(row.data.into()),
                Err(DbError::Conflict(_)) => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Err(DbError::Query("could not allocate a unique key id".to_owned()).into())
    }

    /// `handle`'s active (non-revoked) keys, oldest first.
    pub async fn active_keys(&self, handle: &str) -> Result<Vec<DeviceKey>, StoreError> {
        let q = Ql::new("DeviceKey.filter(.handle == ")
            .str(handle)
            .raw(" && .revoked == false)");
        let mut keys: Vec<DeviceKey> = self
            .db
            .fetch::<KeyRow>(&q)
            .await?
            .into_iter()
            .map(|r| r.data.into())
            .collect();
        keys.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then(a.key_id.cmp(&b.key_id))
        });
        Ok(keys)
    }

    /// `handle`'s active key `key_id`, if any.
    pub async fn active_key(
        &self,
        handle: &str,
        key_id: &str,
    ) -> Result<Option<DeviceKey>, StoreError> {
        let q = Ql::new("DeviceKey.filter(.key_id == ")
            .str(key_id)
            .raw(" && .handle == ")
            .str(handle)
            .raw(" && .revoked == false)");
        Ok(self
            .db
            .fetch::<KeyRow>(&q)
            .await?
            .into_iter()
            .next()
            .map(|r| r.data.into()))
    }

    /// Revoke `handle`'s active key `key_id` in one conditional update.
    /// `false` if no such active key belongs to `handle`.
    ///
    /// The `revoked == false` guard is compare-and-set per object since
    /// rhypedb #59 (decision 0012), so exactly one of two racing
    /// revocations writes and reports `true`. It would not matter if both
    /// did: revoking is idempotent and one-way (nothing sets `revoked`
    /// back), so the key ends revoked either way.
    pub async fn revoke_key(
        &self,
        handle: &str,
        key_id: &str,
        now: i64,
    ) -> Result<bool, StoreError> {
        let q = Ql::new("DeviceKey.filter(.key_id == ")
            .str(key_id)
            .raw(" && .handle == ")
            .str(handle)
            .raw(" && .revoked == false).update({ revoked: true, revoked_at: ")
            .unix_seconds(now)
            .raw(" })");
        Ok(!self.db.write_rows(&q).await?.into_objects().is_empty())
    }

    /// Revoke every active key of `handle` (account disabled, password
    /// reset). Returns the revoked key ids. Idempotent like
    /// [`AccountStore::revoke_key`], so its guard needs no serializing.
    pub async fn revoke_all_keys(&self, handle: &str, now: i64) -> Result<Vec<String>, StoreError> {
        let q = Ql::new("DeviceKey.filter(.handle == ")
            .str(handle)
            .raw(" && .revoked == false).update({ revoked: true, revoked_at: ")
            .unix_seconds(now)
            .raw(" })");
        self.db
            .write_rows(&q)
            .await?
            .into_objects()
            .iter()
            .map(|o| {
                rhypedb_client::Row::<KeyIdRow>::from_object(o)
                    .map(|r| r.data.key_id)
                    .map_err(|e| StoreError::Db(DbError::Decode(e.to_string())))
            })
            .collect()
    }
}

#[derive(Deserialize)]
struct KeyIdRow {
    key_id: String,
}
