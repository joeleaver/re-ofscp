//! Accounts and device keys in rhypedb (`User`, `DeviceKey` in
//! `schema.rhype`). Every query goes through [`Ql`].

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use serde::Deserialize;

use crate::db::{Db, DbError, Ql};

/// Account status values stored in `User.status`.
pub mod status {
    /// Can log in; keys verify.
    pub const ACTIVE: &str = "active";
    /// Cannot log in; keys do not verify.
    pub const DISABLED: &str = "disabled";
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
}

/// An account as the admin API lists it (no password hash).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AccountSummary {
    /// The handle.
    pub handle: String,
    /// Display name.
    pub display_name: String,
    /// [`status::ACTIVE`] or [`status::DISABLED`].
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
    db: Arc<Db>,
}

impl AccountStore {
    /// A store over `db`.
    pub fn new(db: Arc<Db>) -> Self {
        Self { db }
    }

    /// Create an active account. The caller has validated the handle and
    /// hashed the password.
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
        match self.db.write_one::<UserRow>(&q).await {
            Ok(row) => Ok(User {
                id: row.id,
                handle: row.data.handle,
                display_name: row.data.display_name,
                password_hash: row.data.password_hash,
                status: row.data.status,
            }),
            Err(DbError::Conflict(_)) => Err(StoreError::HandleTaken),
            Err(e) => Err(e.into()),
        }
    }

    /// The account with `handle`, if any.
    pub async fn find_user(&self, handle: &str) -> Result<Option<User>, StoreError> {
        let q = Ql::new("User.filter(.handle == ").str(handle).raw(")");
        let rows = self.db.fetch::<UserRow>(&q).await?;
        Ok(rows.into_iter().next().map(|r| User {
            id: r.id,
            handle: r.data.handle,
            display_name: r.data.display_name,
            password_hash: r.data.password_hash,
            status: r.data.status,
        }))
    }

    /// Up to `limit` accounts whose handle contains `contains` (every
    /// account when `None`), in no particular order.
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
            .fetch::<AccountSummary>(&q)
            .await?
            .into_iter()
            .map(|r| r.data)
            .collect())
    }

    /// The account with `handle`, without its password hash.
    pub async fn summary(&self, handle: &str) -> Result<Option<AccountSummary>, StoreError> {
        let q = Ql::new("User.filter(.handle == ").str(handle).raw(")");
        Ok(self
            .db
            .fetch::<AccountSummary>(&q)
            .await?
            .into_iter()
            .next()
            .map(|r| r.data))
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
    /// The `revoked == false` guard is not compare-and-set (decision 0012),
    /// and needs not be: revoking is idempotent and one-way (nothing sets
    /// `revoked` back), so racing revocations all leave the key revoked. At
    /// worst two report `true` and `revoked_at` keeps the later time.
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
