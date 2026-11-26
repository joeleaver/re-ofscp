//! Admins in rhypedb (`Admin` in `schema.rhype`). Every query goes through
//! [`Ql`]. Optional text fields are stored as `""`, never null.
//!
//! A filtered `update` is not compare-and-set in rhypedb, so a guard in a
//! filter (`.credential_epoch == e`) only narrows which rows are written; it
//! does not stop two concurrent writers. Writes whose race matters are
//! serialized by a claim first ([`super::claims`], docs/decisions/0012).

use std::sync::Arc;

use re_ofscp_types::admin::AdminRole;
use serde::Deserialize;

use super::claims::{self, Claims};
use crate::db::{Db, DbError, Ql};

/// Admin status values stored in `Admin.status`.
pub mod status {
    /// Can sign in.
    pub const ACTIVE: &str = "active";
    /// Cannot sign in; final.
    pub const DISABLED: &str = "disabled";
}

/// Most admins a provider may have (active or disabled). Admins are a
/// handful of operators; the cap keeps every admin listing one bounded read.
pub const MAX_ADMINS: usize = 200;

/// An admin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admin {
    /// rhypedb object id.
    pub id: u64,
    /// Username.
    pub username: String,
    /// Argon2id PHC string.
    pub password_hash: String,
    /// Role.
    pub role: AdminRole,
    /// [`status::ACTIVE`] or [`status::DISABLED`].
    pub status: String,
    /// Sealed TOTP secret, or `""` before enrollment.
    pub totp_secret: String,
    /// Sealed secret awaiting confirmation, or `""`.
    pub totp_pending: String,
    /// Last accepted TOTP step.
    pub totp_last_step: i64,
    /// Whether the admin must choose a new password.
    pub password_change_required: bool,
    /// Bumped on every credential change; sessions opened under an
    /// earlier value are dead.
    pub credential_epoch: i64,
    /// Creator's username, or `"setup"`.
    pub created_by: String,
    /// RFC 3339 creation time.
    pub created_at: String,
}

impl Admin {
    /// Whether the admin may sign in.
    pub fn is_active(&self) -> bool {
        self.status == status::ACTIVE
    }

    /// Whether a TOTP secret is enrolled.
    pub fn totp_enabled(&self) -> bool {
        !self.totp_secret.is_empty()
    }

    /// Whether the admin's sessions are limited to finishing their setup
    /// (enrolling TOTP, changing a password another admin chose).
    pub fn restricted(&self) -> bool {
        !self.totp_enabled() || self.password_change_required
    }
}

/// An admin-store failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AdminStoreError {
    /// The username is taken.
    #[error("username already taken")]
    Taken,
    /// The database failed.
    #[error(transparent)]
    Db(#[from] DbError),
}

#[derive(Deserialize)]
struct AdminRow {
    username: String,
    password_hash: String,
    role: String,
    status: String,
    totp_secret: String,
    totp_pending: String,
    totp_last_step: i64,
    password_change_required: bool,
    credential_epoch: i64,
    created_by: String,
    created_at: String,
}

fn decode(id: u64, r: AdminRow) -> Result<Admin, DbError> {
    let role = AdminRole::parse(&r.role)
        .ok_or_else(|| DbError::Decode(format!("admin {id} has an unknown role")))?;
    Ok(Admin {
        id,
        username: r.username,
        password_hash: r.password_hash,
        role,
        status: r.status,
        totp_secret: r.totp_secret,
        totp_pending: r.totp_pending,
        totp_last_step: r.totp_last_step,
        password_change_required: r.password_change_required,
        credential_epoch: r.credential_epoch,
        created_by: r.created_by,
        created_at: r.created_at,
    })
}

/// A new admin's fields.
#[derive(Debug, Clone, Copy)]
pub struct NewAdmin<'a> {
    /// Username (validated by the caller).
    pub username: &'a str,
    /// Argon2id PHC string.
    pub password_hash: &'a str,
    /// Role.
    pub role: AdminRole,
    /// Whether the admin must choose a new password at first sign-in.
    pub password_change_required: bool,
    /// Creator's username, or `"setup"`.
    pub created_by: &'a str,
}

/// Admin storage.
#[derive(Debug, Clone)]
pub struct AdminStore {
    db: Arc<Db>,
    claims: Claims,
}

impl AdminStore {
    /// A store over `db`.
    pub fn new(db: Arc<Db>) -> Self {
        Self {
            claims: Claims::new(db.clone()),
            db,
        }
    }

    /// Claim the move of `admin` from its credential epoch to the next one.
    /// Every write of `credential_epoch` holds this claim, so of several
    /// changes read at one epoch exactly one applies: the guarded update
    /// that follows has no competitor. `false` if another change holds it.
    async fn claim_next_epoch(&self, admin: &Admin, now: i64) -> Result<bool, DbError> {
        self.claims
            .claim(
                &claims::epoch_key(&admin.username, admin.credential_epoch + 1),
                &admin.username,
                now + claims::EPOCH_LEASE_SECS,
                now,
            )
            .await
    }

    /// Delete claims expired by `now` (see [`Claims::purge`]).
    pub async fn purge_claims(&self, now: i64) -> Result<(), DbError> {
        self.claims.purge(now).await
    }

    /// Whether any admin exists, active or not.
    pub async fn any(&self) -> Result<bool, DbError> {
        Ok(!self
            .db
            .fetch::<AdminRow>(&Ql::new("Admin.limit(1)"))
            .await?
            .is_empty())
    }

    /// Create an active admin without TOTP.
    pub async fn create(&self, a: NewAdmin<'_>, now: i64) -> Result<Admin, AdminStoreError> {
        let q = Ql::new("Admin.create({ username: ")
            .str(a.username)
            .raw(", password_hash: ")
            .str(a.password_hash)
            .raw(", role: ")
            .str(a.role.as_str())
            .raw(", status: ")
            .str(status::ACTIVE)
            .raw(", totp_secret: \"\", totp_pending: \"\", totp_last_step: 0")
            .raw(", password_change_required: ")
            .bool(a.password_change_required)
            .raw(", credential_epoch: 0, created_by: ")
            .str(a.created_by)
            .raw(", created_at: ")
            .unix_seconds(now)
            .raw(" })");
        match self.db.write_one::<AdminRow>(&q).await {
            Ok(row) => Ok(decode(row.id, row.data)?),
            Err(DbError::Conflict(_)) => Err(AdminStoreError::Taken),
            Err(e) => Err(e.into()),
        }
    }

    /// The admin named `username`, if any.
    pub async fn find(&self, username: &str) -> Result<Option<Admin>, DbError> {
        let q = Ql::new("Admin.filter(.username == ").str(username).raw(")");
        self.db
            .fetch::<AdminRow>(&q)
            .await?
            .into_iter()
            .next()
            .map(|r| decode(r.id, r.data))
            .transpose()
    }

    /// Every admin (at most [`MAX_ADMINS`] exist), by username.
    pub async fn list(&self) -> Result<Vec<Admin>, DbError> {
        let q = Ql::new("Admin.limit(").uint(MAX_ADMINS as u64 + 1).raw(")");
        let mut admins = self
            .db
            .fetch::<AdminRow>(&q)
            .await?
            .into_iter()
            .map(|r| decode(r.id, r.data))
            .collect::<Result<Vec<_>, _>>()?;
        admins.sort_by(|a, b| a.username.cmp(&b.username));
        Ok(admins)
    }

    /// Replace the password hash, clear the change requirement and bump
    /// the credential epoch, provided the epoch is still `admin`'s (no
    /// credential changed since it was read). `false` if it changed, or
    /// another change of it is under way.
    pub async fn set_password(
        &self,
        admin: &Admin,
        password_hash: &str,
        now: i64,
    ) -> Result<bool, DbError> {
        if !self.claim_next_epoch(admin, now).await? {
            return Ok(false);
        }
        let q = Ql::new("Admin.filter(.username == ")
            .str(&admin.username)
            .raw(" && .credential_epoch == ")
            .int(admin.credential_epoch)
            .raw(").update({ password_hash: ")
            .str(password_hash)
            .raw(", password_change_required: false, credential_epoch: ")
            .int(admin.credential_epoch + 1)
            .raw(" })");
        Ok(!self.db.write_rows(&q).await?.into_objects().is_empty())
    }

    /// Set the role of an active admin. `false` if it is not active.
    ///
    /// Not serialized: racing [`AdminStore::disable`], the role may land on
    /// an admin just disabled, which is harmless (disabling is final, and a
    /// disabled admin's role grants nothing).
    pub async fn set_role(&self, username: &str, role: AdminRole) -> Result<bool, DbError> {
        let q = Ql::new("Admin.filter(.username == ")
            .str(username)
            .raw(" && .status == ")
            .str(status::ACTIVE)
            .raw(").update({ role: ")
            .str(role.as_str())
            .raw(" })");
        Ok(!self.db.write_rows(&q).await?.into_objects().is_empty())
    }

    /// Disable an admin (final).
    pub async fn disable(&self, username: &str) -> Result<(), DbError> {
        let q = Ql::new("Admin.filter(.username == ")
            .str(username)
            .raw(").update({ status: ")
            .str(status::DISABLED)
            .raw(" })");
        self.db.execute(&q).await
    }

    /// Store a sealed secret awaiting confirmation, replacing any earlier
    /// one, provided no secret is enrolled yet. `false` if one is.
    ///
    /// Not serialized, deliberately: racing a confirmation or a reset, a
    /// pending secret may be left beside an enrolled one, or survive a
    /// reset. Neither grants anything. Only [`AdminStore::confirm_totp`]
    /// reads it, under its epoch claim, and it enrolls exactly the secret
    /// its caller proved a code for; a reset leaves the admin to enroll
    /// again, which replaces it.
    pub async fn set_totp_pending(&self, username: &str, sealed: &str) -> Result<bool, DbError> {
        let q = Ql::new("Admin.filter(.username == ")
            .str(username)
            .raw(" && .totp_secret == \"\").update({ totp_pending: ")
            .str(sealed)
            .raw(" })");
        Ok(!self.db.write_rows(&q).await?.into_objects().is_empty())
    }

    /// Promote `admin`'s pending secret to the enrolled one, with `step`
    /// (already claimed with [`AdminStore::use_totp_step`]) as its last
    /// used step, and bump the credential epoch. `false` if the pending
    /// secret or the epoch changed meanwhile, a secret is already enrolled,
    /// or another credential change is under way.
    pub async fn confirm_totp(&self, admin: &Admin, step: i64, now: i64) -> Result<bool, DbError> {
        if !self.claim_next_epoch(admin, now).await? {
            return Ok(false);
        }
        // The secret and the epoch change only under an epoch claim, which
        // we hold; the pending secret may still change (see
        // `set_totp_pending`), and we enroll the one the caller proved.
        let q = Ql::new("Admin.filter(.username == ")
            .str(&admin.username)
            .raw(" && .credential_epoch == ")
            .int(admin.credential_epoch)
            .raw(" && .totp_secret == \"\" && .totp_pending == ")
            .str(&admin.totp_pending)
            .raw(").update({ totp_secret: ")
            .str(&admin.totp_pending)
            .raw(", totp_pending: \"\", totp_last_step: ")
            .int(step)
            .raw(", credential_epoch: ")
            .int(admin.credential_epoch + 1)
            .raw(" })");
        Ok(!self.db.write_rows(&q).await?.into_objects().is_empty())
    }

    /// Use `username`'s TOTP step `step` (a code that just verified):
    /// claim it, so of any number of concurrent requests carrying the code
    /// exactly one gets `true`, then raise the highest used step to it.
    /// `false` if the step was used before. Claim only after the code
    /// verified, or anyone could burn the current step.
    pub async fn use_totp_step(
        &self,
        username: &str,
        step: i64,
        now: i64,
    ) -> Result<bool, DbError> {
        if !self
            .claims
            .claim(
                &claims::totp_step_key(username, step),
                username,
                now + claims::TOTP_CLAIM_SECS,
                now,
            )
            .await?
        {
            return Ok(false);
        }
        // Advisory, so not serialized: it lets `totp::verify` refuse steps
        // older than the highest used, after their claims are purged. Two
        // sign-ins with different codes may race it and leave the lower
        // step, which only makes that refusal less strict; each code still
        // works once, by its claim.
        let q = Ql::new("Admin.filter(.username == ")
            .str(username)
            .raw(" && .totp_last_step < ")
            .int(step)
            .raw(").update({ totp_last_step: ")
            .int(step)
            .raw(" })");
        self.db.execute(&q).await?;
        Ok(true)
    }

    /// Remove `admin`'s TOTP enrollment (they enroll again at next
    /// sign-in) and bump the credential epoch, ending every session. The
    /// highest used step is kept, so old codes stay dead. `false` if the
    /// epoch changed since `admin` was read, or another credential change
    /// is under way.
    pub async fn reset_totp(&self, admin: &Admin, now: i64) -> Result<bool, DbError> {
        if !self.claim_next_epoch(admin, now).await? {
            return Ok(false);
        }
        let q = Ql::new("Admin.filter(.username == ")
            .str(&admin.username)
            .raw(" && .credential_epoch == ")
            .int(admin.credential_epoch)
            .raw(").update({ totp_secret: \"\", totp_pending: \"\", credential_epoch: ")
            .int(admin.credential_epoch + 1)
            .raw(" })");
        Ok(!self.db.write_rows(&q).await?.into_objects().is_empty())
    }
}
