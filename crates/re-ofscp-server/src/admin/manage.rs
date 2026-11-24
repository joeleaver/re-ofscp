//! What a signed-in admin can do to their own identity (TOTP enrollment,
//! password change) and what owners can do to other admins.

use re_ofscp_types::admin::{AdminRole, TotpEnrollment, is_valid_admin_username};

use super::store::{MAX_ADMINS, status};
use super::{Admin, AdminStoreError, Admins, NewAdmin, totp};
use crate::accounts::PasswordError;
use crate::db::DbError;
use crate::ratelimit::Limited;

/// Why a self-service or management operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManageError {
    /// The input is invalid (detail for the response).
    #[error("{0}")]
    Invalid(&'static str),
    /// A TOTP code or the current password was wrong.
    #[error("{0}")]
    WrongCredential(&'static str),
    /// Too many wrong current passwords for this admin.
    #[error("too many failed attempts")]
    Locked(Limited),
    /// The change conflicts with the current state (detail for the
    /// response).
    #[error("{0}")]
    Conflict(&'static str),
    /// No such admin.
    #[error("no such admin")]
    NotFound,
    /// The password is too short or too long, or hashing is saturated.
    #[error(transparent)]
    Password(#[from] PasswordError),
    /// A server fault.
    #[error(transparent)]
    Db(#[from] DbError),
}

/// What [`Admins::update_admin`] changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Changes {
    /// The role was changed.
    pub role: bool,
    /// The admin was disabled.
    pub disabled: bool,
}

impl Admins {
    /// Begin TOTP enrollment: a fresh secret, stored sealed as pending
    /// (replacing any earlier pending one) and returned once. Refused once a
    /// secret is enrolled: an owner resets it first.
    pub async fn enroll_totp(&self, admin: &Admin) -> Result<TotpEnrollment, ManageError> {
        if admin.totp_enabled() {
            return Err(ManageError::Conflict(
                "TOTP is already enrolled; an owner can reset it",
            ));
        }
        let secret = totp::new_secret().map_err(DbError::Query)?;
        let sealed = self
            .secrets()?
            .seal(&secret, &admin.username)
            .map_err(DbError::Query)?;
        if !self
            .store
            .set_totp_pending(&admin.username, &sealed)
            .await?
        {
            return Err(ManageError::Conflict("TOTP is already enrolled"));
        }
        Ok(TotpEnrollment {
            secret: totp::base32(&secret),
            otpauth_uri: totp::otpauth_uri(self.domain.as_str(), &admin.username, &secret),
        })
    }

    /// Finish TOTP enrollment with a current code. On success every other
    /// session of the admin ends (they were opened with the password only);
    /// `session` (the caller's) carries on.
    pub async fn confirm_totp(
        &self,
        admin: &Admin,
        code: &str,
        session: &str,
        now: i64,
    ) -> Result<(), ManageError> {
        if admin.totp_enabled() {
            return Err(ManageError::Conflict("TOTP is already enrolled"));
        }
        if admin.totp_pending.is_empty() {
            return Err(ManageError::Conflict("start TOTP enrollment first"));
        }
        let secret = self
            .secrets()?
            .open(&admin.totp_pending, &admin.username)
            .map_err(|e| DbError::Decode(e.to_string()))?;
        // Wrong codes count towards the sign-in lockout, so a session
        // cannot try codes without limit.
        self.login_backoff
            .attempt(&admin.username, now)
            .map_err(ManageError::Locked)?;
        let step = totp::verify(&secret, code, now, admin.totp_last_step)
            .ok_or(ManageError::WrongCredential("that code is not valid"))?;
        self.login_backoff.succeed(&admin.username);
        if !self
            .store
            .confirm_totp(&admin.username, &admin.totp_pending, step)
            .await?
        {
            return Err(ManageError::Conflict(
                "enrollment changed meanwhile; start again",
            ));
        }
        self.sessions
            .delete_for(&admin.username, Some(session))
            .await?;
        Ok(())
    }

    /// Change the admin's own password, proving the current one. Wrong
    /// guesses count towards the same lockout as sign-ins. Every other
    /// session of the admin ends.
    pub async fn change_password(
        &self,
        admin: &Admin,
        current: &str,
        new: &str,
        session: &str,
        now: i64,
    ) -> Result<(), ManageError> {
        self.login_backoff
            .attempt(&admin.username, now)
            .map_err(ManageError::Locked)?;
        let ok = match self
            .passwords
            .verify(current, Some(&admin.password_hash))
            .await
        {
            Ok(ok) => ok,
            Err(e) => {
                self.login_backoff.refund(&admin.username);
                return Err(e.into());
            }
        };
        if !ok {
            return Err(ManageError::WrongCredential(
                "the current password is wrong",
            ));
        }
        self.login_backoff.succeed(&admin.username);
        if current == new {
            return Err(ManageError::Invalid(
                "the new password must differ from the current one",
            ));
        }
        let hash = self.passwords.hash(new).await?;
        self.store.set_password(admin, &hash, false).await?;
        self.sessions
            .delete_for(&admin.username, Some(session))
            .await?;
        Ok(())
    }

    /// Create an admin (owners only). They must change the password and
    /// enroll TOTP at first sign-in.
    pub async fn create_admin(
        &self,
        by: &Admin,
        username: &str,
        password: &str,
        role: AdminRole,
        now: i64,
    ) -> Result<Admin, ManageError> {
        if !is_valid_admin_username(username) {
            return Err(ManageError::Invalid(
                "username must match ^[a-z0-9][a-z0-9_.-]{2,63}$",
            ));
        }
        let hash = self.passwords.hash(password).await?;
        let _roster = self.roster.lock().await;
        if self.store.list().await?.len() >= MAX_ADMINS {
            return Err(ManageError::Conflict("the admin limit is reached"));
        }
        let created = self
            .store
            .create(
                NewAdmin {
                    username,
                    password_hash: &hash,
                    role,
                    password_change_required: true,
                    created_by: &by.username,
                },
                now,
            )
            .await;
        match created {
            Ok(a) => Ok(a),
            Err(AdminStoreError::Taken) => {
                Err(ManageError::Conflict("that username is already taken"))
            }
            Err(AdminStoreError::Db(e)) => Err(e.into()),
        }
    }

    /// Change another admin's role and/or disable them (owners only).
    /// Disabling is final and ends their sessions. There is always at least
    /// one active owner: the last one can be neither demoted nor disabled.
    pub async fn update_admin(
        &self,
        username: &str,
        role: Option<AdminRole>,
        disable: bool,
    ) -> Result<Changes, ManageError> {
        let _roster = self.roster.lock().await;
        let admins = self.store.list().await?;
        let target = admins
            .iter()
            .find(|a| a.username == username)
            .ok_or(ManageError::NotFound)?;
        if !target.is_active() {
            return Err(ManageError::Conflict("that admin is disabled"));
        }
        let loses_owner = target.role == AdminRole::Owner
            && (disable || role.is_some_and(|r| r != AdminRole::Owner));
        if loses_owner {
            let other_owners = admins
                .iter()
                .filter(|a| {
                    a.username != target.username && a.role == AdminRole::Owner && a.is_active()
                })
                .count();
            if other_owners == 0 {
                return Err(ManageError::Conflict(
                    "there must always be an active owner",
                ));
            }
        }
        let mut changes = Changes::default();
        if let Some(r) = role.filter(|r| *r != target.role) {
            if !self.store.set_role(username, r).await? {
                return Err(ManageError::Conflict("that admin is disabled"));
            }
            changes.role = true;
        }
        if disable {
            self.store.disable(username).await?;
            self.sessions.delete_for(username, None).await?;
            changes.disabled = true;
        }
        Ok(changes)
    }

    /// Remove another admin's TOTP enrollment (owners only), e.g. after a
    /// lost device, and end their sessions: they enroll again at next
    /// sign-in. An owner cannot reset their own: a stolen session must not
    /// be able to strip its owner's second factor.
    pub async fn reset_totp(&self, by: &Admin, username: &str) -> Result<(), ManageError> {
        if by.username == username {
            return Err(ManageError::Conflict("another owner must reset your TOTP"));
        }
        let target = self
            .store
            .find(username)
            .await?
            .ok_or(ManageError::NotFound)?;
        if target.status != status::ACTIVE {
            return Err(ManageError::Conflict("that admin is disabled"));
        }
        self.store.reset_totp(username).await?;
        self.sessions.delete_for(username, None).await?;
        Ok(())
    }
}
