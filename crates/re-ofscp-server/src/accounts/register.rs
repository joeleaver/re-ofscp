//! Registration by invitation (spec §4.1.1, lost-conn/ofscp#18) and issuing
//! account invites.
//!
//! The order of checks is the spec's: the registration mode and the invite
//! are checked **before** anything reveals whether a handle exists or costs
//! a password hash, so a caller without a usable invite learns nothing and
//! cannot make the provider hash.

use re_ofscp_types::auth::{RegistrationMode, RegistrationRequest};

use super::invites::{
    DEFAULT_INVITE_TTL_SECS, IssuedInvite, MAX_INVITE_TTL_SECS, new_token, token_hash,
};
use super::password::check_length;
use super::{Accounts, CreateError, PasswordError, StoreError, User, check_new_handle};
use crate::db::DbError;

/// Why a registration was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegisterError {
    /// The provider does not accept self-registration: `403
    /// registration_closed`.
    #[error("registration is closed")]
    Closed,
    /// No invite, or one that is unknown, expired, used, or pinned to
    /// another handle (deliberately one case): `403 invite_required`.
    #[error("a usable account invite is required")]
    InviteRequired,
    /// Invalid handle or password: `400`.
    #[error(transparent)]
    Invalid(CreateError),
    /// The handle is taken: `409`.
    #[error("handle already taken")]
    HandleTaken,
    /// Hashing is saturated: `503`.
    #[error("password hashing is saturated")]
    Busy,
    /// Storage or hashing failed: `500`.
    #[error("registration failed: {0}")]
    Internal(String),
}

impl From<PasswordError> for RegisterError {
    fn from(e: PasswordError) -> Self {
        match e {
            PasswordError::Length => Self::Invalid(CreateError::Password(e)),
            PasswordError::Busy => Self::Busy,
            PasswordError::Internal(m) => Self::Internal(m),
        }
    }
}

impl From<DbError> for RegisterError {
    fn from(e: DbError) -> Self {
        Self::Internal(e.to_string())
    }
}

impl From<StoreError> for RegisterError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::HandleTaken => Self::HandleTaken,
            StoreError::Db(e) => e.into(),
        }
    }
}

/// Why an invite could not be issued.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InviteError {
    /// The pinned handle is not a valid registration handle (§2.2.1).
    #[error(transparent)]
    InvalidHandle(CreateError),
    /// The pinned handle is already registered.
    #[error("handle already taken")]
    HandleTaken,
    /// The lifetime is not between 1 second and the maximum.
    #[error("invite lifetime must be 1 to {MAX_INVITE_TTL_SECS} seconds")]
    InvalidLifetime,
    /// Storage failed.
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl From<DbError> for InviteError {
    fn from(e: DbError) -> Self {
        Self::Store(StoreError::Db(e))
    }
}

impl Accounts {
    /// Issue an account invite, optionally pinned to `handle`, valid for
    /// `ttl_secs` (default [`DEFAULT_INVITE_TTL_SECS`]). `created_by` names
    /// the issuing admin. Issued in any registration mode, so invites can
    /// be prepared before the provider opens to them.
    pub async fn create_invite(
        &self,
        handle: Option<&str>,
        ttl_secs: Option<i64>,
        created_by: &str,
        now: i64,
    ) -> Result<IssuedInvite, InviteError> {
        let ttl = ttl_secs.unwrap_or(DEFAULT_INVITE_TTL_SECS);
        if !(1..=MAX_INVITE_TTL_SECS).contains(&ttl) {
            return Err(InviteError::InvalidLifetime);
        }
        if let Some(h) = handle {
            check_new_handle(h).map_err(InviteError::InvalidHandle)?;
            if self.store.find_user(h).await?.is_some() {
                return Err(InviteError::HandleTaken);
            }
        }
        let token = new_token()?;
        let hash = token_hash(&token)
            .ok_or_else(|| DbError::Query("minted an unrecognisable invite token".to_owned()))?;
        let expires_at = now + ttl;
        self.invites
            .create(&hash, handle, created_by, now, expires_at)
            .await?;
        Ok(IssuedInvite {
            link: format!("https://{}/register?invite={token}", self.domain),
            token,
            handle: handle.map(str::to_owned),
            expires_at,
        })
    }

    /// Register a full account (§4.1.1). The display name starts as the
    /// handle (the registration request carries none).
    pub async fn register(
        &self,
        req: &RegistrationRequest,
        now: i64,
    ) -> Result<User, RegisterError> {
        // 1. The mode and the invite, before anything else.
        if self.registration == RegistrationMode::Closed {
            return Err(RegisterError::Closed);
        }
        // `Open` is refused by the configuration (docs/decisions/0004); were
        // it ever set, an invite would still be required here.
        let hash = req
            .invite_token
            .as_deref()
            .and_then(token_hash)
            .ok_or(RegisterError::InviteRequired)?;
        let invite = self
            .invites
            .find_live(&hash, now)
            .await?
            .ok_or(RegisterError::InviteRequired)?;
        if invite.handle.as_deref().is_some_and(|h| h != req.handle) {
            return Err(RegisterError::InviteRequired);
        }
        // A used invite is spent, except to resume its own handle's
        // registration when that never made the account (its request
        // crashed or failed after redeeming; docs/decisions/0012). The
        // lookup only answers a caller holding this invite, for the handle
        // it was redeemed for.
        if let Some(by) = &invite.used_by
            && (by != &req.handle || self.store.find_user(&req.handle).await?.is_some())
        {
            return Err(RegisterError::InviteRequired);
        }

        // 2. The handle and password, then hash.
        check_new_handle(&req.handle).map_err(RegisterError::Invalid)?;
        check_length(&req.password)?;
        if self.store.find_user(&req.handle).await?.is_some() {
            return Err(RegisterError::HandleTaken);
        }
        let password_hash = self.passwords.hash(&req.password).await?;

        // 3. Redeem the invite for this handle, then create the account.
        // The redemption is never undone (docs/decisions/0012): the invite
        // can then only ever make the account `req.handle`, and handles are
        // unique, so however requests race, stall or crash, it makes one
        // account at most. A failure from here on leaves it spent on this
        // handle; a retry for the same handle resumes it.
        if !self.invites.redeem(&hash, &req.handle, now).await? {
            return Err(RegisterError::InviteRequired);
        }
        Ok(self
            .store
            .create_user(&req.handle, &req.handle, &password_hash, now)
            .await?)
    }
}
