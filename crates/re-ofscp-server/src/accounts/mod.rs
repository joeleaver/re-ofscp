//! OFSCP accounts on this provider (spec §4.1–§4.7).
//!
//! Accounts are created by admins or by invitation only, never by open
//! self-registration (docs/decisions/0004). A user proves their password
//! once per device ([`Accounts::login`]), receives a bootstrap token, and
//! registers a device key with it; every request after that is signed.

pub mod bootstrap;
pub mod invites;
pub mod keys;
pub mod password;
pub mod register;
pub mod routes;
pub mod store;

use std::sync::Arc;

use re_ofscp_types::auth::RegistrationMode;
use re_ofscp_types::{Authority, is_valid_handle};
use tokio::sync::{Mutex, broadcast};

pub use bootstrap::{BOOTSTRAP_TTL_SECS, BootstrapTokens, IssueError};
pub use invites::{InviteStore, InviteSummary, IssuedInvite, Revoked};
pub use keys::ProviderKeys;
pub use password::{PasswordError, Passwords};
pub use register::{InviteError, RegisterError};
pub use store::{AccountStore, AccountSummary, DeviceKey, StoreError, User};

use crate::db::Db;
use crate::ratelimit::{FailureBackoff, RateLimiter};
use crate::signing::KeyResolver;

/// Most active device keys one account may hold.
pub const MAX_DEVICE_KEYS: usize = 20;

/// Longest accepted `device_name`, in characters.
pub const MAX_DEVICE_NAME_CHARS: usize = 200;

/// Longest accepted display name, in characters.
pub const MAX_DISPLAY_NAME_CHARS: usize = 100;

/// Handles beginning with this are reserved for provider-minted guests
/// (§2.2.1, §4.8).
pub const GUEST_PREFIX: &str = "guest_";

/// A key was revoked (or all of an account's keys were). WebSocket
/// connections authenticated with it must close with `4003` (§4.7.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revocation {
    /// The account.
    pub handle: String,
    /// The key, or `None` for every key of the account.
    pub key_id: Option<String>,
}

/// Why an account could not be created.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CreateError {
    /// The handle does not match `^[a-z0-9_-]{3,32}$` (§2.2.1).
    #[error("handle must match ^[a-z0-9_-]{{3,32}}$")]
    InvalidHandle,
    /// The handle starts with `guest_` (§2.2.1).
    #[error("handles starting with guest_ are reserved")]
    ReservedHandle,
    /// The display name is empty or too long.
    #[error("display name must be 1 to {MAX_DISPLAY_NAME_CHARS} characters")]
    InvalidDisplayName,
    /// The password is too short or too long.
    #[error(transparent)]
    Password(#[from] PasswordError),
    /// The handle is taken, or storage failed.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Validate a handle for a new full account.
pub fn check_new_handle(handle: &str) -> Result<(), CreateError> {
    if !is_valid_handle(handle) {
        return Err(CreateError::InvalidHandle);
    }
    if handle.starts_with(GUEST_PREFIX) {
        return Err(CreateError::ReservedHandle);
    }
    Ok(())
}

/// Account services shared by the routes and the admin API.
#[derive(Debug)]
pub struct Accounts {
    /// This provider's authority.
    pub domain: Authority,
    /// Who may register (§4.1.1).
    pub registration: RegistrationMode,
    /// Storage.
    pub store: AccountStore,
    /// Account invites.
    pub invites: InviteStore,
    /// Password hashing.
    pub passwords: Passwords,
    /// Outstanding bootstrap tokens.
    pub tokens: BootstrapTokens,
    /// Key resolution (local accounts, then remote).
    pub keys: Arc<ProviderKeys>,
    /// Per-client-address limiter for the unauthenticated auth endpoints.
    pub per_source: RateLimiter,
    /// Per-handle progressive lockout after failed logins.
    pub login_backoff: FailureBackoff,
    /// Serializes device-key registration, so the per-account key cap holds
    /// exactly (registration is rare).
    pub key_registration: Mutex<()>,
    /// Serializes claiming an invite with creating its account.
    registration_lock: Mutex<()>,
    revocations: broadcast::Sender<Revocation>,
}

impl Accounts {
    /// Account services over `db` for `domain`, registering by
    /// `registration`, resolving this provider's own signatures with
    /// `provider_keys` (key id, public key) and remote signers with `remote`.
    pub fn new(
        domain: Authority,
        provider_keys: Vec<(String, ed25519_dalek::VerifyingKey)>,
        registration: RegistrationMode,
        db: Arc<Db>,
        remote: Arc<dyn KeyResolver>,
    ) -> Self {
        let invites = InviteStore::new(db.clone());
        let store = AccountStore::new(db);
        let keys = Arc::new(ProviderKeys::new(
            domain.clone(),
            provider_keys,
            store.clone(),
            remote,
        ));
        let (revocations, _) = broadcast::channel(1024);
        Self {
            domain,
            registration,
            store,
            invites,
            passwords: Passwords::new(4),
            tokens: BootstrapTokens::new(100_000),
            keys,
            // 10 requests at once per source, then 20 per minute.
            per_source: RateLimiter::new(10, 20, 100_000),
            // 5 free failures, then 60 s doubling to 1 h.
            login_backoff: FailureBackoff::new(5, 60, 3600, 100_000),
            key_registration: Mutex::new(()),
            registration_lock: Mutex::new(()),
            revocations,
        }
    }

    /// Create an active account (admins and invitations only; there is no
    /// open registration).
    pub async fn create_account(
        &self,
        handle: &str,
        display_name: &str,
        password: &str,
        now: i64,
    ) -> Result<User, CreateError> {
        check_new_handle(handle)?;
        let display_name = display_name.trim();
        let len = display_name.chars().count();
        if len == 0 || len > MAX_DISPLAY_NAME_CHARS {
            return Err(CreateError::InvalidDisplayName);
        }
        let hash = self.passwords.hash(password).await?;
        Ok(self
            .store
            .create_user(handle, display_name, &hash, now)
            .await?)
    }

    /// Disable an account: it can no longer log in, its keys stop
    /// verifying, outstanding bootstrap tokens die, and its keys are revoked.
    ///
    /// The status change is what takes effect (logins and key lookups check
    /// it), so once it is stored the in-process effects run unconditionally,
    /// before the fallible bulk revocation: a failure there leaves the keys
    /// marked active but unusable, and calling this again finishes the job.
    pub async fn disable_account(&self, user: &User, now: i64) -> Result<(), StoreError> {
        self.store.set_status(user, store::status::DISABLED).await?;
        self.tokens.revoke_handle(&user.handle);
        self.keys.invalidate(&user.handle);
        self.announce(Revocation {
            handle: user.handle.clone(),
            key_id: None,
        });
        self.store.revoke_all_keys(&user.handle, now).await?;
        Ok(())
    }

    /// Subscribe to key revocations (for the WebSocket layer, §4.7.1).
    pub fn revocations(&self) -> broadcast::Receiver<Revocation> {
        self.revocations.subscribe()
    }

    fn announce(&self, r: Revocation) {
        // No subscribers yet is fine: nothing to close.
        let _ = self.revocations.send(r);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_handles_follow_the_grammar_and_avoid_the_guest_prefix() {
        assert_eq!(check_new_handle("alice"), Ok(()));
        assert_eq!(check_new_handle("Alice"), Err(CreateError::InvalidHandle));
        assert_eq!(check_new_handle("al"), Err(CreateError::InvalidHandle));
        assert_eq!(
            check_new_handle("guest_bob"),
            Err(CreateError::ReservedHandle)
        );
        assert_eq!(check_new_handle("guestbob"), Ok(()));
    }
}
