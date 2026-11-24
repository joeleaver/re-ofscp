//! Admin identity and the admin API (docs/decisions/0005).
//!
//! Admins are a separate identity system from OFSCP users: their own type
//! (`Admin`), their own sign-in, server-side sessions and a TOTP second
//! factor. They are not actors, are never federated and never sign OFSCP
//! requests. Every admin action goes through `/api/admin/*`, authenticated
//! by the admin session, and is recorded in the audit log.

pub mod audit;
pub mod auth;
pub mod manage;
pub mod routes;
pub mod sessions;
pub mod store;
pub mod totp;

use std::sync::Arc;

use re_ofscp_types::Authority;
use re_ofscp_types::admin::{AdminRole, is_valid_admin_username};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;

pub use audit::AuditLog;
pub use sessions::{Session, SessionStore};
pub use store::{Admin, AdminStore, AdminStoreError, NewAdmin};
pub use totp::SecretBox;

use crate::accounts::{PasswordError, Passwords};
use crate::db::{Db, DbError};
use crate::ratelimit::{FailureBackoff, Limited, RateLimiter};

/// `created_by` of the first owner.
pub const SETUP_CREATOR: &str = "setup";

/// Most usable invites at once. Listing them is then one bounded read.
pub const MAX_OUTSTANDING_INVITES: usize = 1000;

/// The admin secrets from configuration.
#[derive(Debug, Default)]
pub struct AdminSecrets {
    /// Seals TOTP secrets at rest (`ADMIN_SECRET_KEY`). Without it the
    /// admin API is off: there is no safe way to store a second factor.
    pub secret_key: Option<[u8; 32]>,
    /// The one-time first-admin setup token (`ADMIN_SETUP_TOKEN`).
    pub setup_token: Option<String>,
}

/// Why first-admin setup failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SetupError {
    /// No `ADMIN_SETUP_TOKEN` is configured.
    #[error("first-admin setup is not configured")]
    NotConfigured,
    /// The token is wrong.
    #[error("invalid setup token")]
    BadToken,
    /// An admin exists already; setup is over.
    #[error("setup is complete: an admin already exists")]
    Done,
    /// The username does not match the admin username grammar.
    #[error("username must match ^[a-z0-9][a-z0-9_.-]{{2,63}}$")]
    InvalidUsername,
    /// The password is too short or too long, or hashing is saturated.
    #[error(transparent)]
    Password(#[from] PasswordError),
    /// Storage failed.
    #[error(transparent)]
    Db(#[from] DbError),
}

/// Why a sign-in failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LoginError {
    /// Wrong username, password or code, or a disabled admin. One answer
    /// for all, so nothing reveals which part was wrong.
    #[error("invalid username, password or code")]
    Invalid {
        /// Whether the username names an admin (for the audit log only;
        /// never in the response).
        known: bool,
    },
    /// Too many failures for this username.
    #[error("too many failed sign-ins")]
    Locked(Limited),
    /// Hashing is saturated.
    #[error("password hashing is saturated")]
    Busy,
    /// A server fault (storage, an unreadable secret).
    #[error("sign-in failed: {0}")]
    Internal(String),
}

/// Admin services shared by the admin routes.
#[derive(Debug)]
pub struct Admins {
    /// This provider's authority (the TOTP issuer, the allowed `Origin`).
    pub domain: Authority,
    /// Admins.
    pub store: AdminStore,
    /// Sessions.
    pub sessions: SessionStore,
    /// The audit log.
    pub audit: AuditLog,
    /// Password hashing, shared with OFSCP accounts (one memory budget).
    pub passwords: Passwords,
    /// Per-client-address limiter for the unauthenticated admin endpoints.
    pub per_source: RateLimiter,
    /// Per-username progressive lockout after failed sign-ins.
    pub login_backoff: FailureBackoff,
    secrets: Option<SecretBox>,
    setup_token_hash: Option<[u8; 32]>,
    /// Serializes changes that must see a consistent set of admins (setup,
    /// creating admins, role changes and disabling: "at least one active
    /// owner" and the admin cap).
    roster: Mutex<()>,
    /// Serializes issuing invites, so the cap on outstanding invites
    /// ([`MAX_OUTSTANDING_INVITES`]) holds exactly.
    pub invite_issue: Mutex<()>,
}

fn sha256(s: &str) -> [u8; 32] {
    Sha256::digest(s.as_bytes()).into()
}

impl Admins {
    /// Admin services over `db` for `domain`.
    pub fn new(
        domain: Authority,
        db: Arc<Db>,
        passwords: Passwords,
        secrets: AdminSecrets,
    ) -> Self {
        Self {
            domain,
            store: AdminStore::new(db.clone()),
            sessions: SessionStore::new(db.clone()),
            audit: AuditLog::new(db),
            passwords,
            // 5 requests at once per source, then 10 per minute.
            per_source: RateLimiter::new(5, 10, 100_000),
            // 5 free failures, then 60 s doubling to 1 h.
            login_backoff: FailureBackoff::new(5, 60, 3600, 10_000),
            secrets: secrets.secret_key.as_ref().map(SecretBox::new),
            setup_token_hash: secrets.setup_token.as_deref().map(sha256),
            roster: Mutex::new(()),
            invite_issue: Mutex::new(()),
        }
    }

    /// Whether the admin API is available (`ADMIN_SECRET_KEY` is set).
    pub fn enabled(&self) -> bool {
        self.secrets.is_some()
    }

    fn secrets(&self) -> Result<&SecretBox, DbError> {
        self.secrets
            .as_ref()
            .ok_or_else(|| DbError::Query("admin secret key is not configured".to_owned()))
    }

    /// Create the first admin, an owner, with the one-time setup token.
    /// Refused once any admin exists, so the token is useless after first
    /// use even if it stays configured. The owner must enroll TOTP before
    /// doing anything else.
    pub async fn setup(
        &self,
        token: &str,
        username: &str,
        password: &str,
        now: i64,
    ) -> Result<Admin, SetupError> {
        let expected = self.setup_token_hash.ok_or(SetupError::NotConfigured)?;
        // Compare digests in constant time: no timing hint about the token.
        let ok: bool = sha256(token).ct_eq(&expected).into();
        if !ok {
            return Err(SetupError::BadToken);
        }
        if !is_valid_admin_username(username) {
            return Err(SetupError::InvalidUsername);
        }
        let hash = self.passwords.hash(password).await?;
        let _roster = self.roster.lock().await;
        if self.store.any().await? {
            return Err(SetupError::Done);
        }
        let created = self
            .store
            .create(
                NewAdmin {
                    username,
                    password_hash: &hash,
                    role: AdminRole::Owner,
                    password_change_required: false,
                    created_by: SETUP_CREATOR,
                },
                now,
            )
            .await;
        match created {
            Ok(a) => Ok(a),
            // Nothing existed a moment ago under the roster lock.
            Err(AdminStoreError::Taken) => Err(SetupError::Done),
            Err(AdminStoreError::Db(e)) => Err(e.into()),
        }
    }

    /// Check a sign-in: username, password and, once enrolled, a TOTP code.
    ///
    /// Shaped like the OFSCP login (docs/decisions/0004): a valid username
    /// is counted as a failure before anything is checked, unknown and
    /// disabled admins are verified against a dummy hash, faults are
    /// refunded, and a success clears the count. A code is accepted once:
    /// its step is recorded with a conditional update.
    pub async fn login(
        &self,
        username: &str,
        password: &str,
        code: Option<&str>,
        now: i64,
    ) -> Result<Admin, LoginError> {
        let valid = is_valid_admin_username(username);
        if valid {
            self.login_backoff
                .attempt(username, now)
                .map_err(LoginError::Locked)?;
        }
        let undecided = |e: LoginError| {
            if valid {
                self.login_backoff.refund(username);
            }
            e
        };
        let admin = if valid {
            self.store
                .find(username)
                .await
                .map_err(|e| undecided(LoginError::Internal(e.to_string())))?
        } else {
            None
        };
        let known = admin.is_some();
        let active = admin.filter(Admin::is_active);
        let ok = self
            .passwords
            .verify(password, active.as_ref().map(|a| a.password_hash.as_str()))
            .await
            .map_err(|e| {
                undecided(match e {
                    PasswordError::Busy => LoginError::Busy,
                    other => LoginError::Internal(other.to_string()),
                })
            })?;
        let Some(admin) = active.filter(|_| ok) else {
            return Err(LoginError::Invalid { known });
        };
        if admin.totp_enabled() {
            let secret = self
                .secrets()
                .and_then(|b| {
                    b.open(&admin.totp_secret, &admin.username)
                        .map_err(|e| DbError::Decode(e.to_string()))
                })
                .map_err(|e| undecided(LoginError::Internal(e.to_string())))?;
            let step = code
                .and_then(|c| totp::verify(&secret, c, now, admin.totp_last_step))
                .ok_or(LoginError::Invalid { known })?;
            let fresh = self
                .store
                .use_totp_step(&admin.username, step)
                .await
                .map_err(|e| undecided(LoginError::Internal(e.to_string())))?;
            if !fresh {
                // A concurrent sign-in used this code (or a later one).
                return Err(LoginError::Invalid { known });
            }
        }
        self.login_backoff.succeed(&admin.username);
        Ok(admin)
    }

    /// Start a session for `admin`: the token (for the cookie only) and
    /// when the session ends.
    pub async fn start_session(&self, admin: &Admin, now: i64) -> Result<(String, i64), DbError> {
        let token = sessions::new_token()?;
        let hash = sessions::token_hash(&token)
            .ok_or_else(|| DbError::Query("minted an unrecognisable session token".to_owned()))?;
        let expires_at = self.sessions.create(&hash, &admin.username, now).await?;
        Ok((token, expires_at))
    }

    /// The live session for cookie value `token` and its active admin, or
    /// `None`. A session past either limit, or whose admin is gone or
    /// disabled, is deleted. Activity is recorded at most once a minute.
    pub async fn resume(&self, token: &str, now: i64) -> Result<Option<(Session, Admin)>, DbError> {
        let Some(hash) = sessions::token_hash(token) else {
            return Ok(None);
        };
        let Some(session) = self.sessions.find(&hash).await? else {
            return Ok(None);
        };
        if !session.live_at(now) {
            self.sessions.delete(&hash).await?;
            return Ok(None);
        }
        let admin = self
            .store
            .find(&session.username)
            .await?
            .filter(Admin::is_active);
        let Some(admin) = admin else {
            self.sessions.delete(&hash).await?;
            return Ok(None);
        };
        if now - session.last_seen_at >= sessions::TOUCH_EVERY_SECS {
            self.sessions.touch(&hash, now).await?;
        }
        Ok(Some((session, admin)))
    }

    /// Delete ended sessions, every minute, until the task is dropped.
    pub async fn purge_sessions_forever(self: Arc<Self>, clock: Arc<dyn crate::signing::Clock>) {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            if let Err(e) = self.sessions.purge(clock.now().unix_timestamp()).await {
                tracing::warn!(error = %e, "purging ended admin sessions failed");
            }
        }
    }
}
