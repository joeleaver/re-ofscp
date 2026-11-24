//! Password hashing (spec §4.1.4): Argon2id with 64 MiB memory, 3 passes,
//! 4 lanes and a 16-byte random salt, stored as a PHC string.
//!
//! Each hash or verification costs 64 MiB and on the order of 100 ms of CPU,
//! so they run on the blocking pool behind a semaphore: a burst of login
//! attempts queues instead of exhausting memory. Unknown handles are
//! verified against a fixed dummy hash, so response time does not reveal
//! whether an account exists (§4.1.2: "SHOULD NOT reveal whether the handle
//! exists").

use std::sync::{Arc, OnceLock};

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use tokio::sync::Semaphore;

pub use re_ofscp_types::auth::{MAX_PASSWORD_LEN, MIN_PASSWORD_LEN};

/// Memory cost in KiB (§4.1.4: at least 64 MiB).
const M_COST_KIB: u32 = 64 * 1024;
/// Passes (§4.1.4: at least 3).
const T_COST: u32 = 3;
/// Lanes (§4.1.4: 4).
const P_COST: u32 = 4;

/// Why a password operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PasswordError {
    /// Shorter than [`MIN_PASSWORD_LEN`] or longer than [`MAX_PASSWORD_LEN`].
    #[error("password must be {MIN_PASSWORD_LEN} to {MAX_PASSWORD_LEN} bytes")]
    Length,
    /// Every hashing slot stayed busy for [`QUEUE_WAIT`]: answer `503`.
    #[error("password hashing is saturated")]
    Busy,
    /// Hashing failed or a stored hash is unreadable (a server fault).
    #[error("password hashing failed: {0}")]
    Internal(String),
}

/// Longest a request waits for a hashing slot before giving up with
/// [`PasswordError::Busy`], so a flood queues boundedly instead of starving
/// every sign-in indefinitely.
pub const QUEUE_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// `Retry-After` for [`PasswordError::Busy`].
pub const BUSY_RETRY_SECS: u64 = 5;

fn argon2() -> Result<Argon2<'static>, PasswordError> {
    let params = Params::new(M_COST_KIB, T_COST, P_COST, None)
        .map_err(|e| PasswordError::Internal(e.to_string()))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Check a candidate password's length (bytes).
pub fn check_length(password: &str) -> Result<(), PasswordError> {
    if (MIN_PASSWORD_LEN..=MAX_PASSWORD_LEN).contains(&password.len()) {
        Ok(())
    } else {
        Err(PasswordError::Length)
    }
}

fn salt() -> Result<SaltString, PasswordError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| PasswordError::Internal(e.to_string()))?;
    SaltString::encode_b64(&bytes).map_err(|e| PasswordError::Internal(e.to_string()))
}

fn hash_blocking(password: &str) -> Result<String, PasswordError> {
    argon2()?
        .hash_password(password.as_bytes(), &salt()?)
        .map(|h| h.to_string())
        .map_err(|e| PasswordError::Internal(e.to_string()))
}

fn verify_blocking(password: &str, phc: &str) -> Result<bool, PasswordError> {
    let parsed = PasswordHash::new(phc).map_err(|e| PasswordError::Internal(e.to_string()))?;
    Ok(argon2()?
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

/// A PHC hash nobody's password matches, computed once, used for unknown
/// handles so their verification costs the same as a real one.
fn dummy_hash() -> Result<&'static str, PasswordError> {
    static DUMMY: OnceLock<Result<String, PasswordError>> = OnceLock::new();
    DUMMY
        .get_or_init(|| {
            let mut random = [0u8; 32];
            getrandom::fill(&mut random).map_err(|e| PasswordError::Internal(e.to_string()))?;
            let unguessable: String = random.iter().map(|b| format!("{b:02x}")).collect();
            hash_blocking(&unguessable)
        })
        .as_ref()
        .map(String::as_str)
        .map_err(Clone::clone)
}

/// Hashes and verifies passwords on the blocking pool, at most `permits` at
/// a time.
#[derive(Debug, Clone)]
pub struct Passwords {
    permits: Arc<Semaphore>,
    queue_wait: std::time::Duration,
}

impl Passwords {
    /// Allow `concurrent` operations at once (each holds 64 MiB).
    pub fn new(concurrent: usize) -> Self {
        Self::with_queue_wait(concurrent, QUEUE_WAIT)
    }

    /// As [`Passwords::new`], giving up with [`PasswordError::Busy`] after
    /// `queue_wait` without a slot.
    pub fn with_queue_wait(concurrent: usize, queue_wait: std::time::Duration) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(concurrent.max(1))),
            queue_wait,
        }
    }

    async fn run<T: Send + 'static>(
        &self,
        f: impl FnOnce() -> Result<T, PasswordError> + Send + 'static,
    ) -> Result<T, PasswordError> {
        let _permit = tokio::time::timeout(self.queue_wait, self.permits.acquire())
            .await
            .map_err(|_| PasswordError::Busy)?
            .map_err(|e| PasswordError::Internal(e.to_string()))?;
        tokio::task::spawn_blocking(f)
            .await
            .map_err(|e| PasswordError::Internal(e.to_string()))?
    }

    /// Hash a new password (length-checked) into a PHC string.
    pub async fn hash(&self, password: &str) -> Result<String, PasswordError> {
        check_length(password)?;
        let password = password.to_owned();
        self.run(move || hash_blocking(&password)).await
    }

    /// Whether `password` matches `phc`. With `phc = None` (no such account,
    /// or an account without a password) this still does the full work
    /// against a dummy hash and returns `false`.
    pub async fn verify(&self, password: &str, phc: Option<&str>) -> Result<bool, PasswordError> {
        let password = password.to_owned();
        let phc = phc.map(str::to_owned);
        self.run(move || {
            // Oversized input is refused without hashing it, but only after
            // the same permit wait, and it can never match.
            if password.len() > MAX_PASSWORD_LEN {
                return Ok(false);
            }
            match phc {
                Some(phc) => verify_blocking(&password, &phc),
                None => {
                    let _ = verify_blocking(&password, dummy_hash()?);
                    Ok(false)
                }
            }
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn hashes_are_argon2id_with_spec_parameters_and_verify() {
        let p = Passwords::new(2);
        let phc = p.hash("correct horse").await.unwrap();
        assert!(phc.starts_with("$argon2id$v=19$m=65536,t=3,p=4$"), "{phc}");
        let parsed = PasswordHash::new(&phc).unwrap();
        assert_eq!(parsed.salt.unwrap().len(), 22, "16-byte salt, base64");
        assert!(p.verify("correct horse", Some(&phc)).await.unwrap());
        assert!(!p.verify("wrong horse", Some(&phc)).await.unwrap());
        // Unknown account: false, after doing the work.
        assert!(!p.verify("correct horse", None).await.unwrap());
        // Salts differ.
        assert_ne!(phc, p.hash("correct horse").await.unwrap());
    }

    #[tokio::test]
    async fn a_saturated_queue_answers_busy_instead_of_waiting() {
        let p = Passwords::with_queue_wait(1, std::time::Duration::from_millis(1));
        // Hold the only slot, as a long-running hash would.
        let held = p.permits.clone().acquire_owned().await.unwrap();
        assert_eq!(p.hash("correct horse").await, Err(PasswordError::Busy));
        assert_eq!(
            p.verify("correct horse", None).await,
            Err(PasswordError::Busy)
        );
        drop(held);
        assert!(p.hash("correct horse").await.is_ok());
    }

    #[tokio::test]
    async fn lengths_are_enforced() {
        let p = Passwords::new(1);
        assert_eq!(p.hash("short").await, Err(PasswordError::Length));
        assert_eq!(
            p.hash(&"x".repeat(MAX_PASSWORD_LEN + 1)).await,
            Err(PasswordError::Length)
        );
        assert!(
            !p.verify(&"x".repeat(MAX_PASSWORD_LEN + 1), None)
                .await
                .unwrap()
        );
    }
}
