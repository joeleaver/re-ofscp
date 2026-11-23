//! Bootstrap tokens (spec §4.2).
//!
//! A bootstrap token is 256 random bits (`bt_` + base64url), valid for 300 s,
//! bound to the handle that just proved its password, accepted only by
//! `POST /api/auth/device-keys`, and consumed by the first *successful*
//! registration (a request rejected for a bad key leaves it usable).
//!
//! Tokens live in memory, keyed by their SHA-256, never stored in the clear.
//! A restart forgets them; the user simply logs in again, so persistence
//! would add risk without value. The store is bounded; when full it refuses
//! to issue (`503`) rather than evict.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use sha2::{Digest, Sha256};

/// Token lifetime (§4.2 RECOMMENDED 300 s).
pub const BOOTSTRAP_TTL_SECS: i64 = 300;

/// Prefix of every bootstrap token.
const PREFIX: &str = "bt_";

#[derive(Debug)]
struct Entry {
    handle: String,
    expires: i64,
}

/// Why a token could not be issued.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IssueError {
    /// Too many unexpired tokens outstanding.
    #[error("too many outstanding bootstrap tokens")]
    Full,
    /// The system random source failed.
    #[error("random source failed: {0}")]
    Random(String),
}

/// Outstanding bootstrap tokens.
#[derive(Debug)]
pub struct BootstrapTokens {
    inner: Mutex<HashMap<[u8; 32], Entry>>,
    capacity: usize,
}

fn digest(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

impl BootstrapTokens {
    /// A store holding at most `capacity` unexpired tokens.
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            capacity,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<[u8; 32], Entry>> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Issue a token for `handle`, valid until `now + BOOTSTRAP_TTL_SECS`.
    pub fn issue(&self, handle: &str, now: i64) -> Result<String, IssueError> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|e| IssueError::Random(e.to_string()))?;
        let token = format!("{PREFIX}{}", B64URL.encode(bytes));
        let mut map = self.lock();
        if map.len() >= self.capacity {
            map.retain(|_, e| e.expires > now);
            if map.len() >= self.capacity {
                return Err(IssueError::Full);
            }
        }
        map.insert(
            digest(&token),
            Entry {
                handle: handle.to_owned(),
                expires: now + BOOTSTRAP_TTL_SECS,
            },
        );
        Ok(token)
    }

    /// The handle `token` is bound to, if it is outstanding and unexpired.
    /// Does not consume it.
    pub fn peek(&self, token: &str, now: i64) -> Option<String> {
        if !token.starts_with(PREFIX) {
            return None;
        }
        let map = self.lock();
        map.get(&digest(token))
            .filter(|e| e.expires > now)
            .map(|e| e.handle.clone())
    }

    /// Consume `token` if it is still outstanding, unexpired and bound to
    /// `handle`. Atomic: of two concurrent uses, exactly one succeeds.
    pub fn consume(&self, token: &str, handle: &str, now: i64) -> bool {
        let mut map = self.lock();
        let key = digest(token);
        match map.get(&key) {
            Some(e) if e.expires > now && e.handle == handle => {
                map.remove(&key);
                true
            }
            _ => false,
        }
    }

    /// Forget every token bound to `handle` (account disabled, password
    /// changed).
    pub fn revoke_handle(&self, handle: &str) {
        self.lock().retain(|_, e| e.handle != handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: i64 = 1_000_000;

    #[test]
    fn tokens_are_long_random_and_prefixed() {
        let s = BootstrapTokens::new(10);
        let a = s.issue("alice", T).unwrap();
        let b = s.issue("alice", T).unwrap();
        assert!(a.starts_with("bt_"));
        assert_eq!(a.len(), 3 + 43, "256 bits, base64url");
        assert_ne!(a, b);
    }

    #[test]
    fn single_use_bound_to_handle_and_expiring() {
        let s = BootstrapTokens::new(10);
        let t = s.issue("alice", T).unwrap();
        assert_eq!(s.peek(&t, T).as_deref(), Some("alice"));
        assert!(!s.consume(&t, "bob", T), "bound to alice");
        assert!(s.consume(&t, "alice", T));
        assert!(!s.consume(&t, "alice", T), "single use");
        assert_eq!(s.peek(&t, T), None);

        let t = s.issue("alice", T).unwrap();
        assert_eq!(
            s.peek(&t, T + BOOTSTRAP_TTL_SECS - 1).as_deref(),
            Some("alice")
        );
        assert_eq!(s.peek(&t, T + BOOTSTRAP_TTL_SECS), None);
        assert!(!s.consume(&t, "alice", T + BOOTSTRAP_TTL_SECS));
    }

    #[test]
    fn unknown_and_malformed_tokens_are_rejected() {
        let s = BootstrapTokens::new(10);
        assert_eq!(s.peek("bt_nope", T), None);
        assert_eq!(s.peek("", T), None);
        assert_eq!(s.peek("Bearer x", T), None);
    }

    #[test]
    fn bounded_without_evicting_live_tokens() {
        let s = BootstrapTokens::new(2);
        let a = s.issue("a", T).unwrap();
        s.issue("b", T).unwrap();
        assert_eq!(s.issue("c", T), Err(IssueError::Full));
        assert_eq!(s.peek(&a, T).as_deref(), Some("a"));
        // Expired tokens make room.
        assert!(s.issue("c", T + BOOTSTRAP_TTL_SECS).is_ok());
    }

    #[test]
    fn revoking_a_handle_drops_its_tokens() {
        let s = BootstrapTokens::new(10);
        let a = s.issue("alice", T).unwrap();
        let b = s.issue("bob", T).unwrap();
        s.revoke_handle("alice");
        assert_eq!(s.peek(&a, T), None);
        assert_eq!(s.peek(&b, T).as_deref(), Some("bob"));
    }
}
