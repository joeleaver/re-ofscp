//! Server-side admin sessions (`AdminSession` in `schema.rhype`).
//!
//! * **Token:** `as_` + 256 random bits, base64url, sent only in the
//!   session cookie. Only its SHA-256 is stored.
//! * **Cookie:** `__Secure-re-ofscp-admin`, `HttpOnly; Secure;
//!   SameSite=Strict; Path=/api/admin`. The admin UI under `/admin` is
//!   static and needs no credential, and a cookie has one path, so it is
//!   scoped to the API alone.
//! * **Lifetime:** at most [`ABSOLUTE_SECS`] from sign-in, and ended after
//!   [`IDLE_SECS`] without a request.
//! * **CSRF token:** derived from the session token (SHA-256 under a
//!   context string), so nothing more is stored: the page cannot read the
//!   `HttpOnly` cookie, and the server recomputes the token from it.

use std::sync::Arc;

use axum::http::HeaderMap;
use axum::http::header::COOKIE;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::db::{Db, DbError, Ql};
use crate::timefmt;

/// The session cookie's name. The `__Secure-` prefix makes browsers refuse
/// it unless it is set with `Secure` from a secure origin.
pub const COOKIE_NAME: &str = "__Secure-re-ofscp-admin";

/// The cookie's path: the admin API.
pub const COOKIE_PATH: &str = "/api/admin";

/// Longest a session lasts: 12 hours.
pub const ABSOLUTE_SECS: i64 = 12 * 3600;

/// A session ends after this long without a request: 30 minutes.
pub const IDLE_SECS: i64 = 30 * 60;

/// Activity is recorded at most this often per session, so reads do not
/// each cost a write.
pub const TOUCH_EVERY_SECS: i64 = 60;

/// Prefix of every session token.
const TOKEN_PREFIX: &str = "as_";

/// Longest cookie value looked up. Ours are 46 characters.
const MAX_TOKEN_LEN: usize = 128;

/// Context for deriving the CSRF token.
const CSRF_CONTEXT: &[u8] = b"re-ofscp admin csrf v1\0";

/// A fresh session token.
pub fn new_token() -> Result<String, DbError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| DbError::Query(format!("random source: {e}")))?;
    Ok(format!("{TOKEN_PREFIX}{}", B64URL.encode(bytes)))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The stored form of a session token, or `None` if it cannot be one of
/// ours (so it is never looked up).
pub fn token_hash(token: &str) -> Option<String> {
    if !token.starts_with(TOKEN_PREFIX) || token.len() > MAX_TOKEN_LEN {
        return None;
    }
    Some(hex(&Sha256::digest(token.as_bytes())))
}

/// The CSRF token belonging to session `token`.
pub fn csrf_token(token: &str) -> String {
    let mut h = Sha256::new();
    h.update(CSRF_CONTEXT);
    h.update(token.as_bytes());
    B64URL.encode(h.finalize())
}

/// `Set-Cookie` value starting a session.
pub fn set_cookie(token: &str) -> String {
    format!(
        "{COOKIE_NAME}={token}; Path={COOKIE_PATH}; Max-Age={ABSOLUTE_SECS}; HttpOnly; Secure; SameSite=Strict"
    )
}

/// `Set-Cookie` value ending a session in the browser.
pub fn clear_cookie() -> String {
    format!("{COOKIE_NAME}=; Path={COOKIE_PATH}; Max-Age=0; HttpOnly; Secure; SameSite=Strict")
}

/// What the request's cookies say about the session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CookieToken {
    /// No session cookie.
    Absent,
    /// Exactly one value.
    One(String),
    /// More than one distinct value (e.g. one planted for a parent domain
    /// by a sibling host): refused rather than guessed between.
    Ambiguous,
}

/// The session cookie from `headers`, across every `Cookie` header.
pub fn cookie_token(headers: &HeaderMap) -> CookieToken {
    let mut found: Option<&str> = None;
    for value in headers.get_all(COOKIE) {
        let Ok(value) = value.to_str() else { continue };
        for pair in value.split(';') {
            let Some((name, v)) = pair.trim().split_once('=') else {
                continue;
            };
            if name != COOKIE_NAME {
                continue;
            }
            match found {
                Some(prev) if prev != v => return CookieToken::Ambiguous,
                _ => found = Some(v),
            }
        }
    }
    found.map_or(CookieToken::Absent, |v| CookieToken::One(v.to_owned()))
}

/// A stored session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// SHA-256 of the token, hex.
    pub token_hash: String,
    /// The admin's username.
    pub username: String,
    /// The admin's credential epoch when it was opened (or last
    /// re-stamped by the admin's own credential change).
    pub credential_epoch: i64,
    /// Unix seconds of the last recorded request.
    pub last_seen_at: i64,
    /// Unix seconds at which it ends regardless.
    pub expires_at: i64,
}

impl Session {
    /// Whether it is still valid at `now`.
    pub fn live_at(&self, now: i64) -> bool {
        now < self.expires_at && now < self.last_seen_at + IDLE_SECS
    }
}

#[derive(Deserialize)]
struct SessionRow {
    token_hash: String,
    username: String,
    credential_epoch: i64,
    last_seen_at: String,
    expires_at: String,
}

/// Session storage.
#[derive(Debug, Clone)]
pub struct SessionStore {
    db: Arc<Db>,
}

impl SessionStore {
    /// A store over `db`.
    pub fn new(db: Arc<Db>) -> Self {
        Self { db }
    }

    /// Store a session for `username`, opened under credential `epoch`,
    /// starting at `now`; returns its end.
    pub async fn create(
        &self,
        token_hash: &str,
        username: &str,
        epoch: i64,
        now: i64,
    ) -> Result<i64, DbError> {
        let expires_at = now + ABSOLUTE_SECS;
        let q = Ql::new("AdminSession.create({ token_hash: ")
            .str(token_hash)
            .raw(", username: ")
            .str(username)
            .raw(", credential_epoch: ")
            .int(epoch)
            .raw(", created_at: ")
            .unix_seconds(now)
            .raw(", last_seen_at: ")
            .unix_seconds(now)
            .raw(", expires_at: ")
            .unix_seconds(expires_at)
            .raw(" })");
        self.db.execute(&q).await?;
        Ok(expires_at)
    }

    /// The session with `token_hash`, if stored (live or not).
    pub async fn find(&self, token_hash: &str) -> Result<Option<Session>, DbError> {
        let q = Ql::new("AdminSession.filter(.token_hash == ")
            .str(token_hash)
            .raw(")");
        let Some(row) = self.db.fetch::<SessionRow>(&q).await?.into_iter().next() else {
            return Ok(None);
        };
        let r = row.data;
        let time = |s: &str| {
            timefmt::unix(s).ok_or_else(|| DbError::Decode("unreadable session time".to_owned()))
        };
        Ok(Some(Session {
            last_seen_at: time(&r.last_seen_at)?,
            expires_at: time(&r.expires_at)?,
            token_hash: r.token_hash,
            username: r.username,
            credential_epoch: r.credential_epoch,
        }))
    }

    /// Record activity at `now`.
    pub async fn touch(&self, token_hash: &str, now: i64) -> Result<(), DbError> {
        let q = Ql::new("AdminSession.filter(.token_hash == ")
            .str(token_hash)
            .raw(").update({ last_seen_at: ")
            .unix_seconds(now)
            .raw(" })");
        self.db.execute(&q).await
    }

    /// Carry the session with `token_hash` over to credential `epoch` (the
    /// admin's own credential change, made through this session).
    pub async fn restamp(&self, token_hash: &str, epoch: i64) -> Result<(), DbError> {
        let q = Ql::new("AdminSession.filter(.token_hash == ")
            .str(token_hash)
            .raw(").update({ credential_epoch: ")
            .int(epoch)
            .raw(" })");
        self.db.execute(&q).await
    }

    /// End one session.
    pub async fn delete(&self, token_hash: &str) -> Result<(), DbError> {
        let q = Ql::new("AdminSession.filter(.token_hash == ")
            .str(token_hash)
            .raw(").delete()");
        self.db.execute(&q).await
    }

    /// End every session of `username` except the one with `keep` (if any).
    pub async fn delete_for(&self, username: &str, keep: Option<&str>) -> Result<(), DbError> {
        let q = Ql::new("AdminSession.filter(.username == ").str(username);
        let q = match keep {
            Some(k) => q.raw(" && .token_hash != ").str(k),
            None => q,
        };
        self.db.execute(&q.raw(").delete()")).await
    }

    /// Delete sessions that ended by `now`, by either limit.
    pub async fn purge(&self, now: i64) -> Result<(), DbError> {
        let q = Ql::new("AdminSession.filter(.expires_at <= ")
            .unix_seconds(now)
            .raw(" || .last_seen_at <= ")
            .unix_seconds(now - IDLE_SECS)
            .raw(").delete()");
        self.db.execute(&q).await
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    #[test]
    fn tokens_hash_and_derive_a_csrf_token() {
        let t = new_token().unwrap();
        assert!(t.starts_with("as_"));
        assert_eq!(t.len(), 46);
        assert_ne!(t, new_token().unwrap());
        assert_eq!(token_hash(&t).unwrap().len(), 64);
        assert_eq!(token_hash("ai_x"), None);
        assert_eq!(token_hash(&format!("as_{}", "x".repeat(200))), None);
        assert_eq!(csrf_token(&t), csrf_token(&t));
        assert_ne!(csrf_token(&t), csrf_token(&new_token().unwrap()));
        assert_ne!(csrf_token(&t), token_hash(&t).unwrap());
    }

    #[test]
    fn cookies_carry_every_hardening_attribute() {
        let c = set_cookie("as_abc");
        for attr in [
            "__Secure-re-ofscp-admin=as_abc",
            "Path=/api/admin",
            "Max-Age=43200",
            "HttpOnly",
            "Secure",
            "SameSite=Strict",
        ] {
            assert!(c.contains(attr), "{c} lacks {attr}");
        }
        assert!(clear_cookie().contains("Max-Age=0"));
    }

    fn headers(values: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in values {
            h.append(COOKIE, HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn the_session_cookie_is_found_once_or_refused_as_ambiguous() {
        assert_eq!(cookie_token(&headers(&[])), CookieToken::Absent);
        assert_eq!(
            cookie_token(&headers(&["a=1; __Secure-re-ofscp-admin=as_x; b=2"])),
            CookieToken::One("as_x".to_owned())
        );
        assert_eq!(
            cookie_token(&headers(&[
                "__Secure-re-ofscp-admin=as_x",
                "__Secure-re-ofscp-admin=as_x"
            ])),
            CookieToken::One("as_x".to_owned())
        );
        assert_eq!(
            cookie_token(&headers(&[
                "__Secure-re-ofscp-admin=as_x; __Secure-re-ofscp-admin=as_y"
            ])),
            CookieToken::Ambiguous
        );
    }

    #[test]
    fn sessions_end_at_the_absolute_or_idle_limit() {
        let s = Session {
            token_hash: String::new(),
            username: "joe".into(),
            credential_epoch: 0,
            last_seen_at: 1_000,
            expires_at: 1_000 + ABSOLUTE_SECS,
        };
        assert!(s.live_at(1_000));
        assert!(s.live_at(1_000 + IDLE_SECS - 1));
        assert!(!s.live_at(1_000 + IDLE_SECS));
        let busy = Session {
            last_seen_at: 1_000 + ABSOLUTE_SECS - 1,
            ..s
        };
        assert!(!busy.live_at(1_000 + ABSOLUTE_SECS));
    }
}
