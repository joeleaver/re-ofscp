//! Authenticating admin requests: the session cookie, CSRF protection,
//! the restricted-session gate and role checks, each refusal audited.
//!
//! * **Session:** [`AdminCtx`] (full sessions only) and [`Restricted`]
//!   (also sessions still finishing setup) resume the session named by the
//!   cookie. Requests are never authenticated by OFSCP signatures.
//! * **CSRF:** every state-changing request (anything but `GET`/`HEAD`)
//!   must come from this provider's own origin: an `Origin` header, when
//!   present, must be `https://{DOMAIN}`, and `Sec-Fetch-Site`, when
//!   present, must be `same-origin`. Signed-in requests must also carry
//!   `X-CSRF-Token` matching the session. With `SameSite=Strict` and
//!   JSON-only bodies (which a cross-site form cannot send without a CORS
//!   preflight this API never grants) that is defence in depth.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{HeaderMap, Method};
use re_ofscp_types::Authority;
use re_ofscp_types::admin::AdminRole;
use subtle::ConstantTimeEq;

use super::audit::{Record, outcome};
use super::sessions::{CookieToken, cookie_token, csrf_token};
use super::{Admin, Session};
use crate::AppState;
use crate::client::{Peer, client_key};
use crate::problem::Problem;

/// The CSRF header.
pub const CSRF_HEADER: &str = "x-csrf-token";

fn internal(e: impl std::fmt::Display) -> Problem {
    tracing::error!(error = %e, "admin operation failed");
    Problem::internal()
}

/// The answer when `ADMIN_SECRET_KEY` is not configured.
pub fn disabled() -> Problem {
    Problem::not_found().with_detail("the admin console is not configured on this provider")
}

/// Whether `method` changes state.
pub fn is_mutation(method: &Method) -> bool {
    !matches!(*method, Method::GET | Method::HEAD)
}

/// Refuse a cross-origin state-changing request.
pub fn check_origin(headers: &HeaderMap, domain: &Authority) -> Result<(), Problem> {
    let refuse = || Problem::forbidden().with_detail("cross-origin requests are not accepted");
    let mut origins = headers.get_all("origin").iter();
    if let Some(origin) = origins.next() {
        let expected = format!("https://{domain}");
        let ok = origin
            .to_str()
            .is_ok_and(|o| o.eq_ignore_ascii_case(&expected));
        if !ok || origins.next().is_some() {
            return Err(refuse());
        }
    }
    let mut sites = headers.get_all("sec-fetch-site").iter();
    if let Some(site) = sites.next()
        && (site.as_bytes() != b"same-origin" || sites.next().is_some())
    {
        return Err(refuse());
    }
    Ok(())
}

fn csrf_matches(headers: &HeaderMap, token: &str) -> bool {
    let mut values = headers.get_all(CSRF_HEADER).iter();
    let (Some(v), None) = (values.next(), values.next()) else {
        return false;
    };
    csrf_token(token).as_bytes().ct_eq(v.as_bytes()).into()
}

/// The client address as the audit log records it.
pub fn source(state: &AppState, parts: &Parts) -> String {
    client_key(&state.config, &parts.headers, &Peer::from_parts(parts))
}

/// A signed-in admin whose sign-in is fully set up.
#[derive(Debug, Clone)]
pub struct AdminCtx {
    /// The admin, as stored when the request arrived.
    pub admin: Admin,
    /// The session.
    pub session: Session,
    /// The session token (to derive the CSRF token for the response).
    pub token: String,
    /// The client address.
    pub source: String,
    /// When the request arrived (unix seconds).
    pub now: i64,
}

/// A signed-in admin who may still be finishing setup (enrolling TOTP,
/// changing a password another admin chose).
#[derive(Debug, Clone)]
pub struct Restricted(pub AdminCtx);

async fn resume(parts: &Parts, state: &AppState) -> Result<AdminCtx, Problem> {
    let admins = &state.admins;
    if !admins.enabled() {
        return Err(disabled());
    }
    let mutation = is_mutation(&parts.method);
    if mutation {
        check_origin(&parts.headers, &admins.domain)?;
    }
    let unauthorized = || Problem::unauthorized().with_detail("sign in to the admin console");
    let token = match cookie_token(&parts.headers) {
        CookieToken::One(t) => t,
        CookieToken::Absent => return Err(unauthorized()),
        CookieToken::Ambiguous => {
            return Err(Problem::unauthorized()
                .with_detail("conflicting admin session cookies; clear them and sign in again"));
        }
    };
    let now = state.verifier.now();
    let (session, admin) = admins
        .resume(&token, now)
        .await
        .map_err(internal)?
        .ok_or_else(unauthorized)?;
    let ctx = AdminCtx {
        admin,
        session,
        source: source(state, parts),
        token,
        now,
    };
    if mutation && !csrf_matches(&parts.headers, &ctx.token) {
        ctx.deny(state, "csrf", parts.uri.path()).await;
        return Err(Problem::forbidden().with_detail("missing or invalid X-CSRF-Token"));
    }
    Ok(ctx)
}

impl FromRequestParts<AppState> for Restricted {
    type Rejection = Problem;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Problem> {
        resume(parts, state).await.map(Self)
    }
}

impl FromRequestParts<AppState> for AdminCtx {
    type Rejection = Problem;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Problem> {
        let ctx = resume(parts, state).await?;
        if ctx.admin.restricted() {
            ctx.deny(state, "restricted", parts.uri.path()).await;
            return Err(Problem::forbidden().with_detail(
                "finish setting up your sign-in first: enroll TOTP and change your password if asked",
            ));
        }
        Ok(ctx)
    }
}

/// An action recorded as pending; finish it with [`Audited::ok`] or
/// [`Audited::failed`].
#[must_use = "finish the audit entry"]
pub struct Audited<'a> {
    state: &'a AppState,
    id: u64,
    record: Record,
}

impl Audited<'_> {
    /// The action succeeded.
    pub async fn ok(self, detail: &str) {
        self.state
            .admins
            .audit
            .finish(self.id, &self.record, outcome::OK, detail)
            .await;
    }

    /// The action failed; `detail` says why (never a secret).
    pub async fn failed(self, detail: &str) {
        self.state
            .admins
            .audit
            .finish(self.id, &self.record, outcome::FAILED, detail)
            .await;
    }
}

impl AdminCtx {
    fn record(&self, action: &'static str, target: &str, detail: &str) -> Record {
        Record {
            admin: self.admin.username.clone(),
            action,
            target: target.to_owned(),
            source: self.source.clone(),
            detail: detail.to_owned(),
        }
    }

    /// The CSRF token for this session.
    pub fn csrf_token(&self) -> String {
        csrf_token(&self.token)
    }

    /// Record a refusal. Best effort: the request is refused either way.
    pub async fn deny(&self, state: &AppState, action: &'static str, target: &str) {
        let r = self.record(action, target, "");
        if let Err(e) = state
            .admins
            .audit
            .record(&r, outcome::DENIED, self.now)
            .await
        {
            tracing::error!(target: "audit", error = %e, "could not record a refused admin action");
        }
    }

    /// Require at least `role` for `action` on `target`; a refusal is
    /// audited and answered `403`.
    pub async fn require(
        &self,
        state: &AppState,
        role: AdminRole,
        action: &'static str,
        target: &str,
    ) -> Result<(), Problem> {
        if self.admin.role >= role {
            return Ok(());
        }
        self.deny(state, action, target).await;
        Err(Problem::forbidden().with_detail(format!("this needs the {} role", role.as_str())))
    }

    /// Record `action` on `target` as pending before running it. If the
    /// audit log cannot be written the action must not run: `503`.
    pub async fn begin<'a>(
        &self,
        state: &'a AppState,
        action: &'static str,
        target: &str,
        detail: &str,
    ) -> Result<Audited<'a>, Problem> {
        let record = self.record(action, target, detail);
        let id = state
            .admins
            .audit
            .begin(&record, self.now)
            .await
            .map_err(|e| {
                tracing::error!(target: "audit", error = %e, "audit log unavailable; refusing an admin action");
                Problem::service_unavailable(5).with_detail("the audit log is unavailable; retry shortly")
            })?;
        Ok(Audited { state, id, record })
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn h(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for (k, v) in pairs {
            m.append(*k, HeaderValue::from_str(v).unwrap());
        }
        m
    }

    #[test]
    fn only_same_origin_mutations_pass() {
        let d = Authority::parse_canonical("social.example").unwrap();
        assert!(check_origin(&h(&[]), &d).is_ok());
        assert!(check_origin(&h(&[("origin", "https://social.example")]), &d).is_ok());
        assert!(check_origin(&h(&[("sec-fetch-site", "same-origin")]), &d).is_ok());
        for bad in [
            h(&[("origin", "https://evil.example")]),
            h(&[("origin", "http://social.example")]),
            h(&[("origin", "null")]),
            h(&[
                ("origin", "https://social.example"),
                ("origin", "https://evil.example"),
            ]),
            h(&[("sec-fetch-site", "cross-site")]),
            h(&[("sec-fetch-site", "same-site")]),
        ] {
            assert!(check_origin(&bad, &d).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_csrf_header_must_match_the_session_exactly_once() {
        let t = "as_token";
        let good = csrf_token(t);
        assert!(csrf_matches(&h(&[(CSRF_HEADER, &good)]), t));
        assert!(!csrf_matches(&h(&[]), t));
        assert!(!csrf_matches(&h(&[(CSRF_HEADER, "nope")]), t));
        assert!(!csrf_matches(
            &h(&[(CSRF_HEADER, &good), (CSRF_HEADER, &good)]),
            t
        ));
        assert!(!csrf_matches(&h(&[(CSRF_HEADER, &good)]), "as_other"));
    }
}
