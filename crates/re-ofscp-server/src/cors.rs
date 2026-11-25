//! Cross-origin access for browser clients (§3.4).
//!
//! OFSCP authenticates with request signatures, never with ambient
//! credentials, so a browser client served from one provider must be able
//! to call every other provider directly. Every `/api/…` and
//! `/.well-known/ofscp…` path therefore allows any origin, without
//! credentials.
//!
//! The admin API (`/api/admin/…`) and the admin console (`/admin`) are the
//! exception: they authenticate with a `SameSite=Strict` session cookie
//! plus CSRF protection and stay same-origin (docs/decisions/0005), so they
//! get no CORS headers at all and a preflight to them is not answered. §3.4
//! "Scope" (lost-conn/ofscp#21) puts a provider's own non-standard
//! endpoints outside the CORS requirement, and says endpoints with ambient
//! credentials SHOULD NOT be opened cross-origin.

use axum::extract::Request;
use axum::http::header::{
    ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN,
    ACCESS_CONTROL_EXPOSE_HEADERS, ACCESS_CONTROL_MAX_AGE, ACCESS_CONTROL_REQUEST_METHOD, ORIGIN,
    VARY,
};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// `Access-Control-Allow-Methods` (§3.4).
pub const ALLOW_METHODS: &str = "GET, POST, PUT, PATCH, DELETE, OPTIONS";

/// `Access-Control-Allow-Headers`: the transport headers clients send and
/// every OFSCP signing header, user- and provider-signed (§3.4, §4.4.1, §8.1).
pub const ALLOW_HEADERS: &str = "content-type, accept, authorization, x-ofscp-actor, \
     x-ofscp-provider, x-ofscp-key-id, x-ofscp-timestamp, x-ofscp-nonce, \
     x-ofscp-content-digest, x-ofscp-signature";

/// `Access-Control-Expose-Headers`: the allow list plus `Retry-After` (so
/// clients can honour 429/503 backoff) and `ETag` (§3.4).
pub const EXPOSE_HEADERS: &str = "content-type, accept, authorization, x-ofscp-actor, \
     x-ofscp-provider, x-ofscp-key-id, x-ofscp-timestamp, x-ofscp-nonce, \
     x-ofscp-content-digest, x-ofscp-signature, retry-after, etag";

/// `Access-Control-Max-Age`, in seconds (§3.4 RECOMMENDED).
pub const MAX_AGE_SECS: &str = "600";

/// Whether `path` is one the spec opens to cross-origin callers: every
/// `/api/…` and `/.well-known/ofscp…` path except the admin API.
pub fn applies(path: &str) -> bool {
    if path.starts_with("/.well-known/ofscp") {
        return true;
    }
    match path.strip_prefix("/api/") {
        Some(rest) => {
            let first = rest.split('/').next().unwrap_or_default();
            first != "admin"
        }
        None => false,
    }
}

/// The CORS middleware. Install it outside problem rendering, so error
/// responses carry the headers too, and outside signature verification, so
/// a preflight (which carries no signature) is answered before it.
pub async fn layer(req: Request, next: Next) -> Response {
    if !applies(req.uri().path()) {
        return next.run(req).await;
    }
    if !req.headers().contains_key(ORIGIN) {
        // Still vary on Origin: a shared cache must not hand this
        // header-less response to a browser that sends one.
        let mut resp = next.run(req).await;
        resp.headers_mut()
            .append(VARY, HeaderValue::from_static("Origin"));
        return resp;
    }
    if req.method() == Method::OPTIONS && req.headers().contains_key(ACCESS_CONTROL_REQUEST_METHOD)
    {
        return preflight();
    }
    let mut resp = next.run(req).await;
    add_response_headers(resp.headers_mut());
    resp
}

/// `204` with the allow lists (§3.4). The requested method and headers are
/// not checked here: the browser compares them against the lists.
fn preflight() -> Response {
    let mut resp = StatusCode::NO_CONTENT.into_response();
    let h = resp.headers_mut();
    add_response_headers(h);
    h.insert(
        ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static(ALLOW_METHODS),
    );
    h.insert(
        ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static(ALLOW_HEADERS),
    );
    h.insert(
        ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_static(MAX_AGE_SECS),
    );
    resp
}

/// The headers every response to a request with `Origin` carries. Never
/// `Access-Control-Allow-Credentials` (§3.4 MUST NOT).
fn add_response_headers(h: &mut HeaderMap) {
    h.insert(ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    h.insert(
        ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static(EXPOSE_HEADERS),
    );
    h.append(VARY, HeaderValue::from_static("Origin"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applies_to_ofscp_paths_only() {
        for open in [
            "/api/health",
            "/api/auth/login",
            "/api/administrators",
            "/api/unknown/thing",
            "/.well-known/ofscp-provider",
            "/.well-known/ofscp/users/alice/keys",
        ] {
            assert!(applies(open), "{open}");
        }
        for closed in [
            "/api/admin",
            "/api/admin/",
            "/api/admin/session",
            "/admin",
            "/admin/",
            "/api",
            "/problems/not_found",
            "/.well-known/other",
            "/",
        ] {
            assert!(!applies(closed), "{closed}");
        }
    }

    #[test]
    fn allow_list_has_every_spec_header() {
        for h in [
            "content-type",
            "accept",
            "authorization",
            "x-ofscp-actor",
            "x-ofscp-provider",
            "x-ofscp-key-id",
            "x-ofscp-timestamp",
            "x-ofscp-nonce",
            "x-ofscp-content-digest",
            "x-ofscp-signature",
        ] {
            let listed = |list: &str| list.split(", ").any(|x| x == h);
            assert!(listed(ALLOW_HEADERS), "allow {h}");
            assert!(listed(EXPOSE_HEADERS), "expose {h}");
        }
        assert!(EXPOSE_HEADERS.ends_with(", retry-after, etag"));
    }
}
