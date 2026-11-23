//! RFC 7807 `application/problem+json` errors (spec §2.6, §7.3).
//!
//! * Every problem carries an `errorCode` from the registry in §7.3. That is
//!   the cross-provider identifier clients branch on (with `status`).
//! * `type` is `https://{our canonical authority}/problems/{errorCode}`
//!   (§2.6), and [`describe`] serves a human-readable page at that URL.
//!
//! Handlers return [`Problem`] values. Because `type` depends on the
//! configured authority, a `Problem` turns into a response in two steps: its
//! `IntoResponse` sets the status and headers and stashes itself in the
//! response extensions, and the [`render`] layer, installed once on the
//! router, writes the JSON body. A response that bypassed the layer would
//! have an empty body, which the router tests guard against.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use re_ofscp_types::Authority;
use serde::Serialize;

/// Content type of every error response.
pub const PROBLEM_CONTENT_TYPE: &str = "application/problem+json";

/// One registered error code (§7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorCode {
    /// The `errorCode` value.
    pub code: &'static str,
    /// The HTTP status it pairs with.
    pub status: u16,
    /// The `title`.
    pub title: &'static str,
    /// Served at the `type` URL.
    pub description: &'static str,
}

// The §7.3 registry, one constant per code.
/// `bad_request`.
pub const BAD_REQUEST: ErrorCode = ErrorCode {
    code: "bad_request",
    status: 400,
    title: "Bad Request",
    description: "The request was malformed, failed schema validation, or its body did not match X-OFSCP-Content-Digest.",
};
/// `unauthorized`.
pub const UNAUTHORIZED: ErrorCode = ErrorCode {
    code: "unauthorized",
    status: 401,
    title: "Unauthorized",
    description: "The request was not signed, or its signature, key, timestamp or nonce did not verify.",
};
/// `forbidden`.
pub const FORBIDDEN: ErrorCode = ErrorCode {
    code: "forbidden",
    status: 403,
    title: "Forbidden",
    description: "The signer is authenticated but not allowed to do this.",
};
/// `not_found`.
pub const NOT_FOUND: ErrorCode = ErrorCode {
    code: "not_found",
    status: 404,
    title: "Not Found",
    description: "No such resource, or the signer may not know that it exists.",
};
/// `conflict`.
pub const CONFLICT: ErrorCode = ErrorCode {
    code: "conflict",
    status: 409,
    title: "Conflict",
    description: "The request conflicts with current state, for example a duplicate clientMessageId.",
};
/// `subscription_limit`.
pub const SUBSCRIPTION_LIMIT: ErrorCode = ErrorCode {
    code: "subscription_limit",
    status: 409,
    title: "Subscription Limit",
    description: "The connection already holds the maximum number of subscriptions; unsubscribe first. Waiting does not help.",
};
/// `payload_too_large`.
pub const PAYLOAD_TOO_LARGE: ErrorCode = ErrorCode {
    code: "payload_too_large",
    status: 413,
    title: "Payload Too Large",
    description: "The request body exceeds this provider's limit.",
};
/// `too_many_requests`.
pub const TOO_MANY_REQUESTS: ErrorCode = ErrorCode {
    code: "too_many_requests",
    status: 429,
    title: "Too Many Requests",
    description: "Rate limited. Wait for Retry-After seconds; signed requests must be re-signed with a fresh timestamp and nonce.",
};
/// `internal_error`.
pub const INTERNAL_ERROR: ErrorCode = ErrorCode {
    code: "internal_error",
    status: 500,
    title: "Internal Server Error",
    description: "The provider failed unexpectedly.",
};
/// `service_unavailable`.
pub const SERVICE_UNAVAILABLE: ErrorCode = ErrorCode {
    code: "service_unavailable",
    status: 503,
    title: "Service Unavailable",
    description: "Temporarily unavailable (for example warming up after a restart). Wait for Retry-After seconds, then re-sign with a fresh timestamp and nonce and retry.",
};

/// Extension code (§7.3 allows extensions paired with their status): the
/// resource exists but not with this method.
pub const METHOD_NOT_ALLOWED: ErrorCode = ErrorCode {
    code: "method_not_allowed",
    status: 405,
    title: "Method Not Allowed",
    description: "The resource exists but does not support this HTTP method.",
};

/// Extension code: the request (typically its body) did not arrive in time.
pub const REQUEST_TIMEOUT: ErrorCode = ErrorCode {
    code: "request_timeout",
    status: 408,
    title: "Request Timeout",
    description: "The request body did not arrive in time. Re-sign with a fresh timestamp and nonce and retry.",
};

/// Extension code: the body's media type is not accepted here.
pub const UNSUPPORTED_MEDIA_TYPE: ErrorCode = ErrorCode {
    code: "unsupported_media_type",
    status: 415,
    title: "Unsupported Media Type",
    description: "The request body's Content-Type is not accepted by this endpoint (usually application/json is required).",
};

/// Codes this provider uses beyond the registry.
pub const EXTENSIONS: &[ErrorCode] = &[METHOD_NOT_ALLOWED, REQUEST_TIMEOUT, UNSUPPORTED_MEDIA_TYPE];

/// Every registered code (§7.3).
pub const REGISTRY: &[ErrorCode] = &[
    BAD_REQUEST,
    UNAUTHORIZED,
    FORBIDDEN,
    NOT_FOUND,
    CONFLICT,
    SUBSCRIPTION_LIMIT,
    PAYLOAD_TOO_LARGE,
    TOO_MANY_REQUESTS,
    INTERNAL_ERROR,
    SERVICE_UNAVAILABLE,
];

/// Look up a registered or extension code.
pub fn lookup(code: &str) -> Option<&'static ErrorCode> {
    REGISTRY.iter().chain(EXTENSIONS).find(|c| c.code == code)
}

/// A problem response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    code: &'static ErrorCode,
    detail: Option<String>,
    retry_after: Option<u64>,
}

impl Problem {
    const fn new(code: &'static ErrorCode) -> Self {
        Self {
            code,
            detail: None,
            retry_after: None,
        }
    }

    /// 400 `bad_request`.
    pub fn bad_request() -> Self {
        Self::new(&BAD_REQUEST)
    }
    /// 401 `unauthorized`.
    pub fn unauthorized() -> Self {
        Self::new(&UNAUTHORIZED)
    }
    /// 403 `forbidden`.
    pub fn forbidden() -> Self {
        Self::new(&FORBIDDEN)
    }
    /// 404 `not_found`.
    pub fn not_found() -> Self {
        Self::new(&NOT_FOUND)
    }
    /// 405 `method_not_allowed` (extension code).
    pub fn method_not_allowed() -> Self {
        Self::new(&METHOD_NOT_ALLOWED)
    }
    /// 408 `request_timeout` (extension code).
    pub fn request_timeout() -> Self {
        Self::new(&REQUEST_TIMEOUT)
    }
    /// 415 `unsupported_media_type` (extension code).
    pub fn unsupported_media_type() -> Self {
        Self::new(&UNSUPPORTED_MEDIA_TYPE)
    }
    /// 409 `conflict`.
    pub fn conflict() -> Self {
        Self::new(&CONFLICT)
    }
    /// 413 `payload_too_large`.
    pub fn payload_too_large() -> Self {
        Self::new(&PAYLOAD_TOO_LARGE)
    }
    /// 429 `too_many_requests` with `Retry-After`.
    pub fn too_many_requests(retry_after_secs: u64) -> Self {
        Self::new(&TOO_MANY_REQUESTS).retry_after(retry_after_secs)
    }
    /// 500 `internal_error`. Log the cause; never put it in the detail.
    pub fn internal() -> Self {
        Self::new(&INTERNAL_ERROR)
    }
    /// 503 `service_unavailable` with `Retry-After`.
    pub fn service_unavailable(retry_after_secs: u64) -> Self {
        Self::new(&SERVICE_UNAVAILABLE).retry_after(retry_after_secs)
    }

    fn retry_after(mut self, secs: u64) -> Self {
        self.retry_after = Some(secs);
        self
    }

    /// Attach a human-readable explanation.
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// The HTTP status.
    pub fn status(&self) -> StatusCode {
        StatusCode::from_u16(self.code.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
    }

    /// The `errorCode`.
    pub fn code(&self) -> &'static str {
        self.code.code
    }

    /// The `detail`, if any.
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }
}

impl IntoResponse for Problem {
    fn into_response(self) -> Response {
        let mut res = self.status().into_response();
        let headers = res.headers_mut();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(PROBLEM_CONTENT_TYPE),
        );
        if let Some(secs) = self.retry_after {
            headers.insert(header::RETRY_AFTER, HeaderValue::from(secs));
        }
        res.extensions_mut().insert(self);
        res
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProblemJson<'a> {
    #[serde(rename = "type")]
    kind: String,
    title: &'a str,
    status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<&'a str>,
    error_code: &'a str,
}

/// Where `type` URIs point: `https://{authority}/problems/`.
#[derive(Debug, Clone)]
pub struct ProblemBase(Arc<str>);

impl ProblemBase {
    /// The base for this provider.
    pub fn new(authority: &Authority) -> Self {
        Self(Arc::from(format!("https://{authority}/problems/")))
    }

    /// The `type` URI for `code`.
    pub fn type_uri(&self, code: &str) -> String {
        format!("{}{code}", self.0)
    }
}

/// Response layer: writes the body of every [`Problem`] response, and turns
/// any *other* error response (axum's own extractor rejections, for example
/// a malformed path, JSON body or query string) into a problem too, so every
/// error leaves as `application/problem+json` (§2.6).
/// Install with `axum::middleware::map_response_with_state`.
pub async fn render(State(base): State<ProblemBase>, mut res: Response) -> Response {
    if let Some(problem) = res.extensions_mut().remove::<Problem>() {
        return write_body(&base, res, &problem);
    }
    let status = res.status();
    let already_problem = res
        .headers()
        .get(header::CONTENT_TYPE)
        .is_some_and(|v| v.as_bytes().starts_with(PROBLEM_CONTENT_TYPE.as_bytes()));
    if !(status.is_client_error() || status.is_server_error()) || already_problem {
        return res;
    }
    let (parts, body) = res.into_parts();
    let problem = from_status(status);
    let problem = if status.is_client_error() {
        // Rejection bodies are short plain-text explanations; keep a bounded
        // prefix as the detail. 5xx bodies are never echoed.
        let text = axum::body::to_bytes(body, 4096).await.unwrap_or_default();
        let text = String::from_utf8_lossy(&text);
        let text = text.trim();
        if text.is_empty() {
            problem
        } else {
            problem.with_detail(text.chars().take(300).collect::<String>())
        }
    } else {
        problem
    };
    let mut fresh = problem.clone().into_response();
    // Keep headers that still mean something (e.g. `Allow` on a 405).
    for name in [header::ALLOW, header::RETRY_AFTER] {
        if let Some(v) = parts.headers.get(&name) {
            fresh.headers_mut().insert(name, v.clone());
        }
    }
    fresh.extensions_mut().remove::<Problem>();
    write_body(&base, fresh, &problem)
}

/// The problem for a bare error status.
fn from_status(status: StatusCode) -> Problem {
    match status.as_u16() {
        401 => Problem::unauthorized(),
        403 => Problem::forbidden(),
        404 => Problem::not_found(),
        405 => Problem::method_not_allowed(),
        408 => Problem::request_timeout(),
        409 => Problem::conflict(),
        413 => Problem::payload_too_large(),
        415 => Problem::unsupported_media_type(),
        // Rate limits and unavailability without a known wait: a short one.
        429 => Problem::too_many_requests(1),
        503 => Problem::service_unavailable(1),
        // 400, 422 (axum's JSON data errors) and any other 4xx.
        400..=499 => Problem::bad_request(),
        _ => Problem::internal(),
    }
}

fn write_body(base: &ProblemBase, mut res: Response, problem: &Problem) -> Response {
    let body = ProblemJson {
        kind: base.type_uri(problem.code()),
        title: problem.code.title,
        status: problem.code.status,
        detail: problem.detail(),
        error_code: problem.code(),
    };
    let bytes = serde_json::to_vec(&body).unwrap_or_default();
    res.headers_mut().remove(header::CONTENT_LENGTH);
    *res.body_mut() = Body::from(bytes);
    res
}

/// `GET /problems/{errorCode}`: a plain-text description of a registered
/// code (§2.6 SHOULD), `404` otherwise.
pub async fn describe(Path(code): Path<String>) -> Response {
    match lookup(&code) {
        Some(c) => (
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            format!(
                "{} ({} {})\n\n{}\n",
                c.code, c.status, c.title, c.description
            ),
        )
            .into_response(),
        None => Problem::not_found()
            .with_detail("no such error code")
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_constructor_is_registered() {
        for p in [
            Problem::bad_request(),
            Problem::unauthorized(),
            Problem::forbidden(),
            Problem::not_found(),
            Problem::method_not_allowed(),
            Problem::request_timeout(),
            Problem::unsupported_media_type(),
            Problem::conflict(),
            Problem::payload_too_large(),
            Problem::too_many_requests(1),
            Problem::internal(),
            Problem::service_unavailable(1),
        ] {
            let c = lookup(p.code()).unwrap();
            assert_eq!(p.status().as_u16(), c.status);
        }
        assert_eq!(Problem::internal().code(), "internal_error");
    }

    #[test]
    fn registry_codes_are_snake_case_and_unique() {
        let all: Vec<_> = REGISTRY.iter().chain(EXTENSIONS).collect();
        for (i, c) in all.iter().enumerate() {
            assert!(
                c.code
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            );
            assert!(all[i + 1..].iter().all(|o| o.code != c.code));
        }
    }

    #[test]
    fn type_uri_uses_our_authority_and_the_code_verbatim() {
        let base = ProblemBase::new(&Authority::parse_canonical("social.example").unwrap());
        assert_eq!(
            base.type_uri("service_unavailable"),
            "https://social.example/problems/service_unavailable"
        );
    }
}
