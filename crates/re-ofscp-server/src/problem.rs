//! RFC 7807 `application/problem+json` errors (spec §2.6, §7.3).
//!
//! `type` URIs are minted under the same `https://ofscp.org/problems/` base
//! the reference implementation uses, so clients that key on `type` see the
//! same values from either implementation. Every problem also carries a
//! stable `errorCode` (§2.6 allows it).

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// Base for problem `type` URIs.
pub const PROBLEM_TYPE_BASE: &str = "https://ofscp.org/problems/";

/// Content type of every error response.
pub const PROBLEM_CONTENT_TYPE: &str = "application/problem+json";

/// A problem response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    status: StatusCode,
    slug: &'static str,
    title: &'static str,
    detail: Option<String>,
    retry_after: Option<u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Body<'a> {
    #[serde(rename = "type")]
    kind: String,
    title: &'a str,
    status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<&'a str>,
    error_code: &'a str,
}

impl Problem {
    const fn new(status: StatusCode, slug: &'static str, title: &'static str) -> Self {
        Self {
            status,
            slug,
            title,
            detail: None,
            retry_after: None,
        }
    }

    /// 400.
    pub const fn bad_request() -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_request", "Bad Request")
    }
    /// 401.
    pub const fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized", "Unauthorized")
    }
    /// 403.
    pub const fn forbidden() -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", "Forbidden")
    }
    /// 404.
    pub const fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", "Not Found")
    }
    /// 413.
    pub const fn payload_too_large() -> Self {
        Self::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "Payload Too Large",
        )
    }
    /// 500. The detail is never shown to the client; log the cause instead.
    pub const fn internal() -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Internal Server Error",
        )
    }
    /// 503 with `Retry-After` in seconds.
    pub const fn service_unavailable(retry_after_secs: u64) -> Self {
        let mut p = Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "service_unavailable",
            "Service Unavailable",
        );
        p.retry_after = Some(retry_after_secs);
        p
    }

    /// Attach a human-readable explanation.
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// The HTTP status.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// The `errorCode` / slug.
    pub fn code(&self) -> &'static str {
        self.slug
    }

    /// The `detail`, if any.
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }
}

impl IntoResponse for Problem {
    fn into_response(self) -> Response {
        let body = Body {
            kind: format!("{PROBLEM_TYPE_BASE}{}", self.slug.replace('_', "-")),
            title: self.title,
            status: self.status.as_u16(),
            detail: self.detail.as_deref(),
            error_code: self.slug,
        };
        let bytes = serde_json::to_vec(&body).unwrap_or_default();
        let mut res = (self.status, bytes).into_response();
        let headers = res.headers_mut();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(PROBLEM_CONTENT_TYPE),
        );
        if let Some(secs) = self.retry_after {
            headers.insert(header::RETRY_AFTER, HeaderValue::from(secs));
        }
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn renders_problem_json() {
        let res = Problem::service_unavailable(30)
            .with_detail("replay store full")
            .into_response();
        assert_eq!(res.status(), 503);
        assert_eq!(res.headers()[header::CONTENT_TYPE], PROBLEM_CONTENT_TYPE);
        assert_eq!(res.headers()[header::RETRY_AFTER], "30");
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "type": "https://ofscp.org/problems/service-unavailable",
                "title": "Service Unavailable",
                "status": 503,
                "detail": "replay store full",
                "errorCode": "service_unavailable",
            })
        );
    }
}
