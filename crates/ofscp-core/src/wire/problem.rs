//! Errors: RFC 7807 problem details and the `errorCode` registry (spec
//! §2.6, §7.3, lost-conn/ofscp#17).

use serde::{Deserialize, Serialize};

use super::open_enum;

open_enum! {
    /// The interoperable key of an error (§7.3). Decide how to handle an
    /// error from this and the HTTP status; when it is absent or unknown,
    /// fall back to the status alone (§2.6). A provider may add extension
    /// codes, which arrive as `Other`.
    pub enum ErrorCode {
        /// 400: invalid payload, parameters, or schema mismatch.
        BadRequest = "bad_request",
        /// 401: invalid or missing signature or credentials.
        Unauthorized = "unauthorized",
        /// 403: not permitted, or refused by federation policy.
        Forbidden = "forbidden",
        /// 403: the provider takes no self-registration.
        RegistrationClosed = "registration_closed",
        /// 403: registration needs a usable account invite.
        InviteRequired = "invite_required",
        /// 404: no such resource, or not visible to the caller.
        NotFound = "not_found",
        /// 409: conflicts with the current state.
        Conflict = "conflict",
        /// 409: too many live subscriptions on one socket.
        SubscriptionLimit = "subscription_limit",
        /// 413: over the provider's size limit.
        PayloadTooLarge = "payload_too_large",
        /// 429: rate limited; honour `Retry-After`.
        TooManyRequests = "too_many_requests",
        /// 500: an unexpected provider error.
        InternalError = "internal_error",
        /// 503: temporarily unavailable; honour `Retry-After`.
        ServiceUnavailable = "service_unavailable",
    }
}

impl ErrorCode {
    /// Every code of the §7.3 registry.
    pub const REGISTRY: [ErrorCode; 12] = [
        Self::BadRequest,
        Self::Unauthorized,
        Self::Forbidden,
        Self::RegistrationClosed,
        Self::InviteRequired,
        Self::NotFound,
        Self::Conflict,
        Self::SubscriptionLimit,
        Self::PayloadTooLarge,
        Self::TooManyRequests,
        Self::InternalError,
        Self::ServiceUnavailable,
    ];

    /// The HTTP status the registry fixes for this code (§7.3), or `None`
    /// for an extension code, whose status only its provider knows.
    pub fn status(&self) -> Option<u16> {
        Some(match Self::from(self.as_str()) {
            Self::BadRequest => 400,
            Self::Unauthorized => 401,
            Self::Forbidden | Self::RegistrationClosed | Self::InviteRequired => 403,
            Self::NotFound => 404,
            Self::Conflict | Self::SubscriptionLimit => 409,
            Self::PayloadTooLarge => 413,
            Self::TooManyRequests => 429,
            Self::InternalError => 500,
            Self::ServiceUnavailable => 503,
            Self::Other(_) => return None,
        })
    }
}

/// RFC 7807's default `type` (§4.2 there): no further semantics.
pub const ABOUT_BLANK: &str = "about:blank";

fn about_blank() -> String {
    ABOUT_BLANK.to_owned()
}

/// An `application/problem+json` error body (§2.6).
///
/// Only `status` is required to read one: a body from a proxy or an older
/// provider may carry nothing else, and RFC 7807 makes `type` default to
/// `about:blank` and `title` optional. Do not depend on `type`: each
/// provider mints its own (`https://{authority}/problems/{errorCode}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProblemDetails {
    /// The provider's URI for the problem; `about:blank` when absent.
    #[serde(rename = "type", default = "about_blank")]
    pub kind: String,
    /// A short human-readable summary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// The HTTP status.
    pub status: u16,
    /// The interoperable code. Every OFSCP problem has one (§2.6), but a
    /// proxy's or an older provider's answer may lack it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<ErrorCode>,
    /// What went wrong, for people.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// The request path it is about.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn a_bare_status_decodes() {
        let p: ProblemDetails = serde_json::from_value(json!({"status": 503})).unwrap();
        assert_eq!(p.kind, ABOUT_BLANK);
        assert_eq!(p.title, None);
        assert_eq!(p.error_code, None);
        assert_eq!(p.status, 503);
    }

    #[test]
    fn extension_codes_are_kept() {
        let p: ProblemDetails =
            serde_json::from_value(json!({"status": 410, "errorCode": "gone"})).unwrap();
        assert_eq!(p.error_code, Some(ErrorCode::Other("gone".into())));
        assert_eq!(p.error_code.and_then(|c| c.status()), None);
    }

    #[test]
    fn every_registry_code_has_its_status() {
        let statuses: Vec<_> = ErrorCode::REGISTRY.iter().map(ErrorCode::status).collect();
        assert!(statuses.iter().all(Option::is_some));
        assert_eq!(ErrorCode::InviteRequired.status(), Some(403));
        assert_eq!(ErrorCode::SubscriptionLimit.status(), Some(409));
        assert_eq!(ErrorCode::Other("not_found".into()).status(), Some(404));
    }
}
