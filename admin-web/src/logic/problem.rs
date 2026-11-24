//! Reading the admin API's answers: success bodies and RFC 7807
//! problem+json errors (docs/decisions/0005, spec §2.6).

use serde::Deserialize;
use serde::de::DeserializeOwned;

/// Why an API call failed, ready to show to the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    /// The server answered with an error status.
    Status {
        /// The HTTP status.
        status: u16,
        /// What to tell the user: the problem's `detail`, else its `title`.
        message: String,
    },
    /// The request never got an answer (offline, server down).
    Network(String),
    /// A success answer that isn't the JSON this console expects.
    Unreadable(String),
}

impl ApiError {
    /// Whether the session is gone (signed out, expired or ended
    /// elsewhere): the console goes back to sign-in.
    pub fn is_unauthorized(&self) -> bool {
        matches!(self, Self::Status { status: 401, .. })
    }

    /// The HTTP status, if the server answered.
    pub fn status(&self) -> Option<u16> {
        match self {
            Self::Status { status, .. } => Some(*status),
            Self::Network(_) | Self::Unreadable(_) => None,
        }
    }

    /// The message to show.
    pub fn message(&self) -> String {
        match self {
            Self::Status { message, .. } => message.clone(),
            Self::Network(e) => format!("Couldn't reach the server ({e})."),
            Self::Unreadable(e) => format!("The server's answer couldn't be read ({e})."),
        }
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message())
    }
}

/// The fields of a problem document the console uses.
#[derive(Debug, Deserialize)]
struct ProblemBody {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    detail: Option<String>,
}

/// The error for a non-2xx answer. `retry_after` is the `Retry-After`
/// header (seconds), which 429 and 503 answers carry.
pub fn error_from(status: u16, body: &[u8], retry_after: Option<&str>) -> ApiError {
    let problem = serde_json::from_slice::<ProblemBody>(body).ok();
    let text = problem
        .and_then(|p| p.detail.or(p.title))
        .map(|t| t.trim().to_owned())
        .filter(|t| !t.is_empty())
        .unwrap_or_else(|| fallback(status).to_owned());
    let message = match retry_after.and_then(|r| r.trim().parse::<u64>().ok()) {
        Some(secs) => format!("{} Try again in {}.", sentence(&text), duration(secs)),
        None => sentence(&text),
    };
    ApiError::Status { status, message }
}

/// Decode a success body.
pub fn decode<T: DeserializeOwned>(body: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(body).map_err(|e| ApiError::Unreadable(e.to_string()))
}

fn fallback(status: u16) -> &'static str {
    match status {
        400 => "The request was refused",
        401 => "Sign in to the admin console",
        403 => "You aren't allowed to do that",
        404 => "Not found",
        409 => "That conflicts with the current state",
        429 => "Too many attempts",
        503 => "The server is busy",
        500..=599 => "The server failed",
        _ => "The request failed",
    }
}

/// `text` with an initial capital and a final full stop.
fn sentence(text: &str) -> String {
    let mut chars = text.chars();
    let mut out: String = match chars.next() {
        Some(c) => c.to_uppercase().chain(chars).collect(),
        None => String::new(),
    };
    if !out.ends_with(['.', '!', '?']) {
        out.push('.');
    }
    out
}

/// `secs` as a short human duration.
pub fn duration(secs: u64) -> String {
    match secs {
        0..=1 => "a second".to_owned(),
        2..=89 => format!("{secs} seconds"),
        90..=5399 => format!("{} minutes", secs.div_ceil(60)),
        _ => format!("{} hours", secs.div_ceil(3600)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detail_wins_over_title_and_is_a_sentence() {
        let body = br#"{"type":"https://x/problems/bad_request","title":"Bad Request","status":400,"detail":"since must be before until","errorCode":"bad_request"}"#;
        let e = error_from(400, body, None);
        assert_eq!(e.message(), "Since must be before until.");
        assert_eq!(e.status(), Some(400));
        assert!(!e.is_unauthorized());
    }

    #[test]
    fn title_then_status_fallback() {
        let e = error_from(409, br#"{"title":"Conflict","status":409}"#, None);
        assert_eq!(e.message(), "Conflict.");
        let e = error_from(502, b"<html>bad gateway</html>", None);
        assert_eq!(e.message(), "The server failed.");
        let e = error_from(404, br#"{"detail":"   "}"#, None);
        assert_eq!(e.message(), "Not found.");
    }

    #[test]
    fn unauthorized_is_recognised() {
        assert!(error_from(401, b"{}", None).is_unauthorized());
        assert!(!ApiError::Network("x".into()).is_unauthorized());
    }

    #[test]
    fn retry_after_is_spelled_out() {
        let e = error_from(429, br#"{"title":"Too Many Requests"}"#, Some("120"));
        assert_eq!(e.message(), "Too Many Requests. Try again in 2 minutes.");
        let e = error_from(503, b"", Some(" 5 "));
        assert_eq!(e.message(), "The server is busy. Try again in 5 seconds.");
        let e = error_from(429, b"", Some("soon"));
        assert_eq!(e.message(), "Too many attempts.");
    }

    #[test]
    fn durations() {
        assert_eq!(duration(1), "a second");
        assert_eq!(duration(60), "60 seconds");
        assert_eq!(duration(90), "2 minutes");
        assert_eq!(duration(3600), "60 minutes");
        assert_eq!(duration(7200), "2 hours");
    }

    #[test]
    fn decode_reports_bad_json() {
        let ok: Result<Vec<u8>, _> = decode(b"[1,2]");
        assert_eq!(ok.unwrap(), vec![1, 2]);
        let bad: Result<Vec<u8>, _> = decode(b"nope");
        assert!(matches!(bad, Err(ApiError::Unreadable(_))));
    }
}
