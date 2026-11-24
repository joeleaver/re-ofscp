//! Converting between unix seconds and the RFC 3339 strings rhypedb returns
//! for `DateTime` fields and the API puts on the wire.

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// `unix` as RFC 3339 (UTC). Out-of-range values give the epoch.
pub fn rfc3339(unix: i64) -> String {
    OffsetDateTime::from_unix_timestamp(unix)
        .ok()
        .and_then(|t| t.format(&Rfc3339).ok())
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_owned())
}

/// Unix seconds from RFC 3339, if it parses.
pub fn unix(rfc3339: &str) -> Option<i64> {
    OffsetDateTime::parse(rfc3339, &Rfc3339)
        .ok()
        .map(OffsetDateTime::unix_timestamp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        assert_eq!(rfc3339(1_767_268_800), "2026-01-01T12:00:00Z");
        assert_eq!(unix("2026-01-01T12:00:00Z"), Some(1_767_268_800));
        assert_eq!(unix("2026-01-01T12:00:00.250Z"), Some(1_767_268_800));
        assert_eq!(unix("yesterday"), None);
    }
}
