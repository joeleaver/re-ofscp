//! Converting between unix seconds, the RFC 3339 strings rhypedb returns
//! for `DateTime` fields, and the wire's [`Timestamp`] (`ofscp_core::wire`).
//!
//! The server keeps time as unix seconds (`time` crate); the protocol types
//! use `jiff::Timestamp`. This is the one place the two meet.

use ofscp_core::wire::Timestamp;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// `unix` as RFC 3339 (UTC). Out-of-range values give the epoch.
pub fn rfc3339(unix: i64) -> String {
    OffsetDateTime::from_unix_timestamp(unix)
        .ok()
        .and_then(|t| t.format(&Rfc3339).ok())
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_owned())
}

/// `unix` as a wire timestamp. Out-of-range values give the epoch, like
/// [`rfc3339`].
pub fn timestamp(unix: i64) -> Timestamp {
    Timestamp::from_second(unix).unwrap_or(Timestamp::UNIX_EPOCH)
}

/// A wire timestamp from RFC 3339 (as rhypedb returns it), if it parses.
pub fn parse_timestamp(rfc3339: &str) -> Option<Timestamp> {
    rfc3339.parse().ok()
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
        assert_eq!(timestamp(1_767_268_800).to_string(), "2026-01-01T12:00:00Z");
        assert_eq!(timestamp(i64::MAX), Timestamp::UNIX_EPOCH);
        assert_eq!(
            parse_timestamp("2026-01-01T12:00:00Z"),
            Some(timestamp(1_767_268_800))
        );
        assert_eq!(parse_timestamp("yesterday"), None);
    }
}
