//! Building rhypedb query-language text safely.
//!
//! rhypedb has no bind parameters: values travel inside the query text. To
//! make injection impossible by construction, a [`Ql`] can only be extended
//! with **static** text (`&'static str`, i.e. written in this source code)
//! or with **typed literals** that this module renders and escapes. A value
//! that came from a request can therefore never become query syntax.
//!
//! String literals use the two escapes rhypedb's parser defines (`\"` and
//! `\\`); every other character, including newlines and control characters,
//! is taken verbatim inside the quotes. `tests/db.rs` round-trips hostile
//! strings through a real server to hold this to account.

use std::fmt::Write as _;

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// A query under construction. See the module docs for the safety rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ql(String);

impl Ql {
    /// Start a query with static text, e.g. `Ql::new("ReplayNonce")`.
    pub fn new(text: &'static str) -> Self {
        Self(text.to_owned())
    }

    /// Append static text (syntax, type and field names).
    #[must_use]
    pub fn raw(mut self, text: &'static str) -> Self {
        self.0.push_str(text);
        self
    }

    /// Append a quoted, escaped string literal.
    #[must_use]
    pub fn str(mut self, value: &str) -> Self {
        self.0.reserve(value.len() + 2);
        self.0.push('"');
        for c in value.chars() {
            match c {
                '"' => self.0.push_str("\\\""),
                '\\' => self.0.push_str("\\\\"),
                c => self.0.push(c),
            }
        }
        self.0.push('"');
        self
    }

    /// Append an integer literal.
    #[must_use]
    pub fn int(mut self, value: i64) -> Self {
        let _ = write!(self.0, "{value}");
        self
    }

    /// Append an unsigned integer literal (object ids, limits).
    #[must_use]
    pub fn uint(mut self, value: u64) -> Self {
        let _ = write!(self.0, "{value}");
        self
    }

    /// Append a boolean literal.
    #[must_use]
    pub fn bool(mut self, value: bool) -> Self {
        self.0.push_str(if value { "true" } else { "false" });
        self
    }

    /// Append a `DateTime` literal (an RFC 3339 string, UTC, second precision).
    #[must_use]
    pub fn datetime(self, value: OffsetDateTime) -> Self {
        let utc = value.to_offset(time::UtcOffset::UTC);
        // RFC 3339 formatting fails only for years outside 0..=9999. Fall
        // back to the epoch-milliseconds integer form, which rhypedb also
        // accepts for DateTime fields, rather than panicking.
        match utc.replace_nanosecond(0).map(|t| t.format(&Rfc3339)) {
            Ok(Ok(text)) => self.str(&text),
            _ => self.int(utc.unix_timestamp().saturating_mul(1000)),
        }
    }

    /// Append a `DateTime` literal from unix seconds.
    #[must_use]
    pub fn unix_seconds(self, secs: i64) -> Self {
        match OffsetDateTime::from_unix_timestamp(secs) {
            Ok(t) => self.datetime(t),
            Err(_) => self.int(secs.saturating_mul(1000)),
        }
    }

    /// The finished query text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_are_escaped() {
        let q = Ql::new("T.filter(.k == ")
            .str(r#"a" || true || "\"#)
            .raw(")");
        assert_eq!(q.as_str(), r#"T.filter(.k == "a\" || true || \"\\")"#);
    }

    #[test]
    fn literals() {
        let q = Ql::new("x(")
            .int(-5)
            .raw(", ")
            .uint(7)
            .raw(", ")
            .bool(true)
            .raw(", ")
            .unix_seconds(1_767_268_800)
            .raw(")");
        assert_eq!(q.as_str(), r#"x(-5, 7, true, "2026-01-01T12:00:00Z")"#);
    }

    #[test]
    fn datetimes_are_utc_seconds() {
        let t = time::macros::datetime!(2026-01-01 14:00:00.75 +02:00);
        assert_eq!(
            Ql::new("").datetime(t).as_str(),
            r#""2026-01-01T12:00:00Z""#
        );
    }
}
