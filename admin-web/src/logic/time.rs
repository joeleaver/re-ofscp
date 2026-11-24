//! Times: the audit log's window, entered as UTC `datetime-local` values,
//! and timestamps from the server shown in UTC.

use re_ofscp_types::admin::{DEFAULT_AUDIT_WINDOW_SECS, MAX_AUDIT_WINDOW_SECS};
use time::format_description::FormatItem;
use time::format_description::well_known::Rfc3339;
use time::macros::format_description;
use time::{OffsetDateTime, PrimitiveDateTime};

use super::Invalid;
use super::request::AuditFilter;

/// What an `<input type="datetime-local">` holds, to the minute.
const INPUT_MINUTES: &[FormatItem<'static>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]");
/// The same with seconds, which browsers produce when a step allows them.
const INPUT_SECONDS: &[FormatItem<'static>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]");
/// How the console shows a time.
const DISPLAY: &[FormatItem<'static>] =
    format_description!("[year]-[month]-[day] [hour]:[minute]:[second] UTC");

fn utc(unix: i64) -> Option<OffsetDateTime> {
    OffsetDateTime::from_unix_timestamp(unix).ok()
}

/// `unix` as a `datetime-local` value (UTC, to the minute).
pub fn input_value(unix: i64) -> String {
    utc(unix)
        .and_then(|t| t.format(INPUT_MINUTES).ok())
        .unwrap_or_default()
}

/// The default audit window for the inputs: the last day, ending at the
/// next whole minute so that nothing from the current minute is cut off.
pub fn default_window(now_unix: i64) -> (String, String) {
    let until = (now_unix.div_euclid(60) + 1) * 60;
    (
        input_value(until - DEFAULT_AUDIT_WINDOW_SECS),
        input_value(until),
    )
}

fn parse_input(value: &str, which: &str) -> Result<OffsetDateTime, Invalid> {
    let value = value.trim();
    PrimitiveDateTime::parse(value, INPUT_MINUTES)
        .or_else(|_| PrimitiveDateTime::parse(value, INPUT_SECONDS))
        .map(PrimitiveDateTime::assume_utc)
        .map_err(|_| Invalid::new(format!("Enter the {which} date and time.")))
}

/// The audit filter for the window `[since, until)` given as UTC
/// `datetime-local` values: `since` before `until`, at most 31 days.
pub fn audit_window(
    since: &str,
    until: &str,
    admin: Option<String>,
) -> Result<AuditFilter, Invalid> {
    let since = parse_input(since, "start")?;
    let until = parse_input(until, "end")?;
    if since >= until {
        return Err(Invalid::new("The start must be before the end."));
    }
    if (until - since).whole_seconds() > MAX_AUDIT_WINDOW_SECS {
        return Err(Invalid::new(format!(
            "The window can be at most {} days.",
            MAX_AUDIT_WINDOW_SECS / 86_400
        )));
    }
    let rfc = |t: OffsetDateTime| {
        t.format(&Rfc3339)
            .map_err(|e| Invalid::new(format!("That time can't be used ({e}).")))
    };
    Ok(AuditFilter {
        since: rfc(since)?,
        until: rfc(until)?,
        admin,
    })
}

/// An RFC 3339 time from the server, shown in UTC; anything unreadable is
/// shown as it came.
pub fn display(rfc3339: &str) -> String {
    OffsetDateTime::parse(rfc3339, &Rfc3339)
        .ok()
        .and_then(|t| t.to_offset(time::UtcOffset::UTC).format(DISPLAY).ok())
        .unwrap_or_else(|| rfc3339.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-11-24T15:25:16Z.
    const NOW: i64 = 1_795_533_916;

    #[test]
    fn default_window_is_the_last_day_to_the_next_minute() {
        let (since, until) = default_window(NOW);
        assert_eq!(until, "2026-11-24T15:26");
        assert_eq!(since, "2026-11-23T15:26");
        let f = audit_window(&since, &until, None).unwrap();
        assert_eq!(f.since, "2026-11-23T15:26:00Z");
        assert_eq!(f.until, "2026-11-24T15:26:00Z");
    }

    #[test]
    fn windows_are_ordered_and_bounded() {
        assert!(audit_window("2026-11-24T10:00", "2026-11-24T10:00", None).is_err());
        assert!(audit_window("2026-11-24T11:00", "2026-11-24T10:00", None).is_err());
        assert!(audit_window("2026-10-24T10:00", "2026-11-24T10:00", None).is_ok());
        assert!(audit_window("2026-10-24T09:59", "2026-11-24T10:00", None).is_err());
        assert!(audit_window("", "2026-11-24T10:00", None).is_err());
        assert!(audit_window("yesterday", "2026-11-24T10:00", None).is_err());
        let f = audit_window(
            "2026-11-24T10:00:30",
            "2026-11-24T11:00",
            Some("ops".into()),
        )
        .unwrap();
        assert_eq!(f.since, "2026-11-24T10:00:30Z");
        assert_eq!(f.admin.as_deref(), Some("ops"));
    }

    #[test]
    fn display_is_utc() {
        assert_eq!(display("2026-11-24T15:25:16Z"), "2026-11-24 15:25:16 UTC");
        assert_eq!(
            display("2026-11-24T17:25:16+02:00"),
            "2026-11-24 15:25:16 UTC"
        );
        assert_eq!(display("not a time"), "not a time");
    }
}
