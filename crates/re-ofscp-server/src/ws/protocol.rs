//! The server half of the WebSocket wire format. The format itself (the
//! envelope, the close codes, the §7.3 `error` data and the message data)
//! is pure protocol and lives in [`ofscp_core::ws`], shared with clients;
//! this module adds what needs the server: event ids, the clock, and how a
//! connection is closed (docs/decisions/0010-websocket.md).

use std::sync::atomic::{AtomicU64, Ordering};

use ofscp_core::ws::Event;
pub use ofscp_core::ws::{
    ACCESS_REVOKED, Command, MAX_ID_LEN, STANDARD_COMMANDS, WsError, close, parse_command,
};
use serde_json::Value;

use crate::timefmt::rfc3339;

/// Why a connection is being closed: its code, a short reason (at most
/// 123 bytes, the close-frame limit; ours are fixed text), and whether
/// what is already queued for the client is sent first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Close {
    /// The close code.
    pub code: u16,
    /// The close reason.
    pub reason: &'static str,
    /// Send what was queued before the close (an `error` explaining it).
    pub flush: bool,
}

impl Close {
    /// A close with `code` and `reason`, after what is queued.
    pub const fn new(code: u16, reason: &'static str) -> Self {
        Self {
            code,
            reason,
            flush: true,
        }
    }

    /// A close with `code` and `reason` that drops what is queued: the
    /// client is not keeping up with it.
    pub const fn abandon(code: u16, reason: &'static str) -> Self {
        Self {
            code,
            reason,
            flush: false,
        }
    }
}

static NEXT_EVENT: AtomicU64 = AtomicU64::new(1);

/// A fresh server event id, unique in this process (so within every
/// connection, §7.1).
pub fn event_id() -> String {
    format!("evt_{}", NEXT_EVENT.fetch_add(1, Ordering::Relaxed))
}

/// A server event, serialized, with a fresh id and `ts` = `now`.
pub fn event(kind: &str, correlation: Option<&str>, data: Value, now: i64) -> String {
    Event {
        id: event_id(),
        kind: kind.to_owned(),
        ts: rfc3339(now),
        correlation_id: correlation.map(str::to_owned),
        data,
    }
    .to_json()
}

/// The serialized `error` event of a [`WsError`].
pub trait ErrorEvent {
    /// The `error` event, answering `correlation` if given.
    fn to_event(&self, correlation: Option<&str>, now: i64) -> String;
}

impl ErrorEvent for WsError {
    fn to_event(&self, correlation: Option<&str>, now: i64) -> String {
        event("error", correlation, self.to_value(), now)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn events_carry_the_envelope_and_errors_their_status() {
        let text = WsError::service_unavailable("later", 7).to_event(Some("cli_1"), 0);
        let v: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["type"], "error");
        assert_eq!(v["correlationId"], "cli_1");
        assert_eq!(v["ts"], "1970-01-01T00:00:00Z");
        assert_eq!(v["data"]["status"], 503);
        assert_eq!(v["data"]["details"]["retryAfter"], 7);
        assert!(v["id"].as_str().unwrap().starts_with("evt_"));
        let other: Value = serde_json::from_str(&event("pong", None, json!({}), 0)).unwrap();
        assert_ne!(other["id"], v["id"]);
        assert!(other.get("correlationId").is_none());
    }
}
