//! The WebSocket wire format (spec §7.1 "WebSocket message envelope",
//! §7.3 "WebSocket error messages", the close-code table), and the close
//! codes this provider uses where the spec has none
//! (docs/decisions/0008-websocket.md).

use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Map, Value, json};

use crate::timefmt::rfc3339;

/// Close codes.
pub mod close {
    /// §7.1: authentication failed, refused by federation policy, or the
    /// connection's key can no longer be confirmed. The key was not
    /// revoked; the client may reconnect and re-authenticate.
    pub const AUTH_FAILED: u16 = 4001;
    /// §7.1: the connection's credentials were revoked (its device key, or
    /// the account). The client must not reconnect with the same key.
    pub const REVOKED: u16 = 4003;
    /// RFC 6455: normal closure (here: the heartbeat timed out).
    pub const NORMAL: u16 = 1000;
    /// RFC 6455: going away (the provider is shutting down).
    pub const GOING_AWAY: u16 = 1001;
    /// RFC 6455: protocol error (the transport rejected a frame).
    pub const PROTOCOL: u16 = 1002;
    /// RFC 6455: unsupported data (a binary message).
    pub const UNSUPPORTED: u16 = 1003;
    /// RFC 6455: policy violation (the command rate was abused).
    pub const POLICY: u16 = 1008;
    /// RFC 6455: a message over the size limit.
    pub const TOO_BIG: u16 = 1009;
    /// RFC 6455: an unexpected provider error.
    pub const INTERNAL: u16 = 1011;
    /// RFC 6455: try again later (a connection cap, or the client did not
    /// keep up with its events).
    pub const TRY_AGAIN: u16 = 1013;
}

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

/// The client commands §7.1 defines. A command of one of these types that
/// this provider does not implement yet gets an `error`; any other unknown
/// type is ignored (§2.3).
pub const STANDARD_COMMANDS: &[&str] = &[
    "authenticate",
    "subscribe",
    "unsubscribe",
    "message.create",
    "message.update",
    "message.delete",
    "reaction.add",
    "reaction.remove",
    "typing.start",
    "typing.stop",
    "presence.subscribe",
    "presence.unsubscribe",
    "presence.set",
    "ping",
    "pong",
];

/// Longest client `id` echoed back as a `correlationId`.
pub const MAX_ID_LEN: usize = 256;

/// A client command, as received.
#[derive(Debug, Clone, PartialEq)]
pub struct Inbound {
    /// `id`: the client's id for this command.
    pub id: String,
    /// `type`.
    pub kind: String,
    /// `data` (`null` when absent). Unknown fields are ignored (§2.3).
    pub data: Value,
}

/// Why a frame is not a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Malformed {
    /// The frame's `id`, if it had a usable one (for `correlationId`).
    pub id: Option<String>,
    /// What is wrong.
    pub why: &'static str,
}

/// Parse a text frame as a command envelope. `ts` is not required on
/// client commands (the spec's own examples omit it) and is ignored; `id`
/// and `type` are required (docs/decisions/0008-websocket.md).
pub fn parse(text: &str) -> Result<Inbound, Malformed> {
    let malformed = |id: Option<String>, why| Malformed { id, why };
    let Ok(Value::Object(mut obj)) = serde_json::from_str::<Value>(text) else {
        return Err(malformed(None, "frame is not a JSON object"));
    };
    let id = match obj.remove("id") {
        Some(Value::String(id)) if !id.is_empty() && id.len() <= MAX_ID_LEN => Some(id),
        _ => None,
    };
    let kind = match obj.remove("type") {
        Some(Value::String(kind)) if !kind.is_empty() => kind,
        _ => return Err(malformed(id, "frame has no type")),
    };
    let Some(id) = id else {
        return Err(malformed(None, "frame has no usable id"));
    };
    Ok(Inbound {
        id,
        kind,
        data: obj.remove("data").unwrap_or(Value::Null),
    })
}

static NEXT_EVENT: AtomicU64 = AtomicU64::new(1);

/// A fresh server event id, unique in this process (so within every
/// connection, §7.1).
pub fn event_id() -> String {
    format!("evt_{}", NEXT_EVENT.fetch_add(1, Ordering::Relaxed))
}

/// A server event, serialized: `{id, type, ts, correlationId?, data}`.
pub fn event(kind: &str, correlation: Option<&str>, data: Value, now: i64) -> String {
    let mut obj = Map::new();
    obj.insert("id".into(), Value::String(event_id()));
    obj.insert("type".into(), Value::String(kind.to_owned()));
    obj.insert("ts".into(), Value::String(rfc3339(now)));
    if let Some(c) = correlation {
        obj.insert("correlationId".into(), Value::String(c.to_owned()));
    }
    obj.insert("data".into(), data);
    Value::Object(obj).to_string()
}

/// A WebSocket `error` (§7.3): an `errorCode` with its HTTP status.
#[derive(Debug, Clone, PartialEq)]
pub struct WsError {
    /// The `errorCode`.
    pub code: &'static str,
    /// Its status.
    pub status: u16,
    /// Human-readable text.
    pub message: String,
    /// Machine-readable details, if any.
    pub details: Option<Value>,
}

impl WsError {
    fn new(code: &'static str, status: u16, message: impl Into<String>) -> Self {
        Self {
            code,
            status,
            message: message.into(),
            details: None,
        }
    }

    /// `bad_request` (400).
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new("bad_request", 400, message)
    }

    /// `unauthorized` (401).
    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new("unauthorized", 401, message)
    }

    /// `forbidden` (403).
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new("forbidden", 403, message)
    }

    /// `not_found` (404).
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new("not_found", 404, message)
    }

    /// `subscription_limit` (409).
    pub fn subscription_limit(message: impl Into<String>) -> Self {
        Self::new("subscription_limit", 409, message)
    }

    /// `too_many_requests` (429), retry after `retry_after` seconds.
    pub fn too_many_requests(message: impl Into<String>, retry_after: u64) -> Self {
        Self::new("too_many_requests", 429, message).retry_after(retry_after)
    }

    /// `internal_error` (500).
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new("internal_error", 500, message)
    }

    /// `service_unavailable` (503), retry after `retry_after` seconds.
    pub fn service_unavailable(message: impl Into<String>, retry_after: u64) -> Self {
        Self::new("service_unavailable", 503, message).retry_after(retry_after)
    }

    /// Add `details`.
    #[must_use]
    pub fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }

    /// The WebSocket counterpart of `Retry-After`: `details.retryAfter`.
    fn retry_after(self, secs: u64) -> Self {
        self.with_details(json!({ "retryAfter": secs }))
    }

    /// The serialized `error` event, answering `correlation` if given.
    pub fn to_event(&self, correlation: Option<&str>, now: i64) -> String {
        let mut data = json!({
            "code": self.code,
            "message": self.message,
            "status": self.status,
        });
        if let (Some(details), Value::Object(obj)) = (&self.details, &mut data) {
            obj.insert("details".into(), details.clone());
        }
        event("error", correlation, data, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_need_an_id_and_a_type_but_not_ts() {
        let c = parse(r#"{"id":"cli_1","type":"ping","extra":1}"#).unwrap();
        assert_eq!(c.kind, "ping");
        assert_eq!(c.data, Value::Null);
        assert_eq!(
            parse(r#"{"type":"ping"}"#).unwrap_err().why,
            "frame has no usable id"
        );
        let e = parse(r#"{"id":"cli_2","data":{}}"#).unwrap_err();
        assert_eq!(e.id.as_deref(), Some("cli_2"));
        assert!(parse("[1]").is_err());
        assert!(parse("not json").is_err());
        let long = "x".repeat(MAX_ID_LEN + 1);
        assert!(parse(&format!(r#"{{"id":"{long}","type":"ping"}}"#)).is_err());
    }

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
