//! The §7.1 WebSocket wire format: the message envelope, the close codes,
//! the `error` event of §7.3, and the data of the handshake and
//! subscription messages.
//!
//! Everything here is pure: frames are parsed from and serialized to text,
//! and the caller supplies event ids and timestamps. A provider and a
//! client use the same types, so both sides agree on the shapes byte for
//! byte. The canonical string a client signs for `authenticate` is
//! [`ws_canonical_string`], re-exported from [`crate::signing`].
//!
//! Where the spec leaves a choice, this module follows what the OFSCP
//! oracle confirmed for re-ofscp (its `docs/decisions/0010-websocket.md`):
//! `ts` is optional on client commands, and the close codes other than
//! 4001/4003 are the RFC 6455 ones.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

pub use crate::signing::{WS_AUTH_SEPARATOR, ws_canonical_string};

/// Close codes.
pub mod close {
    /// §7.1: authentication failed, refused by federation policy, or the
    /// connection's key can no longer be confirmed. The key was not
    /// revoked; the client may reconnect and re-authenticate.
    pub const AUTH_FAILED: u16 = 4001;
    /// §7.1: the connection's credentials were revoked (its device key, or
    /// the account). The client must not reconnect with the same key.
    pub const REVOKED: u16 = 4003;
    /// RFC 6455: normal closure (for example, the heartbeat timed out).
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

/// The client commands §7.1 defines. A provider answers one it does not
/// implement with an `error`; any other unknown type is ignored (§2.3).
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

/// Longest client `id` a provider accepts (and echoes as `correlationId`).
pub const MAX_ID_LEN: usize = 256;

/// `unsubscribed.reason` when the actor lost read access (§7.1 "Losing
/// access").
pub const ACCESS_REVOKED: &str = "access_revoked";

/// A client command, as received.
#[derive(Debug, Clone, PartialEq)]
pub struct Command {
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

/// Parse a text frame as a command envelope. `id` (non-empty, at most
/// [`MAX_ID_LEN`] bytes) and `type` are required; `ts` is not required on
/// commands (the spec's own examples omit it) and is ignored.
pub fn parse_command(text: &str) -> Result<Command, Malformed> {
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
    Ok(Command {
        id,
        kind,
        data: obj.remove("data").unwrap_or(Value::Null),
    })
}

/// A server event: `{id, type, ts, correlationId?, data}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    /// The event's id, unique within its connection.
    pub id: String,
    /// `type`.
    #[serde(rename = "type")]
    pub kind: String,
    /// When it was sent (RFC 3339).
    pub ts: String,
    /// The `id` of the command this answers, if any.
    #[serde(
        rename = "correlationId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub correlation_id: Option<String>,
    /// The type's payload.
    #[serde(default)]
    pub data: Value,
}

impl Event {
    /// The event as a text frame.
    pub fn to_json(&self) -> String {
        let mut obj = Map::new();
        obj.insert("id".into(), Value::String(self.id.clone()));
        obj.insert("type".into(), Value::String(self.kind.clone()));
        obj.insert("ts".into(), Value::String(self.ts.clone()));
        if let Some(c) = &self.correlation_id {
            obj.insert("correlationId".into(), Value::String(c.clone()));
        }
        obj.insert("data".into(), self.data.clone());
        Value::Object(obj).to_string()
    }
}

/// The data of an `error` event (§7.3): an `errorCode` with its HTTP
/// status.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WsError {
    /// The `errorCode`.
    pub code: String,
    /// Human-readable text.
    pub message: String,
    /// The HTTP status paired with `code`.
    pub status: u16,
    /// Machine-readable details, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

impl WsError {
    /// An error with `code` and `status`.
    pub fn new(code: &str, status: u16, message: impl Into<String>) -> Self {
        Self {
            code: code.to_owned(),
            message: message.into(),
            status,
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
        Self::new("too_many_requests", 429, message).with_retry_after(retry_after)
    }

    /// `internal_error` (500).
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new("internal_error", 500, message)
    }

    /// `service_unavailable` (503), retry after `retry_after` seconds.
    pub fn service_unavailable(message: impl Into<String>, retry_after: u64) -> Self {
        Self::new("service_unavailable", 503, message).with_retry_after(retry_after)
    }

    /// Set `details`, replacing any (a `retryAfter` among them).
    #[must_use]
    pub fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }

    /// Add `field` to `details`, keeping what is there.
    #[must_use]
    pub fn with_detail(mut self, field: &str, value: Value) -> Self {
        match &mut self.details {
            Some(Value::Object(obj)) => {
                obj.insert(field.to_owned(), value);
            }
            _ => self.details = Some(json!({ field: value })),
        }
        self
    }

    /// Set `details.retryAfter`, the WebSocket counterpart of
    /// `Retry-After`.
    #[must_use]
    pub fn with_retry_after(self, secs: u64) -> Self {
        self.with_detail("retryAfter", json!(secs))
    }

    /// `details.retryAfter`, if given.
    pub fn retry_after(&self) -> Option<u64> {
        self.details.as_ref()?.get("retryAfter")?.as_u64()
    }

    /// The `data` of the `error` event.
    pub fn to_value(&self) -> Value {
        let mut data = json!({
            "code": self.code,
            "message": self.message,
            "status": self.status,
        });
        if let (Some(details), Value::Object(obj)) = (&self.details, &mut data) {
            obj.insert("details".into(), details.clone());
        }
        data
    }
}

/// `auth.challenge` data (`ws/auth-challenge.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthChallenge {
    /// The nonce the client signs (at least 128 bits).
    pub nonce: String,
    /// When the challenge expires (RFC 3339).
    pub expires_at: String,
}

impl AuthChallenge {
    /// The event data.
    pub fn to_value(&self) -> Value {
        json!({ "nonce": self.nonce, "expiresAt": self.expires_at })
    }
}

/// `authenticate` data (`ws/authenticate.json`). `signature` signs
/// [`ws_canonical_string`] of the provider's authority, the challenge
/// nonce and `timestamp`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Authenticate {
    /// The actor, `handle@domain`.
    pub actor: String,
    /// The signing key's id.
    pub key_id: String,
    /// When it was signed (RFC 3339).
    pub timestamp: String,
    /// The base64 Ed25519 signature.
    pub signature: String,
}

impl Authenticate {
    /// The command data.
    pub fn to_value(&self) -> Value {
        json!({
            "actor": self.actor,
            "keyId": self.key_id,
            "timestamp": self.timestamp,
            "signature": self.signature,
        })
    }
}

/// `authenticated` data (`ws/authenticated.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authenticated {
    /// The authenticated actor, canonical.
    pub actor: String,
}

impl Authenticated {
    /// The event data.
    pub fn to_value(&self) -> Value {
        json!({ "actor": self.actor })
    }
}

/// `subscribe` data (`ws/subscribe.json`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Subscribe {
    /// The channel ids.
    pub channels: Vec<String>,
    /// Only these event types, if given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include: Option<Vec<String>>,
    /// Resume cursors: channel id to the cursor to replay after.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<BTreeMap<String, String>>,
}

impl Subscribe {
    /// The command data.
    pub fn to_value(&self) -> Value {
        let mut data = json!({ "channels": self.channels });
        if let Some(include) = &self.include {
            data["include"] = json!(include);
        }
        if let Some(since) = &self.since {
            data["since"] = json!(since);
        }
        data
    }
}

/// `subscribed` data (`ws/subscribed.json`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Subscribed {
    /// The channels now subscribed.
    pub channels: Vec<String>,
    /// Resumed channels whose replay was cut short: the client backfills
    /// them through REST history.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub truncated: Vec<String>,
}

impl Subscribed {
    /// The event data.
    pub fn to_value(&self) -> Value {
        let mut data = json!({ "channels": self.channels });
        if !self.truncated.is_empty() {
            data["truncated"] = json!(self.truncated);
        }
        data
    }
}

/// `unsubscribe` data (`ws/unsubscribe.json`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Unsubscribe {
    /// The channel ids.
    pub channels: Vec<String>,
}

impl Unsubscribe {
    /// The command data.
    pub fn to_value(&self) -> Value {
        json!({ "channels": self.channels })
    }
}

/// `unsubscribed` data (`ws/unsubscribed.json`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Unsubscribed {
    /// The channels no longer subscribed.
    pub channels: Vec<String>,
    /// Why, on an unsolicited `unsubscribed` (for example
    /// [`ACCESS_REVOKED`]); absent when the client asked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl Unsubscribed {
    /// The event data.
    pub fn to_value(&self) -> Value {
        let mut data = json!({ "channels": self.channels });
        if let Some(reason) = &self.reason {
            data["reason"] = json!(reason);
        }
        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_need_an_id_and_a_type_but_not_ts() {
        let c = parse_command(r#"{"id":"cli_1","type":"ping","extra":1}"#).unwrap();
        assert_eq!(c.kind, "ping");
        assert_eq!(c.data, Value::Null);
        assert_eq!(
            parse_command(r#"{"type":"ping"}"#).unwrap_err().why,
            "frame has no usable id"
        );
        let e = parse_command(r#"{"id":"cli_2","data":{}}"#).unwrap_err();
        assert_eq!(e.id.as_deref(), Some("cli_2"));
        assert!(parse_command("[1]").is_err());
        assert!(parse_command("not json").is_err());
        let long = "x".repeat(MAX_ID_LEN + 1);
        assert!(parse_command(&format!(r#"{{"id":"{long}","type":"ping"}}"#)).is_err());
    }

    #[test]
    fn events_round_trip_and_omit_an_absent_correlation() {
        let e = Event {
            id: "evt_1".into(),
            kind: "pong".into(),
            ts: "1970-01-01T00:00:00Z".into(),
            correlation_id: None,
            data: json!({}),
        };
        let text = e.to_json();
        assert!(!text.contains("correlationId"));
        assert_eq!(serde_json::from_str::<Event>(&text).unwrap(), e);
        let answer = Event {
            correlation_id: Some("cli_1".into()),
            ..e
        };
        let v: Value = serde_json::from_str(&answer.to_json()).unwrap();
        assert_eq!(v["correlationId"], "cli_1");
        assert_eq!(v["type"], "pong");
    }

    #[test]
    fn errors_carry_their_status_and_keep_retry_after_with_other_details() {
        let e = WsError::service_unavailable("later", 7).with_detail("channels", json!(["c"]));
        assert_eq!(e.retry_after(), Some(7));
        let v = e.to_value();
        assert_eq!(v["status"], 503);
        assert_eq!(v["details"], json!({ "retryAfter": 7, "channels": ["c"] }));
        let back: WsError = serde_json::from_value(v).unwrap();
        assert_eq!(back, e);
        assert_eq!(WsError::not_found("x").to_value().get("details"), None);
    }

    /// Each `to_value` is what serde makes of the same data, so a client
    /// deserializing a provider's frames sees exactly what was sent.
    #[test]
    fn data_types_serialize_as_serde_does() {
        fn same<T: Serialize>(t: &T, v: Value) {
            assert_eq!(serde_json::to_value(t).unwrap(), v);
        }
        let ch = AuthChallenge {
            nonce: "n".into(),
            expires_at: "t".into(),
        };
        same(&ch, ch.to_value());
        let auth = Authenticate {
            actor: "a@b".into(),
            key_id: "dk_1".into(),
            timestamp: "t".into(),
            signature: "s".into(),
        };
        same(&auth, auth.to_value());
        let ok = Authenticated {
            actor: "a@b".into(),
        };
        same(&ok, ok.to_value());
        let sub = Subscribe {
            channels: vec!["c".into()],
            include: Some(vec!["message.created".into()]),
            since: Some(BTreeMap::from([("c".into(), "cur".into())])),
        };
        same(&sub, sub.to_value());
        same(&Subscribe::default(), Subscribe::default().to_value());
        let acked = Subscribed {
            channels: vec!["c".into()],
            truncated: vec!["c".into()],
        };
        same(&acked, acked.to_value());
        same(&Subscribed::default(), Subscribed::default().to_value());
        let un = Unsubscribe {
            channels: vec!["c".into()],
        };
        same(&un, un.to_value());
        let gone = Unsubscribed {
            channels: vec!["c".into()],
            reason: Some(ACCESS_REVOKED.into()),
        };
        same(&gone, gone.to_value());
        same(&Unsubscribed::default(), Unsubscribed::default().to_value());
    }

    #[test]
    fn subscribe_rejects_a_cursor_that_is_not_a_string() {
        let bad = json!({ "channels": ["c"], "since": { "c": 5 } });
        assert!(serde_json::from_value::<Subscribe>(bad).is_err());
        let s: Subscribe = serde_json::from_value(json!({ "channels": ["c"], "x": 1 })).unwrap();
        assert_eq!(s.channels, ["c"]);
    }
}
