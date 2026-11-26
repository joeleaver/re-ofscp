//! The WebSocket protocol (spec §7.1): the envelope every frame uses, the
//! commands a client sends, the events a provider sends, and the close
//! codes.
//!
//! Frames decode in two steps: the envelope, then its `data` by `type`. A
//! `type` this version does not know decodes as `Other` and keeps its data,
//! since clients must ignore unknown types (§2.3). Call events (§9) are among
//! those for now: calls are a later wave.
//!
//! Encoding is strict where decoding is lenient (docs/decisions/0016): a
//! frame is always sent with `ts` and an object `data`, so it validates
//! against both `ws/command-envelope.json` and `ws/event-envelope.json`.
//! A received frame needs only `id` and `type` in its envelope; its `ts` is
//! read when it is a valid RFC 3339 time and ignored otherwise, since
//! providers must ignore a command's `ts` (§7.1, lost-conn/ofscp#27). The
//! `data` of a standard type must be an object (§7.1).

mod command;
mod event;

pub use command::*;
pub use event::*;

use serde::{Deserialize, Serialize};

use crate::wire::Timestamp;

/// Close code: authentication failed, the actor or provider is refused by
/// federation policy, or the key could not be confirmed. The key was not
/// revoked; the client may reconnect later (§7.1).
pub const CLOSE_AUTH_FAILED: u16 = 4001;

/// Close code: the connection's key was revoked, or its account no longer
/// exists. The client must not reconnect with the same key (§7.1).
pub const CLOSE_REVOKED: u16 = 4003;

/// One frame: the envelope (§7.1) around a command or an event.
#[derive(Debug, Clone, PartialEq)]
pub struct Envelope<T> {
    /// Unique within the connection.
    pub id: String,
    /// When it was sent. Events must carry it (`ws/event-envelope.json`),
    /// so [`Envelope::encode`] refuses a frame without it, commands
    /// included. A received frame may lack it, and one whose `ts` is not an
    /// RFC 3339 time reads as `None`: on commands it is optional and
    /// providers must ignore its value (§7.1, lost-conn/ofscp#27).
    pub ts: Option<Timestamp>,
    /// The `id` of the command this answers.
    pub correlation_id: Option<String>,
    /// The command or event.
    pub body: T,
}

/// A command or event: a `type` and its `data`.
pub trait Body: Sized {
    /// Decode `data` by `kind`. An unknown kind is not an error.
    fn decode(kind: &str, data: serde_json::Value) -> Result<Self, serde_json::Error>;

    /// The `type` and `data` to send.
    fn encode(&self) -> Result<(String, serde_json::Value), serde_json::Error>;
}

/// Why a frame could not be read.
#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    /// It is not a JSON envelope.
    #[error("not an OFSCP frame: {0}")]
    Envelope(#[source] serde_json::Error),
    /// Its envelope was read, but its `data` does not fit its `type`: for
    /// a standard type, a `data` that is missing, not an object, or not of
    /// that type's shape.
    ///
    /// A provider answers a command like this with an `error`
    /// (`bad_request`) whose `correlationId` is `id`, and keeps the
    /// connection open (§7.1); for `authenticate` it
    /// answers `unauthorized` and closes 4001 instead. A client that cannot
    /// read an event keeps this to itself: it never sends a reply.
    #[error("bad data for {kind} {id}: {source}")]
    Data {
        /// The frame's `id`, to echo as `correlationId`.
        id: String,
        /// The frame's `type`.
        kind: String,
        /// The frame's `correlationId`, when it had one.
        correlation_id: Option<String>,
        /// What did not fit.
        #[source]
        source: serde_json::Error,
    },
}

/// Why a frame could not be written.
#[derive(Debug, thiserror::Error)]
pub enum EncodeError {
    /// The frame has no `ts`, which every event needs (and which this
    /// crate also sends on commands, where providers ignore it).
    #[error("a frame needs a ts")]
    MissingTs,
    /// Its body did not serialize.
    #[error("cannot serialize the frame: {0}")]
    Json(#[from] serde_json::Error),
}

/// The envelope as received, before `data` is decoded. Only `id` and
/// `type` are required here; a missing `data` reads as `null` (which only
/// an unknown type accepts), and a `ts` that is not a time reads as `None`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawFrame {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default, deserialize_with = "lenient_ts")]
    ts: Option<Timestamp>,
    #[serde(default)]
    correlation_id: Option<String>,
    #[serde(default)]
    data: serde_json::Value,
}

/// The envelope as sent: `id`, `type`, `ts` and `data` always present, as
/// `ws/event-envelope.json` requires (and `ws/command-envelope.json`
/// allows).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OutFrame<'a> {
    id: &'a str,
    #[serde(rename = "type")]
    kind: String,
    ts: Timestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    correlation_id: Option<&'a str>,
    data: serde_json::Value,
}

impl<T: Body> Envelope<T> {
    /// Read a frame's text.
    pub fn decode(text: &str) -> Result<Self, DecodeError> {
        let raw: RawFrame = serde_json::from_str(text).map_err(DecodeError::Envelope)?;
        let RawFrame {
            id,
            kind,
            ts,
            correlation_id,
            data,
        } = raw;
        match T::decode(&kind, data) {
            Ok(body) => Ok(Self {
                id,
                ts,
                correlation_id,
                body,
            }),
            Err(source) => Err(DecodeError::Data {
                id,
                kind,
                correlation_id,
                source,
            }),
        }
    }

    /// The frame's text, to send. It always carries `ts` (so `ts` must be
    /// set) and `data`. A `data` of `null`, which only an unknown frame
    /// received without one can hold, is written as `{}`: an object is the
    /// one form every envelope schema accepts (the base, command and event
    /// envelopes).
    pub fn encode(&self) -> Result<String, EncodeError> {
        let ts = self.ts.ok_or(EncodeError::MissingTs)?;
        let (kind, data) = self.body.encode()?;
        Ok(serde_json::to_string(&OutFrame {
            id: &self.id,
            kind,
            ts,
            correlation_id: self.correlation_id.as_deref(),
            data: known_data(data),
        })?)
    }
}

/// Define a command or event enum: each variant a `type` and its data, plus
/// `Other` for types this version does not know.
macro_rules! ws_body {
    (
        $(#[$meta:meta])*
        pub enum $name:ident {
            $( $(#[$vmeta:meta])* $variant:ident($data:ty) = $kind:literal, )+
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq)]
        pub enum $name {
            $( $(#[$vmeta])* $variant($data), )+
            /// A type this version does not know, kept as received.
            ///
            /// Build it only for a nonstandard type: one built with a kind
            /// in [`Self::KINDS`] is sent under that kind, and so decodes
            /// back as that kind's variant (or fails to, if `data` does not
            /// fit), never as `Other`.
            Other {
                /// Its `type`.
                kind: String,
                /// Its `data`.
                data: serde_json::Value,
            },
        }

        impl $name {
            /// Every standard `type` this enum knows.
            pub const KINDS: &'static [&'static str] = &[$($kind),+];

            /// The `type` on the wire.
            pub fn kind(&self) -> &str {
                match self {
                    $( Self::$variant(_) => $kind, )+
                    Self::Other { kind, .. } => kind,
                }
            }
        }

        impl $crate::ws::Body for $name {
            fn decode(kind: &str, data: serde_json::Value) -> Result<Self, serde_json::Error> {
                Ok(match kind {
                    $( $kind => Self::$variant(serde_json::from_value($crate::ws::object_data(data)?)?), )+
                    other => Self::Other { kind: other.to_owned(), data },
                })
            }

            fn encode(&self) -> Result<(String, serde_json::Value), serde_json::Error> {
                Ok(match self {
                    $( Self::$variant(data) => ($kind.to_owned(), serde_json::to_value(data)?), )+
                    Self::Other { kind, data } => (kind.clone(), data.clone()),
                })
            }
        }
    };
}
pub(crate) use ws_body;

/// The `data` of a standard type, which must be an object (§7.1): one
/// that is missing, `null` or of another JSON type is refused, so a
/// provider answers the command with `bad_request` (an array would
/// otherwise deserialize into a struct field by field).
pub(crate) fn object_data(data: serde_json::Value) -> Result<serde_json::Value, serde_json::Error> {
    match data {
        serde_json::Value::Object(_) => Ok(data),
        _ => Err(serde::de::Error::custom("data must be an object")),
    }
}

/// A received `ts`: the time it names, or `None` when it is absent, `null`
/// or not an RFC 3339 string. Providers must ignore a command's `ts`
/// (§7.1), so a bad one never fails the frame.
fn lenient_ts<'de, D>(deserializer: D) -> Result<Option<Timestamp>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    Ok(serde_json::from_value(value).ok())
}

/// `data` as sent: one that is `null` (only an unknown frame received
/// without `data` holds one) is written as `{}`.
fn known_data(data: serde_json::Value) -> serde_json::Value {
    match data {
        serde_json::Value::Null => serde_json::Value::Object(serde_json::Map::new()),
        data => data,
    }
}

/// The `data` of `ping` and `pong`: an empty object.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Empty {}

#[cfg(test)]
#[path = "ws_tests.rs"]
mod tests;
