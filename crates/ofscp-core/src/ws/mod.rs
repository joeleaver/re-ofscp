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
//! frame is always sent with `ts` and `data`, which spec main's
//! `ws/envelope.json` requires, but one received without them is still read.

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
    /// When it was sent. Spec main's envelope requires it on every frame,
    /// so [`Envelope::encode`] refuses a frame without it. A received frame
    /// may lack it: lost-conn/ofscp#27 (open) makes it optional on commands,
    /// and tells providers to ignore its value there.
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
    /// Its `data` does not fit its `type`.
    #[error("bad data for {kind}: {source}")]
    Data {
        /// The frame's `type`.
        kind: String,
        /// What did not fit.
        #[source]
        source: serde_json::Error,
    },
}

/// Why a frame could not be written.
#[derive(Debug, thiserror::Error)]
pub enum EncodeError {
    /// The frame has no `ts`, which spec main requires on every frame.
    #[error("a frame needs a ts")]
    MissingTs,
    /// Its body did not serialize.
    #[error("cannot serialize the frame: {0}")]
    Json(#[from] serde_json::Error),
}

/// The envelope as received, before `data` is decoded. Only `id` and
/// `type` are required here; a missing `data` reads as `null`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawFrame {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    ts: Option<Timestamp>,
    #[serde(default)]
    correlation_id: Option<String>,
    #[serde(default)]
    data: serde_json::Value,
}

/// The envelope as sent: `id`, `type`, `ts` and `data` always present, as
/// spec main's `ws/envelope.json` requires.
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
        let body = T::decode(&raw.kind, raw.data).map_err(|source| DecodeError::Data {
            kind: raw.kind,
            source,
        })?;
        Ok(Self {
            id: raw.id,
            ts: raw.ts,
            correlation_id: raw.correlation_id,
            body,
        })
    }

    /// The frame's text, to send. It always carries `ts` (so `ts` must be
    /// set) and `data`. A `data` of `null`, which only an unknown frame
    /// received without one can hold, is written as `{}`: an object is the
    /// one form every envelope schema accepts, at spec main and in
    /// lost-conn/ofscp#27.
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
                    $( $kind => Self::$variant(serde_json::from_value($crate::ws::known_data(data))?), )+
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

/// `data` as an object: one that is absent or `null` is empty. Standard
/// types decode through it (a `ping` or `pong` may leave its `data` out),
/// and every frame is encoded through it.
pub(crate) fn known_data(data: serde_json::Value) -> serde_json::Value {
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
