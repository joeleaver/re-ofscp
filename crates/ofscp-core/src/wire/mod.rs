//! The REST payloads of OFSCP v0.1 as serde types, following the spec's
//! JSON Schemas (`schemas/v0.1`). The WebSocket frames are not here.
//!
//! Conventions (docs/decisions/0013):
//!
//! * **Unknown fields are ignored** (§2.3): no type denies them.
//! * **Received enumerations are open**: each has an `Other` variant that
//!   keeps a value this version does not know, so one new value (a MINOR
//!   version, §2.1) never makes a whole response unreadable. Equality and
//!   hashing go through the wire string, so `Other("private".into())`
//!   equals [`Tier::Private`]. Enumerations only ever *sent* by a client,
//!   whose values the spec fixes ([`SetAvailability`], [`Visibility`]), are
//!   closed, so a provider refuses an unknown value while decoding.
//! * **Optional fields** are `Option`s, left out when `None`.
//! * **`metadata` and `attachments`**, lists the schemas require, read as
//!   empty when a sender leaves them out: refusing a whole object over it
//!   would lose the rest.
//! * **Identifiers deserialize strictly** ([`crate::Actor`],
//!   [`crate::Authority`], [`crate::LocalId`], [`crate::ObjectRef`]); no
//!   field here opts into [`crate::actor::lenient`].
//! * **Timestamps** are [`Timestamp`] (`jiff`, RFC 3339, §2.5).
//! * Field names are camelCase, except the auth and key payloads of §4,
//!   which are snake_case (§2.5).

mod auth;
mod common;
mod contact;
mod delivery;
mod directory;
mod discovery;
mod dm;
mod follow;
mod group;
mod guest;
mod membership;
mod message;
mod notify;
mod open_enum;
mod privacy;
mod problem;
mod profile;

pub use auth::*;
pub use common::*;
pub use contact::*;
pub use delivery::*;
pub use directory::*;
pub use discovery::*;
pub use dm::*;
pub use follow::*;
pub use group::*;
pub use guest::*;
pub use membership::*;
pub use message::*;
pub use notify::*;
pub use privacy::*;
pub use problem::*;
pub use profile::*;

/// An RFC 3339 instant (§2.5).
pub use jiff::Timestamp;

pub(crate) use open_enum::open_enum;
