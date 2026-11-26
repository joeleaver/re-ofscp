//! Shapes shared across the payloads: metadata, content, paging, tiers,
//! the key algorithm (`schemas/v0.1/defs`), and the serde helpers for
//! optional and clearable fields.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

use super::open_enum;

/// A metadata object (§5.4): `{ schema, version, data }`, plus any further
/// fields the sender included, kept as they came. Consumers ignore schemas
/// they do not know.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetadataObject {
    /// The HTTPS URI naming the extension's schema.
    pub schema: String,
    /// The schema's version.
    pub version: String,
    /// The payload, validated by the schema, not here. Required, but may be
    /// `null`.
    #[serde(deserialize_with = "present_value")]
    pub data: Value,
    /// Any other fields, preserved.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `data` must be present; `null` is a value. Without this, serde would
/// accept a missing `data` as `null`.
fn present_value<'de, D: Deserializer<'de>>(d: D) -> Result<Value, D::Error> {
    Value::deserialize(d)
}

/// A body of text and its media type (`text/plain`, `text/markdown`, HTML).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Content {
    /// The text.
    pub text: String,
    /// Its IANA media type.
    pub mime: String,
}

/// The cursors of one page of a list (`PagedResponse.page`). Cursors are
/// opaque (§2.5).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Page {
    /// The cursor for the next (older) page, if there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    /// The cursor for the previous (newer) page, if there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_cursor: Option<String>,
}

/// One page of a list (`PagedResponse`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Paged<T> {
    /// The items on this page.
    pub items: Vec<T>,
    /// Where the neighbouring pages are.
    pub page: Page,
}

open_enum! {
    /// Who may see a group or channel (§11). Every provider has `private`;
    /// a provider may define more, listed by `GET /api/tiers`.
    pub enum Tier {
        /// Members only.
        Private = "private",
        /// Members of the group.
        Group = "group",
        /// Anyone, including anonymous readers.
        Public = "public",
        /// Public, and listed for discovery.
        Discoverable = "discoverable",
    }
}

open_enum! {
    /// A device key's algorithm. v0.1 has only Ed25519 (§4.3.3).
    pub enum KeyAlgorithm {
        /// Ed25519.
        Ed25519 = "Ed25519",
    }
}

/// A present optional field must hold a value: `null` is refused rather
/// than read as absent (only fields typed [`Patch`] give `null` a meaning).
pub(crate) fn some<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

/// A field of a partial update that may also be cleared with `null`.
/// Give the field `#[serde(default, skip_serializing_if = "Patch::is_keep")]`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Patch<T> {
    /// Absent: leave it unchanged.
    #[default]
    Keep,
    /// `null`: remove it.
    Clear,
    /// A new value.
    Set(T),
}

impl<T> Patch<T> {
    /// Whether the field is left out.
    pub fn is_keep(&self) -> bool {
        matches!(self, Self::Keep)
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Patch<T> {
    // Called only when the field is present (absent fields take the
    // `Default`, `Keep`), so `null` here means "clear".
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(match Option::<T>::deserialize(d)? {
            None => Self::Clear,
            Some(v) => Self::Set(v),
        })
    }
}

impl<T: Serialize> Serialize for Patch<T> {
    // `Keep` is skipped by `skip_serializing_if`; if it is serialized
    // anyway it becomes `null`, like `Clear`.
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Keep | Self::Clear => s.serialize_none(),
            Self::Set(v) => s.serialize_some(v),
        }
    }
}
