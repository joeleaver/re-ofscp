//! Files attached to messages (spec §5.8, `objects.json#/$defs/Attachment`).
//!
//! Attachments are untrusted (§5.8): every field may be a claim of the
//! author that nobody checked, and `url` is a capability URL.

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

use super::Timestamp;
use crate::LocalId;

/// A file uploaded to `/api/media` and attached to a message (§5.8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Attachment {
    /// The attachment's local id.
    pub id: LocalId,
    /// Its IANA media type.
    pub mime: String,
    /// Where to fetch it (HTTPS); a capability URL.
    pub url: String,
    /// Its size in bytes.
    pub size: u64,
    /// The original file name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    /// A content hash, `<algo>:<base64>` such as `sha-256:…`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    /// Width in pixels, for pictures and video.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<u32>,
    /// Height in pixels, for pictures and video.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
    /// Length in milliseconds, for audio and video.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    /// A preview picture, such as a video's poster frame, set at upload.
    /// A thumbnail that itself carries a thumbnail is refused (§5.8).
    #[serde(
        default,
        deserialize_with = "thumbnail",
        skip_serializing_if = "Option::is_none"
    )]
    pub thumbnail: Option<Thumbnail>,
    /// When a short-lived `url` stops working (§5.8, *Revocation*); absent
    /// means it does not expire. Only the provider that mints the URL sets
    /// it, in messages it holds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Timestamp>,
}

/// An attachment's preview picture (§5.8, *Thumbnail*): an `Attachment`
/// with an `image/*` `mime` and no thumbnail of its own, which this type
/// cannot hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Thumbnail {
    /// The thumbnail's local id.
    pub id: LocalId,
    /// Its IANA media type, `image/*`.
    pub mime: String,
    /// Where to fetch it (HTTPS); a capability URL.
    pub url: String,
    /// Its size in bytes.
    pub size: u64,
    /// The original file name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    /// A content hash, `<algo>:<base64>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    /// Width in pixels.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<u32>,
    /// Height in pixels.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
    /// Length in milliseconds; a picture has none, but one sent is kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    /// When a short-lived `url` stops working (§5.8, *Revocation*).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Timestamp>,
}

/// A present `thumbnail` must be an object without a `thumbnail` of its
/// own (the schema's `not: {required: [thumbnail]}`); `null` is refused.
fn thumbnail<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Thumbnail>, D::Error> {
    let fields = Map::<String, Value>::deserialize(d)?;
    if fields.contains_key("thumbnail") {
        return Err(serde::de::Error::custom(
            "a thumbnail must not carry a thumbnail (§5.8)",
        ));
    }
    Thumbnail::deserialize(Value::Object(fields))
        .map(Some)
        .map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn video() -> Value {
        json!({
            "id": "att_7", "mime": "video/mp4", "url": "https://cdn.a.com/m/1/v.mp4",
            "size": 7, "expiresAt": "2026-01-01T13:00:00Z",
            "thumbnail": {"id": "att_8", "mime": "image/jpeg",
                          "url": "https://cdn.a.com/m/2/p.jpg", "size": 5}
        })
    }

    #[test]
    fn a_thumbnail_round_trips() {
        let a: Attachment = serde_json::from_value(video()).unwrap();
        assert_eq!(a.thumbnail.as_ref().map(|t| t.id.as_str()), Some("att_8"));
        assert!(a.expires_at.is_some());
        assert_eq!(serde_json::to_value(&a).unwrap(), video());
    }

    #[test]
    fn a_nested_or_null_thumbnail_is_refused() {
        let mut nested = video();
        nested["thumbnail"]["thumbnail"] = video()["thumbnail"].clone();
        assert!(serde_json::from_value::<Attachment>(nested).is_err());
        let mut null = video();
        null["thumbnail"] = Value::Null;
        assert!(serde_json::from_value::<Attachment>(null).is_err());
    }

    #[test]
    fn unknown_fields_in_a_thumbnail_are_ignored() {
        let mut extra = video();
        extra["thumbnail"]["future"] = json!(1);
        assert!(serde_json::from_value::<Attachment>(extra).is_ok());
    }
}
