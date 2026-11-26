//! Where a user is in channels: follows (spec §7.6) and read markers
//! (§7.7).

use serde::{Deserialize, Serialize};

use super::{MetadataObject, Timestamp};
use crate::{LocalId, ObjectRef};

/// A channel you follow. A follow is only a pointer; the client builds the
/// feed itself (§7.6).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Follow {
    /// The channel: a local id on your home provider, or an object URI.
    pub channel: ObjectRef,
    /// Its group, likewise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_id: Option<ObjectRef>,
    /// When you followed it.
    pub created_at: Timestamp,
    /// Extension data.
    #[serde(default)]
    pub metadata: Vec<MetadataObject>,
}

/// `POST /api/me/follows` (§7.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FollowCreateRequest {
    /// The channel.
    pub channel: ObjectRef,
    /// Its group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_id: Option<ObjectRef>,
}

/// `GET /api/me/follows` (§7.6).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FollowsResponse {
    /// What you follow.
    pub follows: Vec<Follow>,
    /// Extension data.
    #[serde(default)]
    pub metadata: Vec<MetadataObject>,
}

/// How far you have read in a channel on your home provider, or in a
/// private conversation (§7.7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadMarker {
    /// A channel's local id, or a `dmId`.
    pub scope_id: LocalId,
    /// The newest message read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_read_message_id: Option<LocalId>,
    /// Messages after it.
    pub unread_count: u64,
    /// The channel's group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_id: Option<LocalId>,
}

/// `GET /api/me/read-markers` (§7.7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadMarkersResponse {
    /// One per scope.
    pub scopes: Vec<ReadMarker>,
}

/// One marker to move forward.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadMarkerUpdate {
    /// A channel's local id, or a `dmId`.
    pub scope_id: LocalId,
    /// The newest message now read.
    pub last_read_message_id: LocalId,
}

/// `PATCH /api/me/read-markers` (§7.7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadMarkersUpdateRequest {
    /// At least one marker.
    pub markers: Vec<ReadMarkerUpdate>,
}
