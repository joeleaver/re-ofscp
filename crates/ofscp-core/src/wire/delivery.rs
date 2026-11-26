//! Notification endpoints and their deliveries (spec §10), and Web Push
//! (§10.3).

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::open_enum;
use crate::{Authority, DmId, LocalId};

open_enum! {
    /// How a notification endpoint is reached (§10).
    pub enum EndpointType {
        /// A Web Push endpoint.
        WebPush = "webpush",
    }
}

/// `POST /api/notifications/endpoints`: register an endpoint (§10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointRegistration {
    /// How it is reached.
    #[serde(rename = "type")]
    pub kind: EndpointType,
    /// Where (HTTPS).
    pub target: String,
    /// The event types to deliver, such as `message.created` (§7.1).
    pub events: Vec<String>,
}

/// A registered endpoint: the `201 Created` answer to a registration, and
/// one entry of [`EndpointsResponse`] (§10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationEndpoint {
    /// The endpoint's local id.
    pub id: LocalId,
    /// How it is reached.
    #[serde(rename = "type")]
    pub kind: EndpointType,
    /// Where (HTTPS).
    pub target: String,
    /// The event types it receives.
    pub events: Vec<String>,
}

/// `GET /api/notifications/endpoints` (§10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointsResponse {
    /// The caller's endpoints.
    pub endpoints: Vec<NotificationEndpoint>,
}

/// What a delivery is about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryResource {
    /// The resource's id.
    pub id: String,
    /// Its channel, for channel activity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    /// Any other fields, kept: they are covered by the signature.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A delivery to a notification endpoint (§10). It is provider-signed:
/// `signature` is a detached Ed25519 signature (base64) over the JCS
/// (RFC 8785) form of the object *without* `signature`. Verifying it needs
/// every field the provider sent, so unknown fields are kept in `extra`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delivery {
    /// The event type, such as `message.created`.
    pub event: String,
    /// What it is about.
    pub resource: DeliveryResource,
    /// The provider that signed it.
    pub provider: Authority,
    /// The detached signature, base64.
    pub signature: String,
    /// Any other fields, kept.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `GET /api/push/public-key`: the provider's VAPID key (§10.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PushPublicKey {
    /// The uncompressed P-256 point, base64url, for `applicationServerKey`.
    pub public_key: String,
}

/// A browser `PushSubscription`'s keys (§10.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushKeys {
    /// The subscription's P-256 public key, base64url.
    pub p256dh: String,
    /// The authentication secret, base64url.
    pub auth: String,
}

/// `POST /api/push/subscribe` (§10.3). `endpoint` must be `https:`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushSubscribeRequest {
    /// The push service URL.
    pub endpoint: String,
    /// The browser's keys.
    pub keys: PushKeys,
}

/// The `201 Created` answer to a push subscription (§10.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushSubscribeResponse {
    /// The subscription's local id.
    pub id: LocalId,
}

/// `POST /api/push/unsubscribe` (§10.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushUnsubscribeRequest {
    /// The push service URL subscribed before.
    pub endpoint: String,
}

open_enum! {
    /// Why a push was sent (§10.3): a notification type (§10.1) or a DM.
    pub enum PushKind {
        /// A mention.
        Mention = "mention",
        /// A reply.
        Reply = "reply",
        /// A message, where settings ask for all of them.
        Message = "message",
        /// A private message.
        Dm = "dm",
    }
}

/// Where a push leads (§10.3): `group_id`, `channel_id` and `message_id`
/// for channel activity, or `dm_id` and `message_id` for a DM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PushData {
    /// Why it was sent.
    #[serde(rename = "type")]
    pub kind: PushKind,
    /// The group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_id: Option<LocalId>,
    /// The channel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<LocalId>,
    /// The message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_id: Option<LocalId>,
    /// The conversation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dm_id: Option<DmId>,
    /// Provider additions, such as a `targetUrl` for its own client.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The decrypted payload of a Web Push message (§10.3). `body` is a preview
/// of at most 120 characters; a provider never previews a message the
/// user may not read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushPayload {
    /// The headline.
    pub title: String,
    /// The preview.
    pub body: String,
    /// What it collapses with: `chan:<groupId>` or `dm:<dmId>`.
    pub tag: String,
    /// Where it leads.
    pub data: PushData,
}
