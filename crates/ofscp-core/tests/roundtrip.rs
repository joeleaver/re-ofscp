//! Every REST sample in the spec's `tests/` decodes into its type and
//! encodes back to the same JSON, so nothing a peer sends is lost or
//! misnamed; every sample the spec marks invalid is refused.
//!
//! The samples are read from the sibling checkout `../ofscp`
//! (`OFSCP_SPEC_DIR` overrides), as in `vectors.rs`. A missing spec fails
//! these tests; they never silently skip. The WebSocket (`ws-*`) samples
//! belong to the `ws` module, and the call-signalling (`call-*`) samples are
//! WebSocket payloads too (§9), so neither is covered here.

use std::collections::BTreeSet;
use std::path::PathBuf;

use ofscp_core::signing::decode_public_key;
use ofscp_core::wire::*;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

fn tests_dir() -> PathBuf {
    std::env::var_os("OFSCP_SPEC_DIR")
        .map_or_else(
            || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../ofscp"),
            PathBuf::from,
        )
        .join("tests")
}

fn read(name: &str) -> String {
    let path = tests_dir().join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read {} ({e}); clone lost-conn/ofscp beside this repo or set OFSCP_SPEC_DIR",
            path.display()
        )
    })
}

/// Decode `name` as `T` and encode it again; the failure, if any.
fn roundtrip<T: Serialize + DeserializeOwned>(name: &str) -> Option<String> {
    let text = read(name);
    let decoded: T = match serde_json::from_str(&text) {
        Ok(d) => d,
        Err(e) => return Some(format!("{name}: does not decode: {e}")),
    };
    let original: Value = serde_json::from_str(&text).unwrap();
    let back = serde_json::to_value(&decoded).unwrap();
    (back != original).then(|| format!("{name}: re-encodes as {back}"))
}

/// The REST samples, each with its type.
macro_rules! rest_samples {
    ($($file:literal => $ty:ty,)+) => {
        const REST: &[&str] = &[$($file),+];

        #[test]
        fn rest_samples_round_trip() {
            let failures: Vec<String> = [$( roundtrip::<$ty>($file), )+]
                .into_iter()
                .flatten()
                .collect();
            assert!(failures.is_empty(), "{}", failures.join("\n"));
        }
    };
}

rest_samples! {
    "attachment.sample.json" => Attachment,
    "auth-bootstrap-response.sample.json" => BootstrapResponse,
    "auth-login-request.sample.json" => LoginRequest,
    "auth-registration-request.sample.json" => RegistrationRequest,
    "channel-create-request.sample.json" => ChannelCreateRequest,
    "channel-update-request.sample.json" => ChannelUpdateRequest,
    "channel.sample.json" => Channel,
    "contact-create-request.sample.json" => ContactCreateRequest,
    "contact-event.sample.json" => ContactEvent,
    "contact.sample.json" => Contact,
    "contacts-response.sample.json" => ContactsResponse,
    "device-key-registration.sample.json" => DeviceKeyRegistration,
    "device-key-response.sample.json" => DeviceKeyCreated,
    "device-keys-response.sample.json" => DeviceKeysResponse,
    "discover-response.sample.json" => DiscoverResponse,
    "dm-conversation-pointer-request.sample.json" => ConversationPointer,
    "dm-conversation.sample.json" => DmConversation,
    "dm-conversations-response.sample.json" => DmConversationsResponse,
    "dm-message-create-request.sample.json" => DmMessageCreate,
    "follow-create-request.sample.json" => FollowCreateRequest,
    "follow.sample.json" => Follow,
    "follows-response.sample.json" => FollowsResponse,
    "group-create-request.sample.json" => GroupCreateRequest,
    "group-update-request.sample.json" => GroupUpdateRequest,
    "group.sample.json" => Group,
    "guest-claim-request.sample.json" => GuestClaimRequest,
    "guest-create-request.sample.json" => GuestCreateRequest,
    "guest-upgrade-response.sample.json" => GuestUpgradeResponse,
    "invite-create-request.sample.json" => InviteCreateRequest,
    "invite.sample.json" => Invite,
    "join-request.sample.json" => JoinRequest,
    "member.sample.json" => Member,
    "message-create-request.sample.json" => MessageCreate,
    "message-update-request.sample.json" => MessageUpdate,
    "message.sample.json" => Message,
    "messages-page.sample.json" => MessagesPage,
    "notification-setting.sample.json" => NotificationSetting,
    "notification-settings-response.sample.json" => NotificationSettingsResponse,
    "notification.sample.json" => Notification,
    "notifications-delivery.sample.json" => Delivery,
    "notifications-endpoints-response.sample.json" => EndpointsResponse,
    "notifications-mark-response.sample.json" => NotificationsMarkResponse,
    "notifications-response.sample.json" => NotificationsResponse,
    "notifications-webhook-registration.sample.json" => EndpointRegistration,
    "presence-update-request.sample.json" => PresenceUpdate,
    "presence.sample.json" => Presence,
    "privacy-settings-update-request.sample.json" => PrivacyUpdate,
    "privacy-settings.sample.json" => PrivacySettings,
    "problem-details.sample.json" => ProblemDetails,
    "provider-discovery.sample.json" => DiscoveryDocument,
    "providers-response.sample.json" => ProvidersResponse,
    "push-payload.sample.json" => PushPayload,
    "push-public-key-response.sample.json" => PushPublicKey,
    "push-subscribe-request.sample.json" => PushSubscribeRequest,
    "reaction.sample.json" => Reaction,
    "read-markers-response.sample.json" => ReadMarkersResponse,
    "read-markers-update-request.sample.json" => ReadMarkersUpdateRequest,
    "tiers-response.sample.json" => TiersResponse,
    "user-keys-response.sample.json" => UserKeysResponse,
    "user-profile.sample.json" => UserProfile,
}

/// The samples the spec marks invalid, each refused by a test below.
const INVALID: &[&str] = &[
    "device-key-registration.spki.invalid.json",
    "presence-update-request.offline.invalid.json",
];

#[test]
fn setting_yourself_offline_is_refused() {
    let text = read("presence-update-request.offline.invalid.json");
    assert!(serde_json::from_str::<PresenceUpdate>(&text).is_err());
}

/// The shape is valid; the key is a DER `SubjectPublicKeyInfo`, not the raw
/// 32 bytes, so decoding it as a key refuses it (§4.3.2).
#[test]
fn a_der_public_key_is_refused() {
    let reg: DeviceKeyRegistration =
        serde_json::from_str(&read("device-key-registration.spki.invalid.json")).unwrap();
    assert!(decode_public_key(&reg.public_key).is_err());
    let good: DeviceKeyRegistration =
        serde_json::from_str(&read("device-key-registration.sample.json")).unwrap();
    assert!(decode_public_key(&good.public_key).is_ok());
}

/// A new REST sample in the spec fails this test until it is given a type
/// above, so none is skipped silently.
#[test]
fn every_rest_sample_is_covered() {
    let dir = tests_dir();
    let entries = std::fs::read_dir(&dir).unwrap_or_else(|e| {
        panic!(
            "cannot list {} ({e}); clone lost-conn/ofscp beside this repo or set OFSCP_SPEC_DIR",
            dir.display()
        )
    });
    let on_disk: BTreeSet<String> = entries
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.ends_with(".sample.json") || n.ends_with(".invalid.json"))
        .filter(|n| !n.starts_with("ws-") && !n.starts_with("call-"))
        .collect();
    let covered: BTreeSet<String> = [REST, INVALID]
        .concat()
        .into_iter()
        .map(str::to_owned)
        .collect();
    let missing: Vec<_> = on_disk.difference(&covered).collect();
    assert!(missing.is_empty(), "samples without a type: {missing:?}");
    let gone: Vec<_> = covered.difference(&on_disk).collect();
    assert!(gone.is_empty(), "covered samples not in the spec: {gone:?}");
}
