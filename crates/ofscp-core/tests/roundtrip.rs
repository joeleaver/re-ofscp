//! Every REST sample in the spec's `tests/` decodes into its type and
//! encodes back to the same JSON, so nothing a peer sends is lost or
//! misnamed; every sample the spec marks invalid is refused.
//!
//! The samples are read from the sibling checkout `../ofscp`
//! (`OFSCP_SPEC_DIR` overrides), as in `vectors.rs`. The samples listed in
//! `SCHEMA_CHECKED` are also validated against their schema. A missing spec
//! fails these tests; they never silently skip. The WebSocket (`ws-*`)
//! samples belong to the `ws` module, and the call-signalling (`call-*`)
//! samples are WebSocket payloads too (§9), so neither is covered here.

mod common;

use std::collections::BTreeSet;
use std::path::PathBuf;

use common::{errors_against, spec_dir};
use ofscp_core::signing::decode_public_key;
use ofscp_core::wire::*;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

fn tests_dir() -> PathBuf {
    spec_dir().join("tests")
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
    "attachment-video.sample.json" => Attachment,
    "auth-bootstrap-response.sample.json" => BootstrapResponse,
    "auth-login-request.sample.json" => LoginRequest,
    "auth-registration-request.sample.json" => RegistrationRequest,
    "channel-create-request.sample.json" => ChannelCreateRequest,
    "channel-update-request.sample.json" => ChannelUpdateRequest,
    "channel-list.sample.json" => ChannelsResponse,
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
    "group-membership.sample.json" => Group,
    "group-pointer-request.sample.json" => GroupPointerRequest,
    "group-pointer.sample.json" => GroupPointer,
    "group-pointers-response.sample.json" => GroupPointersResponse,
    "group-update-request.sample.json" => GroupUpdateRequest,
    "group.sample.json" => Group,
    "guest-claim-request.sample.json" => GuestClaimRequest,
    "guest-create-request.sample.json" => GuestCreateRequest,
    "guest-upgrade-response.sample.json" => GuestUpgradeResponse,
    "invite-create-request.sample.json" => InviteCreateRequest,
    "invite.sample.json" => Invite,
    "join-request.sample.json" => JoinRequest,
    "member.sample.json" => Member,
    "message-article.sample.json" => Message,
    "message-create-request.sample.json" => MessageCreate,
    "message-update-article-request.sample.json" => MessageUpdate,
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
    "reaction-put-request.empty.sample.json" => ReactionPut,
    "reaction-put-request.sample.json" => ReactionPut,
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
    "reaction-put-request.http-image.invalid.json",
];

/// The errors of `instance` against `schemas/v0.1/<name>`.
fn schema_errors(name: &str, instance: &Value) -> Vec<String> {
    let path = spec_dir().join("schemas/v0.1").join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {} ({e})", path.display()));
    let schema: Value = serde_json::from_str(&text).unwrap();
    errors_against(name, &schema, instance)
}

/// Samples validated against their schema, each with that schema's file.
const SCHEMA_CHECKED: &[(&str, &str)] = &[
    ("channel-list.sample.json", "channel-list.json"),
    (
        "reaction-put-request.sample.json",
        "reaction-put-request.json",
    ),
    (
        "reaction-put-request.empty.sample.json",
        "reaction-put-request.json",
    ),
];

#[test]
fn schema_checked_samples_validate() {
    let failures: Vec<String> = SCHEMA_CHECKED
        .iter()
        .flat_map(|(sample, schema)| {
            let instance: Value = serde_json::from_str(&read(sample)).unwrap();
            schema_errors(schema, &instance)
        })
        .collect();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The channel list has no `page` (§5.5), so it is not a `Paged<Channel>`,
/// and both the schema and the type require `items`.
#[test]
fn the_channel_list_is_not_a_page() {
    let list = read("channel-list.sample.json");
    assert!(serde_json::from_str::<Paged<Channel>>(&list).is_err());
    assert!(!schema_errors("channel-list.json", &json!({})).is_empty());
    assert!(serde_json::from_value::<ChannelsResponse>(json!({})).is_err());
}

/// `{}` is a valid body (§7.1): no `unicode`, no `image`.
#[test]
fn an_empty_reaction_body_is_the_default() {
    let empty: ReactionPut =
        serde_json::from_str(&read("reaction-put-request.empty.sample.json")).unwrap();
    assert_eq!(empty, ReactionPut::default());
}

/// The schema refuses an `http` image. Like `Reaction::image`, the type
/// keeps it a plain string and leaves the check to whoever fetches it, so
/// the sample decodes but fails validation.
#[test]
fn an_http_reaction_image_is_refused_by_the_schema() {
    let text = read("reaction-put-request.http-image.invalid.json");
    assert!(serde_json::from_str::<ReactionPut>(&text).is_ok());
    let instance: Value = serde_json::from_str(&text).unwrap();
    assert!(!schema_errors("reaction-put-request.json", &instance).is_empty());
}

/// Valid shapes the spec has no sample for: an empty channel list, and
/// reaction bodies with only an image or with both fields (§7.1: each is
/// optional and independent). Each passes the schema and round-trips.
#[test]
fn unsampled_valid_shapes_validate_and_round_trip() {
    let list = json!({ "items": [] });
    assert!(schema_errors("channel-list.json", &list).is_empty());
    let decoded: ChannelsResponse = serde_json::from_value(list.clone()).unwrap();
    assert!(decoded.items.is_empty());
    assert_eq!(serde_json::to_value(&decoded).unwrap(), list);

    for body in [
        json!({ "image": "https://cdn.example/party.png" }),
        json!({ "unicode": "🎉", "image": "https://cdn.example/party.png" }),
    ] {
        assert!(
            schema_errors("reaction-put-request.json", &body).is_empty(),
            "{body} fails the schema"
        );
        let decoded: ReactionPut = serde_json::from_value(body.clone()).unwrap();
        assert_eq!(serde_json::to_value(&decoded).unwrap(), body);
    }
}

/// What the schema refuses for a field's type, the type refuses too.
#[test]
fn reaction_body_refuses_mistyped_fields() {
    for bad in [
        json!({ "unicode": null }),
        json!({ "image": null }),
        json!({ "unicode": 1 }),
    ] {
        assert!(
            !schema_errors("reaction-put-request.json", &bad).is_empty(),
            "{bad} passes the schema, so this test no longer checks it"
        );
        assert!(
            serde_json::from_value::<ReactionPut>(bad.clone()).is_err(),
            "{bad} decodes"
        );
    }
}

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
