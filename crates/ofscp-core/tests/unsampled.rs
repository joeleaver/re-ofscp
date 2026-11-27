//! REST payloads the spec gives neither a schema nor a sample for, only an
//! example in its text. Each example here is copied from the spec (or built
//! from its description), decodes into its type and encodes back to the
//! same JSON, and validates against a schema assembled from the spec's own
//! definitions, so the type cannot drift from what the schemas allow.
//!
//! The schemas are read from the sibling checkout `../ofscp`
//! (`OFSCP_SPEC_DIR` overrides), as in `roundtrip.rs`.

mod common;

use common::{SCHEMA_ID_BASE, errors_against};
use ofscp_core::wire::*;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

/// Decode `example` as `T`, check it encodes back unchanged, and return it.
fn roundtrip<T: Serialize + DeserializeOwned>(example: &Value) -> T {
    let decoded: T = serde_json::from_value(example.clone())
        .unwrap_or_else(|e| panic!("{example} does not decode: {e}"));
    let back = serde_json::to_value(&decoded).unwrap();
    assert_eq!(&back, example, "re-encodes differently");
    decoded
}

fn assert_valid(label: &str, schema: &Value, instance: &Value) {
    let errors = errors_against(label, schema, instance);
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

/// `GET /api/groups/{groupId}/channels` (§5.5): `{ "items": [Channel] }`,
/// each item a `channel.json`, with no `page`.
fn channels_response_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": format!("{SCHEMA_ID_BASE}channels-response.json"),
        "type": "object",
        "additionalProperties": true,
        "required": ["items"],
        "properties": {
            "items": { "type": "array", "items": { "$ref": "./channel.json" } }
        }
    })
}

/// The `PUT …/reactions/{key}` body (§7.1, §7.4): `{ unicode?, image? }`,
/// each typed as the same field of the `Reaction` it creates.
fn reaction_put_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": format!("{SCHEMA_ID_BASE}reaction-put-request.json"),
        "type": "object",
        "additionalProperties": true,
        "properties": {
            "unicode": { "$ref": "./defs/messaging.json#/$defs/Reaction/properties/unicode" },
            "image": { "$ref": "./defs/messaging.json#/$defs/Reaction/properties/image" }
        }
    })
}

#[test]
fn the_channels_list_example_round_trips_and_validates() {
    // §5.5, verbatim.
    let example = json!({ "items": [ {
        "id": "chn_general", "groupId": "grp_1", "type": "text", "tier": "public",
        "createdAt": "2025-03-01T12:00:00Z", "updatedAt": "2025-03-01T12:00:00Z",
        "metadata": []
    } ] });
    let schema = channels_response_schema();
    assert_valid("channels-response", &schema, &example);
    let list: ChannelsResponse = roundtrip(&example);
    assert_eq!(list.items.len(), 1);
    assert_eq!(list.items[0].kind, ChannelType::Text);

    let empty = json!({ "items": [] });
    assert_valid("channels-response", &schema, &empty);
    assert!(roundtrip::<ChannelsResponse>(&empty).items.is_empty());
}

#[test]
fn the_channels_list_is_not_a_page() {
    let unpaged = json!({ "items": [] });
    assert!(serde_json::from_value::<Paged<Channel>>(unpaged).is_err());
    // The schema is live: it refuses a list without `items`.
    assert!(
        !errors_against("channels-response", &channels_response_schema(), &json!({})).is_empty()
    );
    assert!(serde_json::from_value::<ChannelsResponse>(json!({})).is_err());
}

#[test]
fn reaction_put_bodies_round_trip_and_validate() {
    let schema = reaction_put_schema();
    for example in [
        // The optional body of §7.1 and §7.4, filled in.
        json!({ "unicode": "❤️", "image": "https://cdn.example/heart.png" }),
        json!({ "unicode": "❤️" }),
        json!({ "image": "https://cdn.example/heart.png" }),
        json!({}),
    ] {
        assert_valid("reaction-put-request", &schema, &example);
        roundtrip::<ReactionPut>(&example);
    }
    assert_eq!(
        serde_json::from_value::<ReactionPut>(json!({})).unwrap(),
        ReactionPut::default()
    );
}

#[test]
fn reaction_put_refuses_what_the_schema_refuses() {
    let schema = reaction_put_schema();
    for bad in [
        json!({ "unicode": null }),
        json!({ "image": null }),
        json!({ "unicode": 1 }),
    ] {
        assert!(
            !errors_against("reaction-put-request", &schema, &bad).is_empty(),
            "{bad} passes the schema, so this test no longer checks it"
        );
        assert!(
            serde_json::from_value::<ReactionPut>(bad.clone()).is_err(),
            "{bad} decodes"
        );
    }
    // `image` must be HTTPS in the schema; like `Reaction::image`, the type
    // keeps it a string and leaves the check to whoever fetches it.
    let http = json!({ "image": "http://cdn.example/heart.png" });
    assert!(!errors_against("reaction-put-request", &schema, &http).is_empty());
}
