//! `MessageReference.provider` (§5.3, lost-conn/ofscp#34): the referenced
//! message's provider as a canonical authority. Every shape here is checked
//! against the spec's own `MessageReference` schema as well as the type, so
//! the two agree on what is valid. A missing spec fails these tests; they
//! never silently skip.

mod common;

use common::errors_against;
use ofscp_core::wire::{DmMessageCreate, MessageReference, ReferenceKind};
use ofscp_core::{Authority, LocalId};
use serde_json::{Value, json};

/// The errors of `instance` against `defs/messaging.json#/$defs/MessageReference`.
fn reference_schema_errors(instance: &Value) -> Vec<String> {
    let schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "https://example.invalid/ofscp/schemas/v0.1/defs/messaging.json#/$defs/MessageReference"
    });
    errors_against("MessageReference", &schema, instance)
}

fn authority(s: &str) -> Authority {
    Authority::parse_canonical(s).unwrap()
}

/// Without `provider` (the parent is local) and with one, a reference
/// passes the schema, decodes to the expected value and encodes back to the
/// same JSON: absent stays absent rather than becoming `null`.
#[test]
fn a_reference_round_trips_with_and_without_a_provider() {
    let cases = [
        (
            json!({ "type": "reply", "id": "msg_1" }),
            MessageReference {
                kind: ReferenceKind::Reply,
                id: LocalId::new("msg_1").unwrap(),
                provider: None,
            },
        ),
        (
            json!({ "type": "reply", "id": "msg_1", "provider": "b.com" }),
            MessageReference {
                kind: ReferenceKind::Reply,
                id: LocalId::new("msg_1").unwrap(),
                provider: Some(authority("b.com")),
            },
        ),
        (
            json!({ "type": "message", "id": "msg_2", "provider": "b.com:8443" }),
            MessageReference {
                kind: ReferenceKind::Message,
                id: LocalId::new("msg_2").unwrap(),
                provider: Some(authority("b.com:8443")),
            },
        ),
    ];
    for (body, expected) in cases {
        let errors = reference_schema_errors(&body);
        assert!(errors.is_empty(), "{body} fails the schema: {errors:?}");
        let decoded: MessageReference = serde_json::from_value(body.clone()).unwrap();
        assert_eq!(decoded, expected);
        assert_eq!(serde_json::to_value(&decoded).unwrap(), body);
    }
}

/// A present `provider` must hold an authority: `null` is refused by the
/// schema and by the type, never read as absent.
#[test]
fn a_null_provider_is_refused() {
    let body = json!({ "type": "reply", "id": "msg_1", "provider": null });
    assert!(
        !reference_schema_errors(&body).is_empty(),
        "the schema accepts a null provider, so this test no longer checks it"
    );
    assert!(serde_json::from_value::<MessageReference>(body).is_err());
}

/// The provider must already be canonical (§2.2): the type refuses every
/// other spelling, including ones the schema's looser pattern lets through
/// (a default `:443`), since the prose governs.
#[test]
fn a_non_canonical_provider_is_refused() {
    for provider in ["B.com", "b.com.", "b.com:443", "", "https://b.com"] {
        let body = json!({ "type": "reply", "id": "msg_1", "provider": provider });
        assert!(
            serde_json::from_value::<MessageReference>(body).is_err(),
            "{provider:?} accepted"
        );
    }
    // The schema refuses what its pattern can see.
    for provider in ["B.com", "", "https://b.com"] {
        let body = json!({ "type": "reply", "id": "msg_1", "provider": provider });
        assert!(
            !reference_schema_errors(&body).is_empty(),
            "the schema accepts {provider:?}"
        );
    }
}

/// A DM reply naming its parent's provider (§7.4) is a valid create body.
#[test]
fn a_dm_reply_may_name_the_parent_provider() {
    let body = json!({
        "clientMessageId": "c1",
        "content": { "mime": "text/plain", "text": "hi" },
        "reference": { "type": "reply", "id": "msg_1", "provider": "b.com" }
    });
    let path = common::spec_dir().join("schemas/v0.1/dm-message-create-request.json");
    let schema: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let errors = errors_against("dm-message-create-request.json", &schema, &body);
    assert!(errors.is_empty(), "{errors:?}");
    let decoded: DmMessageCreate = serde_json::from_value(body.clone()).unwrap();
    let reference = decoded.reference.as_ref().unwrap();
    assert_eq!(reference.provider, Some(authority("b.com")));
    assert_eq!(serde_json::to_value(&decoded).unwrap(), body);
}
