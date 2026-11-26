//! Every WebSocket sample in the spec's `tests/` (`ws-*`, except the call
//! signalling of §9, a later wave) decodes as a known command or event and
//! encodes back to the same JSON, which validates against the spec's
//! envelope schema and the schema of its `type`.
//!
//! The samples are read from the sibling checkout `../ofscp`
//! (`OFSCP_SPEC_DIR` overrides), as in `roundtrip.rs`.

use std::collections::BTreeSet;
use std::path::PathBuf;

use ofscp_core::ws::{Body, Command, Envelope, Event};
use serde_json::{Value, json};

fn spec_dir() -> PathBuf {
    std::env::var_os("OFSCP_SPEC_DIR").map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../ofscp"),
        PathBuf::from,
    )
}

fn tests_dir() -> PathBuf {
    spec_dir().join("tests")
}

/// The `$id` prefix of the spec's schemas.
const SCHEMA_ID_BASE: &str = "https://example.invalid/ofscp/schemas/v0.1/";

/// Resolves the schemas' relative `$ref`s to files in the spec checkout.
struct SpecRetriever;

impl jsonschema::Retrieve for SpecRetriever {
    fn retrieve(
        &self,
        uri: &jsonschema::Uri<String>,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        let rel = uri
            .as_str()
            .strip_prefix(SCHEMA_ID_BASE)
            .ok_or_else(|| format!("unexpected schema uri {uri}"))?;
        let path = spec_dir().join("schemas/v0.1").join(rel);
        Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
    }
}

/// The errors of `instance` against `schemas/v0.1/ws/<name>`.
fn schema_errors(name: &str, instance: &Value) -> Vec<String> {
    let path = spec_dir().join("schemas/v0.1/ws").join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {} ({e})", path.display()));
    let schema: Value = serde_json::from_str(&text).unwrap();
    let validator = jsonschema::options()
        .should_validate_formats(true)
        .with_retriever(SpecRetriever)
        .build(&schema)
        .unwrap_or_else(|e| panic!("schema {name} does not compile: {e}"));
    validator
        .iter_errors(instance)
        .map(|e| format!("{name}: {e} at {}", e.instance_path()))
        .collect()
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

/// Decode `name` as a frame of `T` and encode it again; the failure, if any.
fn frame<T: Body>(name: &str, kinds: &[&str]) -> Option<String> {
    let text = read(name);
    let original: Value = serde_json::from_str(&text).unwrap();
    let decoded = match Envelope::<T>::decode(&text) {
        Ok(d) => d,
        Err(e) => return Some(format!("{name}: {e}")),
    };
    let kind = original["type"].as_str().unwrap_or_default();
    if !kinds.contains(&kind) {
        return Some(format!("{name}: {kind} decoded as Other"));
    }
    let back: Value = serde_json::from_str(&decoded.encode().unwrap()).unwrap();
    if back != original {
        return Some(format!("{name}: re-encoded as {back}"));
    }
    let mut errors = schema_errors("envelope.json", &back);
    errors.extend(schema_errors(
        &format!("{}.json", kind.replace('.', "-")),
        &back,
    ));
    (!errors.is_empty()).then(|| format!("{name}: {}", errors.join("; ")))
}

/// The samples a client sends.
const COMMANDS: &[&str] = &[
    "ws-authenticate.sample.json",
    "ws-message-create.sample.json",
    "ws-message-delete.sample.json",
    "ws-message-update-article.sample.json",
    "ws-message-update.sample.json",
    "ws-ping.sample.json",
    "ws-pong.sample.json",
    "ws-presence-set.sample.json",
    "ws-presence-subscribe.sample.json",
    "ws-presence-unsubscribe.sample.json",
    "ws-reaction-add.sample.json",
    "ws-reaction-remove.sample.json",
    "ws-subscribe.sample.json",
    "ws-typing-start.sample.json",
    "ws-typing-stop.sample.json",
    "ws-unsubscribe.sample.json",
];

/// The samples a provider sends.
const EVENTS: &[&str] = &[
    "ws-auth-challenge.sample.json",
    "ws-authenticated.sample.json",
    "ws-channel-typing.sample.json",
    "ws-dm-conversation.sample.json",
    "ws-dm-message.sample.json",
    "ws-dm-reaction.sample.json",
    "ws-dm-typing.sample.json",
    "ws-error.sample.json",
    "ws-groups-updated.sample.json",
    "ws-member-updated.sample.json",
    "ws-message-created.sample.json",
    "ws-message-deleted.sample.json",
    "ws-message-updated.sample.json",
    "ws-notification-created.sample.json",
    "ws-presence-subscribed.sample.json",
    "ws-presence-unsubscribed.sample.json",
    "ws-presence-update.sample.json",
    "ws-reaction-added.sample.json",
    "ws-reaction-removed.sample.json",
    "ws-read-updated.sample.json",
    "ws-subscribed.sample.json",
    "ws-unsubscribed-revoked.sample.json",
    "ws-unsubscribed.sample.json",
];

#[test]
fn ws_samples_round_trip() {
    let failures: Vec<String> = COMMANDS
        .iter()
        .filter_map(|n| frame::<Command>(n, Command::KINDS))
        .chain(
            EVENTS
                .iter()
                .filter_map(|n| frame::<Event>(n, Event::KINDS)),
        )
        .collect();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn every_ws_sample_is_listed() {
    let on_disk: BTreeSet<String> = std::fs::read_dir(tests_dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.starts_with("ws-") && n.ends_with(".sample.json"))
        .filter(|n| !n.starts_with("ws-call-"))
        .collect();
    let listed: BTreeSet<String> = [COMMANDS, EVENTS]
        .concat()
        .into_iter()
        .map(str::to_owned)
        .collect();
    assert_eq!(on_disk, listed);
}

#[test]
fn an_unknown_frame_is_sent_as_a_valid_envelope() {
    for text in [
        r#"{"id":"e1","type":"x.y","ts":"2026-01-01T12:00:00Z"}"#,
        r#"{"id":"e1","type":"x.y","ts":"2026-01-01T12:00:00Z","data":null}"#,
    ] {
        let sent: Value =
            serde_json::from_str(&Envelope::<Event>::decode(text).unwrap().encode().unwrap())
                .unwrap();
        assert_eq!(sent["data"], json!({}));
        let errors = schema_errors("envelope.json", &sent);
        assert!(errors.is_empty(), "{}", errors.join("\n"));
    }
    // What the patch's first encoding wrote: spec main refuses it, so the
    // validator above is live.
    let bare = json!({"id": "e1", "type": "x.y"});
    let errors = schema_errors("envelope.json", &bare).join("\n");
    assert!(
        errors.contains("\"ts\"") && errors.contains("\"data\""),
        "{errors}"
    );
}
