//! Every WebSocket sample in the spec's `tests/` (`ws-*`, except the call
//! signalling of §9, a later wave) decodes as a known command or event and
//! encodes back to the same JSON, which validates against the envelope of
//! its direction (`ws/command-envelope.json` for commands,
//! `ws/event-envelope.json` for events, both for `ping` and `pong`) and the
//! schema of its `type`. The spec's invalid `ws-*` frames are refused where
//! a provider answers or a sender writes them.
//!
//! The samples are read from the sibling checkout `../ofscp`
//! (`OFSCP_SPEC_DIR` overrides), as in `roundtrip.rs`.

use std::collections::BTreeSet;
use std::path::PathBuf;

use ofscp_core::ws::{Body, Command, DecodeError, EncodeError, Envelope, Event};
use serde_json::{Value, json};

mod common;

use common::{errors_against, spec_dir};

fn tests_dir() -> PathBuf {
    spec_dir().join("tests")
}

/// The errors of `instance` against `schemas/v0.1/ws/<name>`.
fn schema_errors(name: &str, instance: &Value) -> Vec<String> {
    let path = spec_dir().join("schemas/v0.1/ws").join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {} ({e})", path.display()));
    let schema: Value = serde_json::from_str(&text).unwrap();
    errors_against(name, &schema, instance)
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

/// The `ts` this test gives a decoded frame that had none, so it can be
/// encoded ([`Envelope::encode`] always sends one).
const SENT_TS: &str = "2026-01-01T12:00:00Z";

/// `v` without its `ts`.
fn without_ts(v: &Value) -> Value {
    let mut v = v.clone();
    if let Some(obj) = v.as_object_mut() {
        obj.remove("ts");
    }
    v
}

/// Decode `name` as a frame of `T` and encode it again; the failure, if any.
///
/// The re-encoded frame must equal the sample. Its `ts` is compared only
/// where the sample has a valid one: a command may leave `ts` out, or send
/// one providers ignore (§7.1), and such a frame is sent with [`SENT_TS`].
/// The result must validate against each of `envelopes` and the schema of
/// its `type`.
fn frame<T: Body>(name: &str, kinds: &[&str], envelopes: &[&str]) -> Option<String> {
    let text = read(name);
    let original: Value = serde_json::from_str(&text).unwrap();
    let mut decoded = match Envelope::<T>::decode(&text) {
        Ok(d) => d,
        Err(e) => return Some(format!("{name}: {e}")),
    };
    let kind = original["type"].as_str().unwrap_or_default();
    if !kinds.contains(&kind) {
        return Some(format!("{name}: {kind} decoded as Other"));
    }
    let had_ts = decoded.ts.is_some();
    if !had_ts {
        decoded.ts = Some(SENT_TS.parse().unwrap());
    }
    let back: Value = serde_json::from_str(&decoded.encode().unwrap()).unwrap();
    let same = if had_ts {
        back == original
    } else {
        without_ts(&back) == without_ts(&original)
    };
    if !same {
        return Some(format!("{name}: re-encoded as {back}"));
    }
    let mut errors: Vec<String> = envelopes
        .iter()
        .flat_map(|e| schema_errors(e, &back))
        .collect();
    errors.extend(schema_errors(
        &format!("{}.json", kind.replace('.', "-")),
        &back,
    ));
    (!errors.is_empty()).then(|| format!("{name}: {}", errors.join("; ")))
}

/// The envelopes a client's command must satisfy.
const COMMAND_ENVELOPES: &[&str] = &["envelope.json", "command-envelope.json"];
/// The envelopes a provider's event must satisfy.
const EVENT_ENVELOPES: &[&str] = &["envelope.json", "event-envelope.json"];
/// `ping` and `pong`, which either party sends, use the base envelope; ours
/// always carry `ts` and an object `data`, so they satisfy both directions.
const EITHER_ENVELOPES: &[&str] = &[
    "envelope.json",
    "command-envelope.json",
    "event-envelope.json",
];

/// The samples a client sends.
const COMMANDS: &[&str] = &[
    "ws-authenticate.sample.json",
    "ws-command-ts-ignored.sample.json",
    "ws-message-create.sample.json",
    "ws-message-delete.sample.json",
    "ws-message-update-article.sample.json",
    "ws-message-update.sample.json",
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

/// The samples either party sends.
const EITHER: &[&str] = &["ws-ping.sample.json", "ws-pong.sample.json"];

/// The samples a provider sends.
const EVENTS: &[&str] = &[
    "ws-auth-challenge.sample.json",
    "ws-authenticated.sample.json",
    "ws-channel-typing.sample.json",
    "ws-dm-conversation.sample.json",
    "ws-dm-message.sample.json",
    "ws-dm-reaction.sample.json",
    "ws-dm-typing.sample.json",
    "ws-error-subscribe-partial.sample.json",
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

/// The frames the spec's schemas refuse.
const INVALID: &[&str] = &[
    "ws-ping.data-not-object.invalid.json",
    "ws-subscribe.no-id.invalid.json",
    "ws-subscribed.no-ts.invalid.json",
];

#[test]
fn ws_samples_round_trip() {
    let failures: Vec<String> = COMMANDS
        .iter()
        .filter_map(|n| frame::<Command>(n, Command::KINDS, COMMAND_ENVELOPES))
        .chain(
            EITHER
                .iter()
                .filter_map(|n| frame::<Command>(n, Command::KINDS, EITHER_ENVELOPES)),
        )
        .chain(
            EITHER
                .iter()
                .filter_map(|n| frame::<Event>(n, Event::KINDS, EITHER_ENVELOPES)),
        )
        .chain(
            EVENTS
                .iter()
                .filter_map(|n| frame::<Event>(n, Event::KINDS, EVENT_ENVELOPES)),
        )
        .collect();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The names in the spec's `tests/` that start with `ws-` and end with
/// `suffix`, but the call signalling of §9.
fn on_disk(suffix: &str) -> BTreeSet<String> {
    std::fs::read_dir(tests_dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.starts_with("ws-") && n.ends_with(suffix))
        .filter(|n| !n.starts_with("ws-call-"))
        .collect()
}

#[test]
fn every_ws_sample_is_listed() {
    let listed: BTreeSet<String> = [COMMANDS, EITHER, EVENTS]
        .concat()
        .into_iter()
        .map(str::to_owned)
        .collect();
    assert_eq!(on_disk(".sample.json"), listed);
    let invalid: BTreeSet<String> = INVALID.iter().map(|&n| n.to_owned()).collect();
    assert_eq!(on_disk(".invalid.json"), invalid);
}

/// A command's `ts` is optional, and one that is not a time is ignored
/// (§7.1): `ws-command-ts-ignored` decodes, with no `ts`.
#[test]
fn a_command_ts_that_is_not_a_time_is_ignored() {
    let frame = Envelope::<Command>::decode(&read("ws-command-ts-ignored.sample.json")).unwrap();
    assert_eq!(frame.ts, None);
    assert_eq!(frame.body.kind(), "typing.stop");
    let frame = Envelope::<Command>::decode(&read("ws-subscribe.sample.json")).unwrap();
    assert_eq!(frame.ts, None);
}

/// What each invalid frame decodes as: no `id` is no envelope; a `data`
/// that is not an object is bad data, with the `id` to answer (§7.1); an
/// event without `ts` is read (decoding is lenient) but could not be sent.
#[test]
fn the_invalid_frames_are_refused_where_we_send_or_answer() {
    let no_id = Envelope::<Command>::decode(&read("ws-subscribe.no-id.invalid.json"));
    assert!(matches!(no_id, Err(DecodeError::Envelope(_))), "{no_id:?}");
    let bad_data = Envelope::<Command>::decode(&read("ws-ping.data-not-object.invalid.json"));
    assert!(
        matches!(bad_data, Err(DecodeError::Data { ref id, .. }) if id == "cli_400"),
        "{bad_data:?}"
    );
    let no_ts = Envelope::<Event>::decode(&read("ws-subscribed.no-ts.invalid.json")).unwrap();
    assert_eq!(no_ts.ts, None);
    assert!(matches!(no_ts.encode(), Err(EncodeError::MissingTs)));
    for name in INVALID {
        let instance: Value = serde_json::from_str(&read(name)).unwrap();
        let kind = instance["type"].as_str().unwrap();
        let schema = format!("{}.json", kind.replace('.', "-"));
        assert!(
            !schema_errors(&schema, &instance).is_empty(),
            "{name} passes {schema}, so this test no longer checks the validator"
        );
    }
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
        let errors: Vec<String> = EITHER_ENVELOPES
            .iter()
            .flat_map(|e| schema_errors(e, &sent))
            .collect();
        assert!(errors.is_empty(), "{}", errors.join("\n"));
    }
    // What the patch's first encoding wrote: the event envelope refuses
    // it, so the validator above is live.
    let bare = json!({"id": "e1", "type": "x.y"});
    let errors = schema_errors("event-envelope.json", &bare).join("\n");
    assert!(
        errors.contains("\"ts\"") && errors.contains("\"data\""),
        "{errors}"
    );
}

/// The strings of `$defs.<name>.enum` in the spec's `ws/types.json`.
fn spec_types(name: &str) -> BTreeSet<String> {
    let path = spec_dir().join("schemas/v0.1/ws/types.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read {} ({e}); clone lost-conn/ofscp beside this repo or set OFSCP_SPEC_DIR",
            path.display()
        )
    });
    let types: Value = serde_json::from_str(&text).unwrap();
    types["$defs"][name]["enum"]
        .as_array()
        .unwrap_or_else(|| panic!("types.json has no $defs.{name}.enum"))
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect()
}

fn set(kinds: &[&str]) -> BTreeSet<String> {
    kinds.iter().map(|&k| k.to_owned()).collect()
}

#[test]
fn the_kinds_are_the_spec_types() {
    assert_eq!(set(Command::KINDS), spec_types("WsCommandType"));
    // The call signalling events of §9 are left out on purpose: calls are a
    // later wave, so they decode as `Event::Other` for now. Adding them to
    // `Event` must also drop them from this list.
    let calls = set(&["call.started", "call.ended", "call.participant"]);
    let spec = spec_types("WsEventType");
    assert!(calls.is_subset(&spec), "the spec no longer lists {calls:?}");
    assert_eq!(set(Event::KINDS), &spec - &calls);
}
