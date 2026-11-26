use serde_json::json;

use super::*;

#[test]
fn an_unknown_type_is_kept_as_received() {
    let text =
        r#"{"id":"e1","type":"call.started","ts":"2026-01-01T12:00:00Z","data":{"callId":"c1"}}"#;
    let frame = Envelope::<Event>::decode(text).unwrap();
    assert_eq!(
        frame.body,
        Event::Other {
            kind: "call.started".into(),
            data: json!({"callId": "c1"}),
        }
    );
    assert_eq!(frame.body.kind(), "call.started");
    let back: serde_json::Value = serde_json::from_str(&frame.encode().unwrap()).unwrap();
    assert_eq!(
        back,
        serde_json::from_str::<serde_json::Value>(text).unwrap()
    );
}

#[test]
fn an_unknown_type_without_data_is_sent_with_empty_data() {
    let text = r#"{"id":"e1","type":"x.y","ts":"2026-01-01T12:00:00Z"}"#;
    let frame = Envelope::<Event>::decode(text).unwrap();
    assert_eq!(
        frame.body,
        Event::Other {
            kind: "x.y".into(),
            data: serde_json::Value::Null,
        }
    );
    assert_eq!(
        frame.encode().unwrap(),
        r#"{"id":"e1","type":"x.y","ts":"2026-01-01T12:00:00Z","data":{}}"#
    );
}

#[test]
fn a_frame_without_ts_is_read_but_not_sent() {
    let frame = Envelope::<Command>::decode(r#"{"id":"c1","type":"pong","data":{}}"#).unwrap();
    assert_eq!(frame.ts, None);
    assert!(matches!(frame.encode(), Err(EncodeError::MissingTs)));
}

#[test]
fn every_sent_frame_has_the_fields_spec_main_requires() {
    let frame = Envelope {
        id: "c1".into(),
        ts: Some("2026-01-01T12:00:00Z".parse().unwrap()),
        correlation_id: None,
        body: Command::Ping(Empty {}),
    };
    let sent: serde_json::Value = serde_json::from_str(&frame.encode().unwrap()).unwrap();
    for field in ["id", "type", "ts", "data"] {
        assert!(sent.get(field).is_some(), "{field} missing from {sent}");
    }
    assert!(sent.get("correlationId").is_none());
}

#[test]
fn ping_may_leave_out_its_data() {
    let frame = Envelope::<Command>::decode(r#"{"id":"c1","type":"ping"}"#).unwrap();
    assert_eq!(frame.body, Command::Ping(Empty {}));
    assert_eq!(frame.ts, None);
}

#[test]
fn a_reply_carries_its_correlation_id() {
    let frame = Envelope {
        id: "c2".into(),
        ts: Some("2026-01-01T12:00:00Z".parse().unwrap()),
        correlation_id: Some("e9".into()),
        body: Command::Pong(Empty {}),
    };
    let text = frame.encode().unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&text).unwrap(),
        json!({
            "id": "c2",
            "type": "pong",
            "ts": "2026-01-01T12:00:00Z",
            "correlationId": "e9",
            "data": {},
        })
    );
    assert_eq!(Envelope::<Command>::decode(&text).unwrap(), frame);
}

#[test]
fn bad_data_for_a_known_type_names_the_type() {
    let err =
        Envelope::<Command>::decode(r#"{"id":"c1","type":"subscribe","data":{}}"#).unwrap_err();
    assert!(matches!(err, DecodeError::Data { ref kind, .. } if kind == "subscribe"));
}

#[test]
fn a_frame_without_an_id_is_not_an_envelope() {
    let err = Envelope::<Event>::decode(r#"{"type":"ping"}"#).unwrap_err();
    assert!(matches!(err, DecodeError::Envelope(_)));
}

#[test]
fn every_kind_is_distinct() {
    for kinds in [Command::KINDS, Event::KINDS] {
        let mut sorted = kinds.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), kinds.len());
    }
}

#[test]
fn bad_data_keeps_the_id_to_answer() {
    let err = Envelope::<Command>::decode(
        r#"{"id":"c7","type":"subscribe","correlationId":"e3","data":{"channels":5}}"#,
    )
    .unwrap_err();
    let DecodeError::Data {
        id,
        kind,
        correlation_id,
        ..
    } = err
    else {
        panic!("expected a data error, got {err:?}");
    };
    assert_eq!(
        (id.as_str(), kind.as_str(), correlation_id.as_deref()),
        ("c7", "subscribe", Some("e3"))
    );
}

#[test]
fn an_unknown_typing_or_reaction_state_is_kept() {
    let typing = r#"{"id":"e1","type":"channel.typing","ts":"2026-01-01T12:00:00Z","data":{"channelId":"chn_1","user":"alice@a.example","state":"paused"}}"#;
    let frame = Envelope::<Event>::decode(typing).unwrap();
    let Event::ChannelTyping(ref data) = frame.body else {
        panic!("expected channel.typing, got {:?}", frame.body);
    };
    assert_eq!(data.state, TypingState::Other("paused".into()));
    assert!(!data.state.is_known());
    let back: serde_json::Value = serde_json::from_str(&frame.encode().unwrap()).unwrap();
    assert_eq!(
        back,
        serde_json::from_str::<serde_json::Value>(typing).unwrap()
    );

    let state: ReactionState = serde_json::from_str(r#""replaced""#).unwrap();
    assert_eq!(state, ReactionState::Other("replaced".into()));
    assert_eq!(serde_json::to_string(&state).unwrap(), r#""replaced""#);
    assert_eq!(ReactionState::from("added"), ReactionState::Added);
}

#[test]
fn an_other_with_a_known_kind_decodes_as_that_kind() {
    let frame = Envelope {
        id: "c1".into(),
        ts: Some("2026-01-01T12:00:00Z".parse().unwrap()),
        correlation_id: None,
        body: Command::Other {
            kind: "ping".into(),
            data: json!({}),
        },
    };
    let back = Envelope::<Command>::decode(&frame.encode().unwrap()).unwrap();
    assert_eq!(back.body, Command::Ping(Empty {}));
}
