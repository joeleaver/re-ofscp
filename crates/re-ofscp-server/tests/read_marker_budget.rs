//! How channels from before message ordinals bound a request
//! (docs/decisions/0022 *Existing data*), on a real rhypedb-server: a
//! `PATCH` naming one still being numbered applies nothing, one request
//! numbers at most its budget over every channel it meets, and the
//! startup pass reaches every log however many there are.

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use common::groups::{Env, Party, call, join};
use common::messages::{Chan, public_channel};
use common::read_markers::{connect, legacy_log, legacy_message, mark, posts, scopes, setup};
use common::{assert_valid, schema};
use re_ofscp_server::db::Ql;
use re_ofscp_server::messages::log;
use re_ofscp_server::messages::numbering::INLINE_LIMIT;
use serde_json::{Value, json};

const QUIET: Duration = Duration::from_millis(300);

fn assert_numbering(s: StatusCode, body: &Value) {
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["errorCode"], "service_unavailable", "{body}");
}

/// Another of alice's public channels, in its own group, bob a member,
/// with a log from before ordinals of `last_seq` positions: alice's
/// messages at `first` and at the last, edits or gaps elsewhere (message
/// ids follow positions, so channels in one test use different ones).
/// Returns the channel and the message at `first`.
async fn legacy_channel(
    env: &Env,
    alice: &Party,
    bob: &Party,
    first: i64,
    last_seq: i64,
) -> (Chan, String) {
    let chan = public_channel(env, alice).await;
    join(env, &chan.g, bob, "member").await;
    legacy_log(env, &chan, last_seq).await;
    let first = legacy_message(env, &chan, first, alice, false).await;
    legacy_message(env, &chan, last_seq, alice, false).await;
    (chan, first)
}

/// Whether `chan`'s log is numbered.
async fn numbered(env: &Env, chan: &Chan) -> bool {
    let counts = log::read_counts(&env.state.db, &chan.c).await.unwrap();
    counts.unwrap().messages.is_some()
}

/// `PATCH` as `by`, unchecked.
async fn patch(env: &Env, by: &Party, markers: &[(&str, &str)]) -> (StatusCode, Value) {
    let markers: Vec<Value> = markers
        .iter()
        .map(|(s, m)| json!({"scopeId": s, "lastReadMessageId": m}))
        .collect();
    let body = json!({ "markers": markers });
    call(env, Some(by), "PATCH", "/api/me/read-markers", Some(body)).await
}

#[tokio::test]
async fn a_patch_naming_a_channel_being_numbered_applies_nothing() {
    let (env, alice, bob, chan) = setup().await;
    let m = posts(&env, &alice, &chan, 2).await;
    let (long, first) = legacy_channel(&env, &alice, &bob, 1, INLINE_LIMIT + 1).await;
    let mut phone = connect(&env, &bob).await;

    // The numbered scope comes first: it must not move on its own.
    let (s, b) = patch(&env, &bob, &[(&chan.c, &m[0]), (&long.c, &first)]).await;
    assert_numbering(s, &b);
    assert!(phone.silent_for(QUIET).await);
    assert!(!numbered(&env, &long).await);

    // Once the channel is numbered, nothing was stored for the other one.
    assert_eq!(env.state.messages.number_all().await.unwrap(), 1);
    let got = scopes(&env, &bob).await;
    let entry = got.iter().find(|e| e["scopeId"] == chan.c).unwrap();
    assert!(entry.get("lastReadMessageId").is_none(), "{entry}");
    assert_eq!(entry["unreadCount"], 2);

    // The retry moves, reports and announces both together.
    let moved = mark(&env, &bob, &[(&chan.c, &m[0]), (&long.c, &first)]).await;
    let mut ids: Vec<&str> = moved
        .iter()
        .map(|e| e["scopeId"].as_str().unwrap())
        .collect();
    ids.sort_unstable();
    let mut want = vec![chan.c.as_str(), long.c.as_str()];
    want.sort_unstable();
    assert_eq!(ids, want);
    let e = phone.event().await;
    assert_eq!(e["type"], "read.updated", "{e}");
    assert_valid(&schema("ws/read-updated.json"), &e);
    assert_eq!(e["data"], json!({ "markers": moved }));
}

#[tokio::test]
async fn one_request_numbers_at_most_its_budget_over_every_channel() {
    let (env, alice, bob, _chan) = setup().await;
    // Each fits the budget alone; together they do not.
    let half = INLINE_LIMIT / 2 + 1;
    let (a, _) = legacy_channel(&env, &alice, &bob, 1, half).await;
    let (b, _) = legacy_channel(&env, &alice, &bob, 2, half + 1).await;

    let (s, body) = call(&env, Some(&bob), "GET", "/api/me/read-markers", None).await;
    assert_numbering(s, &body);
    // It numbered one itself and handed the other over.
    let done = [numbered(&env, &a).await, numbered(&env, &b).await];
    assert_eq!(done.iter().filter(|d| **d).count(), 1, "{done:?}");

    // The next request has a budget of its own for the other.
    let got = scopes(&env, &bob).await;
    for chan in [&a, &b] {
        let entry = got.iter().find(|e| e["scopeId"] == chan.c).unwrap();
        assert_eq!(entry["unreadCount"], 2, "{entry}");
    }
}

/// A log as stored before ordinals, for a channel with nothing in it.
async fn bare_legacy_log(env: &Env, channel_id: &str, state: &str) {
    let q = Ql::new("ChannelLog.create({ channel_id: ")
        .str(channel_id)
        .raw(", group_id: \"grp_pass\", last_seq: 0, state: ")
        .str(state)
        .raw(", purged_at: 0 })");
    env.state.db.execute(&q).await.unwrap();
}

#[tokio::test]
async fn the_startup_pass_reaches_every_log_past_one_read() {
    let (env, ..) = setup().await;
    // More logs than one read returns, written out of key order, with
    // closed ones among them (never numbered, never counted).
    let mut open = Vec::new();
    for i in 0..250u32 {
        let id = format!("chn_pass{:03}", (i * 97) % 250);
        if i % 10 == 0 {
            bare_legacy_log(&env, &id, "closed").await;
        } else {
            bare_legacy_log(&env, &id, "open").await;
            open.push(id);
        }
    }

    assert_eq!(env.state.messages.number_all().await.unwrap(), open.len());
    for id in &open {
        let counts = log::read_counts(&env.state.db, id).await.unwrap().unwrap();
        assert_eq!(counts.messages, Some(0), "{id}");
    }
    assert_eq!(env.state.messages.number_all().await.unwrap(), 0);
}
