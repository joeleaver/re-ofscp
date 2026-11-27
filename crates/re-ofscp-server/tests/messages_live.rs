//! Live channel messaging over the WebSocket, on a real rhypedb-server
//! (spec §7.1 "Sending messages", "Editing & deleting messages",
//! "Reactions", "Typing indicators", "Resuming after a disconnect";
//! §11.3; decisions 0010 and 0017).
//!
//! Commands and REST writes fan out to the channel's readers, the
//! requester's copy carrying its `correlationId`; a command that changed
//! nothing answers the requester alone. Access is checked at publish, so a
//! reader whose access a committed change revoked gets nothing even before
//! the group follower has held its subscription. A resume replays the
//! timeline after its cursor, or is truncated.

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use common::groups::{
    Env, Party, call, create_channel, create_group, env_with_remotes, group_body, id, join, local,
};
use common::harness::SIGNED_AT;
use common::ws::{Client, serve};
use common::{assert_valid, schema};
use serde_json::{Value, json};

const QUIET: Duration = Duration::from_millis(300);

/// `who`, connected and authenticated.
async fn connect(env: &Env, who: &Party) -> Client {
    let addr = serve(env.app.clone()).await;
    let mut c = Client::connect(addr, "10.0.0.2").await;
    c.authenticate(
        &who.actor,
        &who.key_id,
        &who.key,
        SIGNED_AT.unix_timestamp(),
    )
    .await;
    c
}

/// Subscribe to `channel` (resuming after `since`), expecting it granted:
/// the ack's data.
async fn subscribe(c: &mut Client, channel: &str, since: Option<&str>) -> Value {
    let mut data = json!({"channels": [channel]});
    if let Some(s) = since {
        data["since"] = json!({ channel: s });
    }
    let cmd = c.command("subscribe", data).await;
    let ack = c.event().await;
    assert_eq!(ack["type"], "subscribed", "{ack}");
    assert_eq!(ack["correlationId"], cmd);
    ack["data"].clone()
}

/// The next event, checked against its `ws/` schema.
async fn event(c: &mut Client) -> Value {
    let e = c.event().await;
    let file = e["type"].as_str().unwrap().replace('.', "-");
    assert_valid(&schema(&format!("ws/{file}.json")), &e);
    e
}

/// A public group owned by `owner` with one public channel, `member`
/// joined: (group id, channel id).
async fn public_channel(env: &Env, owner: &Party, member: &Party) -> (String, String) {
    let gid = id(&create_group(env, owner, group_body("G", "public")).await);
    let cid =
        id(&create_channel(env, owner, &gid, json!({"type": "text", "tier": "public"})).await);
    join(env, &gid, member, "member").await;
    (gid, cid)
}

fn hello(cmid: &str) -> Value {
    json!({"clientMessageId": cmid, "content": {"mime": "text/plain", "text": "hi"}})
}

/// The data of a channel command: `extra` with the target ids.
fn target(gid: &str, cid: &str, extra: Value) -> Value {
    let mut v = extra;
    v["groupId"] = json!(gid);
    v["channelId"] = json!(cid);
    v
}

#[tokio::test]
async fn a_ws_create_reaches_readers_and_a_repeat_only_the_requester() {
    let env = env_with_remotes(&[]).await;
    let (olive, mia, otto) = (
        local(&env, "olive").await,
        local(&env, "mia").await,
        local(&env, "otto").await,
    );
    let (gid, cid) = public_channel(&env, &olive, &mia).await;
    let mut m = connect(&env, &mia).await;
    let mut o = connect(&env, &otto).await;
    subscribe(&mut m, &cid, None).await;
    subscribe(&mut o, &cid, None).await;

    let cmd = m
        .command("message.create", target(&gid, &cid, hello("c1")))
        .await;
    let mine = event(&mut m).await;
    assert_eq!(mine["type"], "message.created");
    assert_eq!(mine["correlationId"], cmd);
    assert_eq!(mine["data"]["cursor"], "t1", "{mine}");
    assert_eq!(mine["data"]["message"]["author"], mia.actor);
    let theirs = event(&mut o).await;
    assert!(theirs.get("correlationId").is_none(), "{theirs}");
    assert_eq!(theirs["data"], mine["data"]);

    // A repeat: the existing message, to the requester alone, no cursor.
    let again = m
        .command("message.create", target(&gid, &cid, hello("c1")))
        .await;
    let e = event(&mut m).await;
    assert_eq!(
        (&e["type"], &e["correlationId"]),
        (&json!("message.created"), &json!(again))
    );
    assert!(e["data"].get("cursor").is_none(), "{e}");
    assert_eq!(e["data"]["message"]["id"], mine["data"]["message"]["id"]);
    assert!(o.silent_for(QUIET).await);

    // A REST create fans out with no correlationId.
    let path = format!("/api/groups/{gid}/channels/{cid}/messages");
    let (s, _) = call(&env, Some(&olive), "POST", &path, Some(hello("c2"))).await;
    assert_eq!(s, StatusCode::CREATED);
    for c in [&mut m, &mut o] {
        let e = event(c).await;
        assert!(e.get("correlationId").is_none(), "{e}");
        assert_eq!(e["data"]["cursor"], "t2", "{e}");
    }
}

#[tokio::test]
async fn the_requester_gets_its_copy_unsubscribed_and_errors_correlated() {
    let env = env_with_remotes(&[]).await;
    let (olive, mia, otto) = (
        local(&env, "olive").await,
        local(&env, "mia").await,
        local(&env, "otto").await,
    );
    let (gid, cid) = public_channel(&env, &olive, &mia).await;
    let mut m = connect(&env, &mia).await;
    let cmd = m
        .command("message.create", target(&gid, &cid, hello("c1")))
        .await;
    let e = event(&mut m).await;
    assert_eq!(
        (&e["type"], &e["correlationId"]),
        (&json!("message.created"), &json!(cmd))
    );
    let msg = e["data"]["message"]["id"].as_str().unwrap().to_owned();

    // An outsider may read but not post; another's message is not theirs.
    let mut o = connect(&env, &otto).await;
    let cases = [
        (
            "message.create",
            target(&gid, &cid, hello("x")),
            "forbidden",
        ),
        (
            "message.create",
            target(&gid, "chn_nope", hello("x")),
            "not_found",
        ),
        (
            "message.create",
            target(&gid, &cid, json!({"type": 7})),
            "bad_request",
        ),
        (
            "message.update",
            target(
                &gid,
                &cid,
                json!({"messageId": msg, "content": {"mime": "text/plain", "text": "no"}}),
            ),
            "forbidden",
        ),
        (
            "message.delete",
            target(&gid, &cid, json!({"messageId": msg})),
            "forbidden",
        ),
        ("message.delete", json!({"groupId": gid}), "bad_request"),
        (
            "typing.start",
            json!({"channelId": "chn_nope"}),
            "not_found",
        ),
    ];
    for (kind, data, code) in cases {
        let cmd = o.command(kind, data).await;
        let e = event(&mut o).await;
        assert_eq!(e["type"], "error", "{kind} {e}");
        assert_eq!(e["correlationId"], cmd);
        assert_eq!(e["data"]["code"], code, "{kind} {e}");
    }
}

#[tokio::test]
async fn edits_deletes_and_reactions_fan_out_once() {
    let env = env_with_remotes(&[]).await;
    let (olive, mia, otto) = (
        local(&env, "olive").await,
        local(&env, "mia").await,
        local(&env, "otto").await,
    );
    let (gid, cid) = public_channel(&env, &olive, &mia).await;
    let mut m = connect(&env, &mia).await;
    let mut o = connect(&env, &otto).await;
    subscribe(&mut m, &cid, None).await;
    subscribe(&mut o, &cid, None).await;
    m.command("message.create", target(&gid, &cid, hello("c1")))
        .await;
    let msg = event(&mut m).await["data"]["message"]["id"].clone();
    event(&mut o).await;
    let on = |extra: Value| {
        let mut v = target(&gid, &cid, extra);
        v["messageId"] = msg.clone();
        v
    };

    let edit = json!({"content": {"mime": "text/plain", "text": "edited"}});
    m.command("message.update", on(edit)).await;
    for c in [&mut m, &mut o] {
        let e = event(c).await;
        assert_eq!(e["type"], "message.updated", "{e}");
        assert_eq!(e["data"]["cursor"], "t2");
        assert_eq!(e["data"]["message"]["content"]["text"], "edited");
        assert!(e["data"]["message"]["editedAt"].is_string(), "{e}");
    }

    // Reactions: a new one fans out; holding it already answers alone.
    m.command("reaction.add", on(json!({"key": "heart", "unicode": "❤️"})))
        .await;
    for c in [&mut m, &mut o] {
        let e = event(c).await;
        assert_eq!(e["type"], "reaction.added", "{e}");
        assert_eq!(e["data"]["reaction"]["key"], "heart");
    }
    let again = m.command("reaction.add", on(json!({"key": "heart"}))).await;
    let e = event(&mut m).await;
    assert_eq!(
        (&e["type"], &e["correlationId"]),
        (&json!("reaction.added"), &json!(again))
    );
    assert!(o.silent_for(QUIET).await);
    m.command("reaction.remove", on(json!({"key": "heart"})))
        .await;
    for c in [&mut m, &mut o] {
        let e = event(c).await;
        assert_eq!(e["type"], "reaction.removed", "{e}");
        assert_eq!(e["data"]["author"], mia.actor);
    }
    let again = m
        .command("reaction.remove", on(json!({"key": "heart"})))
        .await;
    let e = event(&mut m).await;
    assert_eq!(
        (&e["type"], &e["correlationId"]),
        (&json!("reaction.removed"), &json!(again))
    );
    assert!(o.silent_for(QUIET).await);

    // A delete fans out; a second answers the requester alone.
    m.command("message.delete", on(json!({}))).await;
    for c in [&mut m, &mut o] {
        let e = event(c).await;
        assert_eq!(e["type"], "message.deleted", "{e}");
        assert_eq!(e["data"]["cursor"], "t3");
        assert!(e["data"]["deletedAt"].is_string(), "{e}");
    }
    let again = m.command("message.delete", on(json!({}))).await;
    let e = event(&mut m).await;
    assert_eq!(
        (&e["type"], &e["correlationId"]),
        (&json!("message.deleted"), &json!(again))
    );
    assert!(e["data"].get("cursor").is_none(), "{e}");
    assert!(o.silent_for(QUIET).await);
    // A tombstone takes no edit and no reaction.
    for (kind, extra) in [
        (
            "message.update",
            json!({"content": {"mime": "text/plain", "text": "x"}}),
        ),
        ("reaction.add", json!({"key": "heart"})),
    ] {
        m.command(kind, on(extra)).await;
        let e = event(&mut m).await;
        assert_eq!(e["data"]["code"], "not_found", "{kind} {e}");
    }
}

#[tokio::test]
async fn a_revoked_reader_gets_nothing_before_its_subscription_is_held() {
    let env = env_with_remotes(&[]).await;
    let (olive, mia) = (local(&env, "olive").await, local(&env, "mia").await);
    let gid = id(&create_group(&env, &olive, group_body("G", "group")).await);
    let cid =
        id(&create_channel(&env, &olive, &gid, json!({"type": "text", "tier": "group"})).await);
    join(&env, &gid, &mia, "member").await;
    let mut m = connect(&env, &mia).await;
    let mut o = connect(&env, &olive).await;
    subscribe(&mut m, &cid, None).await;
    subscribe(&mut o, &cid, None).await;

    // Commit the revocation without announcing it: the follower that
    // would hold mia's subscription never runs (decision 0010, "The
    // window between a commit and its hold").
    env.state
        .groups
        .store
        .remove_member(&gid, &mia.id())
        .await
        .unwrap();
    let path = format!("/api/groups/{gid}/channels/{cid}/messages");
    let (s, _) = call(&env, Some(&olive), "POST", &path, Some(hello("c1"))).await;
    assert_eq!(s, StatusCode::CREATED);
    let e = event(&mut o).await;
    assert_eq!(e["type"], "message.created", "{e}");
    assert!(
        m.silent_for(QUIET).await,
        "a revoked reader received the event"
    );
}

/// Post `text` as `by` over REST: the new message's id.
async fn post(env: &Env, by: &Party, gid: &str, cid: &str, text: &str) -> String {
    let path = format!("/api/groups/{gid}/channels/{cid}/messages");
    let body = json!({"content": {"mime": "text/plain", "text": text}});
    let (s, m) = call(env, Some(by), "POST", &path, Some(body)).await;
    assert_eq!(s, StatusCode::CREATED, "{m}");
    id(&m)
}

#[tokio::test]
async fn a_resume_replays_the_timeline_after_its_cursor() {
    let env = env_with_remotes(&[]).await;
    let (olive, mia) = (local(&env, "olive").await, local(&env, "mia").await);
    let (gid, cid) = public_channel(&env, &olive, &mia).await;
    let first = post(&env, &olive, &gid, &cid, "one").await; // t1
    let second = post(&env, &olive, &gid, &cid, "two").await; // t2
    let path = |m: &str| format!("/api/groups/{gid}/channels/{cid}/messages/{m}");
    let edit = json!({"content": {"mime": "text/plain", "text": "one, edited"}});
    let (s, _) = call(&env, Some(&olive), "PATCH", &path(&first), Some(edit)).await; // t3
    assert_eq!(s, StatusCode::OK);
    let (s, _) = call(&env, Some(&olive), "DELETE", &path(&second), None).await; // t4
    assert_eq!(s, StatusCode::NO_CONTENT);
    let third = post(&env, &olive, &gid, &cid, "three").await; // t5

    let mut m = connect(&env, &mia).await;
    let ack = subscribe(&mut m, &cid, Some("t1")).await;
    assert!(ack.get("truncated").is_none(), "{ack}");
    let mut got = Vec::new();
    for _ in 0..4 {
        let e = event(&mut m).await;
        let data = &e["data"];
        let msg = data["message"]["id"]
            .as_str()
            .or(data["messageId"].as_str());
        got.push((
            e["type"].as_str().unwrap().to_owned(),
            data["cursor"].as_str().unwrap().to_owned(),
            msg.unwrap().to_owned(),
        ));
        if e["type"] == "message.created" && data["cursor"] == "t2" {
            // Replayed as it stands now: a tombstone.
            assert!(data["message"]["deletedAt"].is_string(), "{e}");
        }
    }
    let want = |k: &str, c: &str, m: &str| (k.to_owned(), c.to_owned(), m.to_owned());
    assert_eq!(
        got,
        vec![
            want("message.created", "t2", &second),
            want("message.updated", "t3", &first),
            want("message.deleted", "t4", &second),
            want("message.created", "t5", &third),
        ]
    );
    assert!(m.silent_for(QUIET).await);

    // Up to date: nothing to replay. A cursor past the end, or not one
    // of this timeline's, is truncated.
    for (since, truncated) in [("t5", false), ("t9", true), ("r1", true), ("junk", true)] {
        let mut c = connect(&env, &mia).await;
        let ack = subscribe(&mut c, &cid, Some(since)).await;
        assert_eq!(ack.get("truncated").is_some(), truncated, "{since} {ack}");
        assert!(c.silent_for(QUIET).await, "{since}");
    }
}

#[tokio::test]
async fn a_resume_too_far_back_is_truncated() {
    let env = env_with_remotes(&[]).await;
    let (olive, mia) = (local(&env, "olive").await, local(&env, "mia").await);
    let (gid, cid) = public_channel(&env, &olive, &mia).await;
    let max = re_ofscp_server::messages::MAX_REPLAY;
    for i in 0..=max {
        post(&env, &olive, &gid, &cid, &format!("m{i}")).await;
    }
    let mut c = connect(&env, &mia).await;
    let ack = subscribe(&mut c, &cid, Some("t0")).await;
    assert_eq!(ack["truncated"], json!([cid]), "{ack}");
    assert!(c.silent_for(QUIET).await);
    // Exactly the most a resume replays is replayed.
    let mut c = connect(&env, &mia).await;
    let ack = subscribe(&mut c, &cid, Some("t1")).await;
    assert!(ack.get("truncated").is_none(), "{ack}");
    for n in 2..=max + 1 {
        let e = c.event().await;
        assert_eq!(e["data"]["cursor"], format!("t{n}"), "{e}");
    }
}

#[tokio::test]
async fn typing_starts_stops_expires_and_ends_with_the_connection() {
    let env = env_with_remotes(&[]).await;
    let (olive, mia) = (local(&env, "olive").await, local(&env, "mia").await);
    let (_, cid) = public_channel(&env, &olive, &mia).await;
    let mut o = connect(&env, &olive).await;
    subscribe(&mut o, &cid, None).await;
    let typing = |state: &str| json!({"channelId": cid, "user": mia.actor, "state": state});

    let mut m = connect(&env, &mia).await;
    m.command("typing.start", json!({"channelId": cid})).await;
    assert_eq!(event(&mut o).await["data"], typing("start"));
    m.command("typing.stop", json!({"channelId": cid})).await;
    assert_eq!(event(&mut o).await["data"], typing("stop"));
    // A stop with no start active says nothing.
    m.command("typing.stop", json!({"channelId": cid})).await;
    assert!(o.silent_for(QUIET).await);
    assert!(m.silent_for(QUIET).await, "typing has no answer on success");

    // Unrefreshed, a start expires after six seconds.
    m.command("typing.start", json!({"channelId": cid})).await;
    assert_eq!(event(&mut o).await["data"], typing("start"));
    assert!(o.silent_for(Duration::from_secs(4)).await);
    assert_eq!(event(&mut o).await["data"], typing("stop"));

    // A dropped connection stops its indicators.
    m.command("typing.start", json!({"channelId": cid})).await;
    assert_eq!(event(&mut o).await["data"], typing("start"));
    drop(m);
    assert_eq!(event(&mut o).await["data"], typing("stop"));
}
