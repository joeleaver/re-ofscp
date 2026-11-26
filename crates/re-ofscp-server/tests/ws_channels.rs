//! WebSocket channel subscriptions over the provider's own groups, on a
//! real rhypedb-server (spec §7.1 "Channel subscriptions", "Losing
//! access"; §11.3; security requirements 1 and 5).
//!
//! A subscribe is granted exactly when effective read access holds: the
//! stricter of the group's tier and the channel's, narrowed by `view`. An
//! unreadable channel is refused exactly as a missing one. A change that
//! revokes access (a tier, `view`, membership, or deletion) ends the
//! subscription with `unsubscribed {reason: "access_revoked"}`, and nothing
//! published afterwards reaches it.

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use common::groups::{
    Env, Party, call, create_channel, create_group, env_with_remotes, group_body, id, join, local,
    remote,
};
use common::harness::SIGNED_AT;
use common::ws::{Client, serve};
use re_ofscp_server::groups::AccessChange as GroupChange;
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

/// Subscribe to `channel`, expecting it granted.
async fn subscribed(c: &mut Client, channel: &str) {
    let cmd = c.command("subscribe", json!({"channels": [channel]})).await;
    let ack = c.event().await;
    assert_eq!(ack["type"], "subscribed", "{ack}");
    assert_eq!(ack["correlationId"], cmd);
    assert_eq!(ack["data"]["channels"], json!([channel]), "{ack}");
}

/// Subscribe to `channels`, expecting every one refused with one
/// `not_found` naming them all, and nothing else.
async fn refused(c: &mut Client, channels: &[&str]) {
    let cmd = c.command("subscribe", json!({"channels": channels})).await;
    let mut e = c.event().await;
    if e["type"] == "subscribed" {
        assert_eq!(e["data"]["channels"], json!([]), "{e}");
        e = c.event().await;
    }
    assert_eq!(e["type"], "error", "{e}");
    assert_eq!(e["correlationId"], cmd);
    assert_eq!(e["data"]["code"], "not_found", "{e}");
    assert_eq!(e["data"]["details"]["channels"], json!(channels), "{e}");
    assert!(c.silent_for(QUIET).await);
}

/// Expect `channel`'s subscription ended for lost access, and nothing
/// published to it afterwards to arrive.
async fn revoked(env: &Env, c: &mut Client, channel: &str) {
    let e = c.event().await;
    assert_eq!(e["type"], "unsubscribed", "{e}");
    assert!(e.get("correlationId").is_none(), "{e}");
    assert_eq!(
        e["data"],
        json!({"channels": [channel], "reason": "access_revoked"})
    );
    env.state
        .ws
        .publish(channel, "message.created", json!({"n": 1}));
    assert!(c.silent_for(QUIET).await);
}

/// Expect `channel`'s subscription still live: a publish arrives.
async fn still_live(env: &Env, c: &mut Client, channel: &str) {
    env.state
        .ws
        .publish(channel, "message.created", json!({"n": 2}));
    let e = c.event().await;
    assert_eq!(
        (&e["type"], &e["data"]),
        (&json!("message.created"), &json!({"n": 2})),
        "{e}"
    );
}

async fn ok(env: &Env, by: &Party, method: &str, path: &str, body: Option<Value>) {
    let (s, b) = call(env, Some(by), method, path, body).await;
    assert!(
        s == StatusCode::OK || s == StatusCode::NO_CONTENT,
        "{s} {b}"
    );
}

/// A group of `group_tier` owned by `owner`, with one channel of
/// `channel`'s body: (group id, channel id).
async fn group_with(
    env: &Env,
    owner: &Party,
    group_tier: &str,
    channel: Value,
) -> (String, String) {
    let gid = id(&create_group(env, owner, group_body("G", group_tier)).await);
    let cid = id(&create_channel(env, owner, &gid, channel).await);
    (gid, cid)
}

fn text(tier: &str) -> Value {
    json!({"type": "text", "tier": tier})
}

#[tokio::test]
async fn subscribing_follows_effective_read_access() {
    let env = env_with_remotes(&[]).await;
    let owner = local(&env, "olive").await;
    let mia = local(&env, "mia").await;
    let out = local(&env, "otto").await;
    let (open, open_chan) = group_with(&env, &owner, "public", text("public")).await;
    let members_chan = id(&create_channel(&env, &owner, &open, text("group")).await);
    let admins = json!({"type": "text", "tier": "public", "permissions": {"view": ["admin"]}});
    let admins_chan = id(&create_channel(&env, &owner, &open, admins).await);
    // A public channel cannot widen a members-only group.
    let (closed, closed_chan) = group_with(&env, &owner, "group", text("public")).await;
    let (_, private_chan) = group_with(&env, &owner, "private", text("private")).await;
    join(&env, &open, &mia, "member").await;
    join(&env, &closed, &mia, "member").await;

    let mut c = connect(&env, &out).await;
    subscribed(&mut c, &open_chan).await;
    refused(
        &mut c,
        &[
            &members_chan,
            &admins_chan,
            &closed_chan,
            &private_chan,
            "chn_nope",
        ],
    )
    .await;

    let mut c = connect(&env, &mia).await;
    subscribed(&mut c, &open_chan).await;
    subscribed(&mut c, &members_chan).await;
    subscribed(&mut c, &closed_chan).await;
    refused(&mut c, &[&admins_chan, &private_chan]).await;

    let mut c = connect(&env, &owner).await;
    for chan in [
        &open_chan,
        &members_chan,
        &admins_chan,
        &closed_chan,
        &private_chan,
    ] {
        subscribed(&mut c, chan).await;
    }
}

#[tokio::test]
async fn tightening_a_channel_tier_revokes_outsiders_only() {
    let env = env_with_remotes(&[]).await;
    let owner = local(&env, "olive").await;
    let mia = local(&env, "mia").await;
    let out = local(&env, "otto").await;
    let (gid, cid) = group_with(&env, &owner, "public", text("public")).await;
    join(&env, &gid, &mia, "member").await;
    let mut outsider = connect(&env, &out).await;
    let mut member = connect(&env, &mia).await;
    subscribed(&mut outsider, &cid).await;
    subscribed(&mut member, &cid).await;

    let path = format!("/api/groups/{gid}/channels/{cid}");
    ok(&env, &owner, "PATCH", &path, Some(text("group"))).await;

    revoked(&env, &mut outsider, &cid).await;
    // The member keeps it (it got the publish `revoked` sent, too).
    let e = member.event().await;
    assert_eq!(e["data"], json!({"n": 1}), "{e}");
    still_live(&env, &mut member, &cid).await;
    refused(&mut outsider, &[&cid]).await;
}

#[tokio::test]
async fn a_view_list_or_a_role_change_revokes() {
    let env = env_with_remotes(&[]).await;
    let owner = local(&env, "olive").await;
    let mia = local(&env, "mia").await;
    let (gid, cid) = group_with(&env, &owner, "group", text("group")).await;
    join(&env, &gid, &mia, "admin").await;
    let mut c = connect(&env, &mia).await;
    subscribed(&mut c, &cid).await;

    let path = format!("/api/groups/{gid}/channels/{cid}");
    let view = json!({"type": "text", "permissions": {"view": ["admin"]}});
    ok(&env, &owner, "PATCH", &path, Some(view)).await;
    still_live(&env, &mut c, &cid).await;

    // Demoted: `view` now leaves her out.
    let groups = &env.state.groups;
    assert!(groups.set_role(&gid, &mia.id(), "member").await.unwrap());
    revoked(&env, &mut c, &cid).await;
}

#[tokio::test]
async fn removing_a_member_revokes_their_subscriptions() {
    let env = env_with_remotes(&[]).await;
    let owner = local(&env, "olive").await;
    let mia = local(&env, "mia").await;
    let (gid, cid) = group_with(&env, &owner, "group", text("group")).await;
    join(&env, &gid, &mia, "member").await;
    let mut c = connect(&env, &mia).await;
    let mut o = connect(&env, &owner).await;
    subscribed(&mut c, &cid).await;
    subscribed(&mut o, &cid).await;

    env.state
        .groups
        .remove_member(&gid, &mia.id())
        .await
        .unwrap();
    revoked(&env, &mut c, &cid).await;
    let e = o.event().await;
    assert_eq!(e["data"], json!({"n": 1}), "{e}");
}

#[tokio::test]
async fn tightening_the_group_revokes_every_channel() {
    let env = env_with_remotes(&[]).await;
    let owner = local(&env, "olive").await;
    let out = local(&env, "otto").await;
    let (gid, first) = group_with(&env, &owner, "public", text("public")).await;
    let second = id(&create_channel(&env, &owner, &gid, text("public")).await);
    let mut c = connect(&env, &out).await;
    subscribed(&mut c, &first).await;
    subscribed(&mut c, &second).await;

    let path = format!("/api/groups/{gid}");
    ok(&env, &owner, "PATCH", &path, Some(json!({"tier": "group"}))).await;

    let mut ended = Vec::new();
    for _ in 0..2 {
        let e = c.event().await;
        assert_eq!(e["type"], "unsubscribed", "{e}");
        assert_eq!(e["data"]["reason"], "access_revoked", "{e}");
        ended.extend(e["data"]["channels"].as_array().unwrap().clone());
        if ended.len() == 2 {
            break;
        }
    }
    ended.sort_by_key(|v| v.as_str().unwrap().to_owned());
    let mut want = vec![json!(first), json!(second)];
    want.sort_by_key(|v| v.as_str().unwrap().to_owned());
    assert_eq!(ended, want);
    assert!(c.silent_for(QUIET).await);
}

#[tokio::test]
async fn deleting_a_channel_or_its_group_revokes() {
    let env = env_with_remotes(&[]).await;
    let owner = local(&env, "olive").await;
    let mia = local(&env, "mia").await;
    let (gid, cid) = group_with(&env, &owner, "public", text("public")).await;
    let other = id(&create_channel(&env, &owner, &gid, text("public")).await);
    let mut c = connect(&env, &mia).await;
    subscribed(&mut c, &cid).await;
    subscribed(&mut c, &other).await;

    let gpath = format!("/api/groups/{gid}");
    ok(
        &env,
        &owner,
        "DELETE",
        &format!("{gpath}/channels/{cid}"),
        None,
    )
    .await;
    revoked(&env, &mut c, &cid).await;
    still_live(&env, &mut c, &other).await;

    // The group's purge removes the rows its channels are found by.
    ok(&env, &owner, "DELETE", &gpath, None).await;
    revoked(&env, &mut c, &other).await;
}

#[tokio::test]
async fn deleting_a_group_names_each_channel_before_the_purge() {
    let env = env_with_remotes(&[]).await;
    let owner = local(&env, "olive").await;
    let (gid, first) = group_with(&env, &owner, "public", text("public")).await;
    let second = id(&create_channel(&env, &owner, &gid, text("group")).await);
    let mut rx = env.state.groups.subscribe_changes();

    ok(&env, &owner, "DELETE", &format!("/api/groups/{gid}"), None).await;

    let mut named = Vec::new();
    loop {
        match rx.recv().await.unwrap() {
            GroupChange::Channel {
                group_id,
                channel_id,
            } => {
                assert_eq!(group_id, gid);
                named.push(channel_id);
            }
            GroupChange::Group { group_id } => {
                assert_eq!(group_id, gid);
                break;
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    named.sort();
    let mut want = vec![first, second];
    want.sort();
    assert_eq!(named, want);
    // The rows are gone: only these announcements could name them.
    let left = env.state.groups.store.channel_ids(&gid).await.unwrap();
    assert!(left.is_empty(), "{left:?}");
}

#[tokio::test]
async fn a_remote_member_is_not_its_local_namesake() {
    let bob = remote("bob", "providerb.com");
    let env = env_with_remotes(&[&bob]).await;
    let owner = local(&env, "olive").await;
    let local_bob = local(&env, "bob").await;
    let (gid, cid) = group_with(&env, &owner, "group", text("group")).await;
    join(&env, &gid, &bob, "member").await;

    let mut theirs = connect(&env, &bob).await;
    subscribed(&mut theirs, &cid).await;
    let mut ours = connect(&env, &local_bob).await;
    refused(&mut ours, &[&cid]).await;

    env.state
        .groups
        .remove_member(&gid, &bob.id())
        .await
        .unwrap();
    revoked(&env, &mut theirs, &cid).await;
}

#[tokio::test]
async fn removing_a_remote_member_spares_its_local_namesake() {
    let bob = remote("bob", "providerb.com");
    let env = env_with_remotes(&[&bob]).await;
    let owner = local(&env, "olive").await;
    let local_bob = local(&env, "bob").await;
    let (gid, cid) = group_with(&env, &owner, "group", text("group")).await;
    join(&env, &gid, &bob, "member").await;
    join(&env, &gid, &local_bob, "member").await;

    let mut theirs = connect(&env, &bob).await;
    subscribed(&mut theirs, &cid).await;
    let mut ours = connect(&env, &local_bob).await;
    subscribed(&mut ours, &cid).await;

    env.state
        .groups
        .remove_member(&gid, &bob.id())
        .await
        .unwrap();
    // Only `bob@providerb.com` loses access; `revoked`'s publish reaches
    // local bob, who is neither held nor ended.
    revoked(&env, &mut theirs, &cid).await;
    let e = ours.event().await;
    assert_eq!(e["data"], json!({"n": 1}), "{e}");
    still_live(&env, &mut ours, &cid).await;
    // And local bob is still a member as far as a fresh check goes.
    let mut again = connect(&env, &local_bob).await;
    subscribed(&mut again, &cid).await;
}
