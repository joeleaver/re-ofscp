//! Membership changes over live WebSocket subscriptions (spec §5.7, §7.1
//! "Losing access"; security requirements 5 and 7): leaving, being kicked
//! or demoted out of a channel's `view` ends the subscription with
//! `access_revoked`; role and nickname changes emit `member.updated` to the
//! group's channel subscribers and the member's own connections; and an
//! event published right after a revoking commit, before the group
//! follower has applied it, never reaches the revoked subscriber
//! (decision 0010, "The window between a commit and its hold").

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use common::groups::{
    Env, Party, call, create_channel, create_group, env_with_remotes, id, join, local, remote,
};
use common::harness::SIGNED_AT;
use common::members::{group_with_policy, kick, leave, members, nickname, set_role};
use common::ws::{Client, serve};
use common::{assert_valid, schema};
use re_ofscp_types::wire::Member;
use serde_json::{Value, json};

const QUIET: Duration = Duration::from_millis(300);

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

async fn subscribed(c: &mut Client, channel: &str) {
    c.command("subscribe", json!({"channels": [channel]})).await;
    let ack = c.event().await;
    assert_eq!(ack["type"], "subscribed", "{ack}");
    assert_eq!(ack["data"]["channels"], json!([channel]), "{ack}");
}

/// The next event of type `kind`, skipping others (such as
/// `groups.updated`, which the member's own connections also receive).
async fn next_of(c: &mut Client, kind: &str) -> Value {
    loop {
        let e = c.event().await;
        if e["type"] == kind {
            return e;
        }
    }
}

/// Expect `channel`'s subscription ended for lost access, and nothing
/// published to it afterwards to arrive.
async fn revoked(env: &Env, c: &mut Client, channel: &str) {
    let e = next_of(c, "unsubscribed").await;
    assert_eq!(
        e["data"],
        json!({"channels": [channel], "reason": "access_revoked"})
    );
    env.state
        .ws
        .publish(channel, "message.created", json!({"n": 1}));
    assert!(c.silent_for(QUIET).await);
}

/// An open group-tier group owned by `owner`, with one channel visible to
/// `view` (all members when `None`): (group, channel).
async fn group_with(env: &Env, owner: &Party, view: Option<&str>) -> (String, String) {
    let g = id(&create_group(env, owner, group_with_policy("group", "open", json!({}))).await);
    let mut channel = json!({"type": "text", "tier": "group"});
    if let Some(v) = view {
        channel["permissions"] = json!({"view": [v]});
    }
    let c = id(&create_channel(env, owner, &g, channel).await);
    (g, c)
}

#[tokio::test]
async fn leaving_ends_the_members_subscriptions() {
    let bob = remote("bob", "providerb.example");
    let env = env_with_remotes(&[&bob]).await;
    let alice = local(&env, "alice").await;
    let (g, ch) = group_with(&env, &alice, None).await;
    let (s, _) = call(
        &env,
        Some(&bob),
        "POST",
        &format!("/api/groups/{g}/join"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    let mut c = connect(&env, &bob).await;
    subscribed(&mut c, &ch).await;
    assert_eq!(leave(&env, &bob, &g).await, StatusCode::NO_CONTENT);
    revoked(&env, &mut c, &ch).await;
}

#[tokio::test]
async fn being_kicked_ends_the_subscriptions() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let mia = local(&env, "mia").await;
    let (g, ch) = group_with(&env, &alice, None).await;
    join(&env, &g, &mia, "member").await;
    let mut c = connect(&env, &mia).await;
    subscribed(&mut c, &ch).await;
    assert_eq!(kick(&env, &alice, &g, "mia").await, StatusCode::NO_CONTENT);
    revoked(&env, &mut c, &ch).await;
}

#[tokio::test]
async fn a_demotion_out_of_view_revokes_and_tells_everyone_watching() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let mia = local(&env, "mia").await;
    let (g, ch) = group_with(&env, &alice, Some("admin")).await;
    join(&env, &g, &mia, "admin").await;
    let mut c = connect(&env, &mia).await;
    let mut o = connect(&env, &alice).await;
    subscribed(&mut c, &ch).await;
    subscribed(&mut o, &ch).await;

    let (s, _) = set_role(&env, &alice, &g, "mia", "member").await;
    assert_eq!(s, StatusCode::OK);
    // Mia's subscription ends, and her own connection is told of the
    // change once, though no channel subscription carries it to her any
    // more. The two may arrive in either order.
    let mut seen = Vec::new();
    while seen.len() < 2 {
        let e = c.event().await;
        let kind = e["type"].as_str().unwrap_or_default().to_owned();
        match kind.as_str() {
            "unsubscribed" => assert_eq!(
                e["data"],
                json!({"channels": [&ch], "reason": "access_revoked"})
            ),
            "member.updated" => assert_eq!(e["data"]["member"]["role"], "member"),
            _ => continue,
        }
        assert!(!seen.contains(&kind), "{kind} twice");
        seen.push(kind);
    }
    env.state
        .ws
        .publish(&ch, "message.created", json!({"n": 1}));
    assert!(c.silent_for(QUIET).await);
    // The owner, still able to read the channel, sees the change.
    let e = next_of(&mut o, "member.updated").await;
    assert_valid(&schema("ws/member-updated.json"), &e);
    assert_eq!(e["data"]["groupId"], json!(g));
    assert_eq!(
        (&e["data"]["member"]["user"], &e["data"]["member"]["role"]),
        (&json!(mia.actor), &json!("member"))
    );
}

#[tokio::test]
async fn nickname_changes_reach_subscribers_and_the_member_once_each() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let mia = local(&env, "mia").await;
    let (g, ch) = group_with(&env, &alice, None).await;
    join(&env, &g, &mia, "member").await;
    let mut mine = connect(&env, &mia).await;
    let mut o = connect(&env, &alice).await;
    subscribed(&mut o, &ch).await;

    let (s, _) = nickname(&env, &mia, &g, "mia", json!({"displayNameOverride": "M"})).await;
    assert_eq!(s, StatusCode::OK);
    let e = next_of(&mut o, "member.updated").await;
    assert_eq!(e["data"]["member"]["displayNameOverride"], "M");
    let e = next_of(&mut mine, "member.updated").await;
    assert_eq!(e["data"]["member"]["displayNameOverride"], "M");
    // Setting the same value changes nothing and says nothing.
    nickname(&env, &mia, &g, "mia", json!({"displayNameOverride": "M"})).await;
    assert!(o.silent_for(QUIET).await);
}

#[tokio::test]
async fn an_event_published_before_the_follower_applies_a_revocation_is_not_leaked() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let mia = local(&env, "mia").await;
    let bob = local(&env, "bob").await;
    let (g, ch) = group_with(&env, &alice, None).await;
    join(&env, &g, &mia, "member").await;
    join(&env, &g, &bob, "member").await;
    let mut c = connect(&env, &mia).await;
    let mut o = connect(&env, &alice).await;
    subscribed(&mut c, &ch).await;
    subscribed(&mut o, &ch).await;
    let (s, page) = members(&env, Some(&alice), &g, "?limit=100").await;
    assert_eq!(s, StatusCode::OK, "{page}");
    let bob_member: Member = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["user"] == json!(bob.actor))
        .map(|m| serde_json::from_value(m.clone()).unwrap())
        .unwrap();

    // Commit the removal through the store alone: no announcement, so the
    // follower never holds mia's subscription (as if it were paused). Her
    // subscription is still registered when bob's `member.updated` goes out.
    env.state
        .groups
        .store
        .remove_member(&g, &mia.id())
        .await
        .unwrap();
    env.state
        .ws
        .member_updated(&env.state.groups, &g, &bob_member)
        .await;
    let e = next_of(&mut o, "member.updated").await;
    assert_eq!(
        e["data"]["member"]["user"],
        json!(bob.actor),
        "a reader gets it"
    );
    assert!(
        c.silent_for(QUIET).await,
        "nothing reaches the revoked subscriber"
    );
}

#[tokio::test]
async fn handing_the_group_on_revokes_the_former_owners_view() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let mia = local(&env, "mia").await;
    // Only members (and the owner, who holds everything) see the channel.
    let (g, ch) = group_with(&env, &alice, Some("member")).await;
    join(&env, &g, &mia, "member").await;
    let mut c = connect(&env, &alice).await;
    subscribed(&mut c, &ch).await;

    let (s, m) = set_role(&env, &alice, &g, "mia", "owner").await;
    assert_eq!(s, StatusCode::OK, "{m}");
    // Alice is an admin now, which the channel's `view` leaves out. Her own
    // connection is also told of her new role (and of mia's), so skip those.
    let e = next_of(&mut c, "unsubscribed").await;
    assert_eq!(
        e["data"],
        json!({"channels": [&ch], "reason": "access_revoked"})
    );
    env.state
        .ws
        .publish(&ch, "message.created", json!({"n": 1}));
    while let Ok(e) = tokio::time::timeout(QUIET, c.event()).await {
        assert_eq!(e["type"], "member.updated", "nothing from the channel: {e}");
    }
}
