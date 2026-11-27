//! `groups.updated` (spec §5.7 *My groups*; docs/decisions/0018) over real
//! WebSocket connections on a real rhypedb-server: pointer writes from any
//! device, and hosted memberships that begin, change role or end, reach
//! every connection of the user, and nothing else does.

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use common::accounts::{EnvOptions, env_with};
use common::groups::{
    Env, Party, call, create_group, env_with_remotes, group_body, id, join, local,
};
use common::harness::SIGNED_AT;
use common::my_groups::{delete, hosted, put};
use common::ws::{Client, serve};
use common::{assert_valid, schema};
use futures_util::stream::{self, StreamExt};
use re_ofscp_server::db::Ql;
use re_ofscp_types::Actor;
use serde_json::{Value, json};

const REMOTE: &str = "https://b.example/api/groups/grp_9";
const QUIET: Duration = Duration::from_millis(300);

async fn connect(env: &Env, who: &Party) -> Client {
    connect_from(env, who, "10.0.0.2").await
}

/// The next event, which must be a valid `groups.updated`; its `data`.
async fn updated(c: &mut Client) -> Value {
    let e = c.event().await;
    assert_eq!(e["type"], "groups.updated", "{e}");
    assert!(e.get("correlationId").is_none(), "{e}");
    assert_valid(&schema("ws/groups-updated.json"), &e);
    e["data"].clone()
}

#[tokio::test]
async fn pointer_writes_reach_every_connection_of_the_user() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let mut phone = connect(&env, &alice).await;
    let mut laptop = connect(&env, &alice).await;
    let mut other = connect(&env, &bob).await;

    let (s, p) = put(&env, &alice, REMOTE, Some(json!({"role": "member"}))).await;
    assert_eq!(s, StatusCode::OK);
    for c in [&mut phone, &mut laptop] {
        assert_eq!(
            updated(c).await,
            json!({"groups": [p.clone()], "removed": []})
        );
    }

    // A PUT that changes nothing emits nothing.
    let (s, _) = put(
        &env,
        &alice,
        "https://B.EXAMPLE/api/groups/grp_9",
        Some(json!({"role": "member"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(phone.silent_for(QUIET).await);

    let (_, changed) = put(&env, &alice, REMOTE, Some(json!({"role": "admin"}))).await;
    assert_eq!(updated(&mut laptop).await["groups"], json!([changed]));
    assert_eq!(updated(&mut phone).await["groups"], json!([changed]));

    let (s, _) = delete(&env, &alice, REMOTE).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    for c in [&mut phone, &mut laptop] {
        assert_eq!(updated(c).await, json!({"groups": [], "removed": [REMOTE]}));
    }
    // Deleting what is not there emits nothing, and no one else heard any of it.
    let (s, _) = delete(&env, &alice, REMOTE).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(phone.silent_for(QUIET).await);
    assert!(other.silent_for(QUIET).await);
}

#[tokio::test]
async fn hosted_memberships_announce_their_changes() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let gid = id(&create_group(&env, &alice, group_body("Home", "public")).await);
    let uri = hosted(&gid);
    let mut c = connect(&env, &bob).await;

    join(&env, &gid, &bob, "member").await;
    let data = updated(&mut c).await;
    assert_eq!(data["groups"][0]["group"], uri.as_str());
    assert_eq!(data["groups"][0]["role"], "member");
    assert_eq!(data["removed"], json!([]));

    assert!(
        env.state
            .groups
            .set_role(&gid, &bob.id(), "admin")
            .await
            .unwrap()
    );
    assert_eq!(updated(&mut c).await["groups"][0]["role"], "admin");

    // A group-settings change leaves the entry as it was.
    let (s, _) = call(
        &env,
        Some(&alice),
        "PATCH",
        &format!("/api/groups/{gid}"),
        Some(json!({"name": "Renamed"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(c.silent_for(QUIET).await);

    env.state
        .groups
        .remove_member(&gid, &bob.id())
        .await
        .unwrap();
    assert_eq!(
        updated(&mut c).await,
        json!({"groups": [], "removed": [uri]})
    );
}

#[tokio::test]
async fn deleting_a_group_removes_it_from_every_member_and_the_owner() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let gid = id(&create_group(&env, &alice, group_body("Home", "private")).await);
    let uri = hosted(&gid);
    join(&env, &gid, &bob, "member").await;
    let mut owner = connect(&env, &alice).await;
    let mut member = connect(&env, &bob).await;

    let (s, _) = call(
        &env,
        Some(&alice),
        "DELETE",
        &format!("/api/groups/{gid}"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    for c in [&mut owner, &mut member] {
        let data = updated(c).await;
        assert_eq!(data["removed"], json!([uri]), "{data}");
        assert_eq!(data["groups"], json!([]));
    }
}

#[tokio::test]
async fn a_remote_members_changes_reach_no_local_connection() {
    let carol = common::groups::remote("carol", "b.example");
    let env = env_with_remotes(&[&carol]).await;
    let alice = local(&env, "alice").await;
    let gid = id(&create_group(&env, &alice, group_body("Home", "public")).await);
    let mut owner = connect(&env, &alice).await;
    join(&env, &gid, &carol, "member").await;
    assert!(owner.silent_for(QUIET).await);
}

/// More members than the `AccessChange` broadcast buffers (1,024).
const CROWD: usize = 1_100;

/// Add `n` members `member{i}@providera.com` to `gid` straight through `Groups`
/// (no accounts: a membership needs none).
async fn crowd(env: &Env, gid: &str, n: usize) {
    let now = SIGNED_AT.unix_timestamp();
    let groups = &env.state.groups;
    stream::iter(0..n)
        .for_each_concurrent(16, |i| async move {
            let who = Actor::parse_canonical(&format!("member{i}@providera.com")).unwrap();
            assert!(groups.add_member(gid, &who, "member", now).await.unwrap());
        })
        .await;
}

/// [`connect`] from client address `ip` (each address has its own cap).
async fn connect_from(env: &Env, who: &Party, ip: &str) -> Client {
    let addr = serve(env.app.clone()).await;
    let mut c = Client::connect(addr, ip).await;
    c.authenticate(
        &who.actor,
        &who.key_id,
        &who.key,
        SIGNED_AT.unix_timestamp(),
    )
    .await;
    c
}

#[tokio::test]
async fn deleting_a_crowded_group_tells_each_connected_member_and_no_one_else() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let carol = local(&env, "carol").await;
    let erin = local(&env, "erin").await;
    let gid = id(&create_group(&env, &alice, group_body("Crowd", "public")).await);
    let uri = hosted(&gid);
    join(&env, &gid, &bob, "member").await;
    crowd(&env, &gid, CROWD).await;
    join(&env, &gid, &carol, "member").await;
    let mut owner = connect_from(&env, &alice, "10.0.1.1").await;
    let mut first = connect_from(&env, &bob, "10.0.1.2").await;
    let mut last = connect_from(&env, &carol, "10.0.1.3").await;
    let mut outsider = connect_from(&env, &erin, "10.0.1.4").await;

    let (s, _) = call(
        &env,
        Some(&alice),
        "DELETE",
        &format!("/api/groups/{gid}"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    for c in [&mut owner, &mut first, &mut last] {
        assert_eq!(updated(c).await, json!({"groups": [], "removed": [uri]}));
    }
    // A non-member hears nothing and stays connected: a pointer write
    // still reaches her.
    assert!(outsider.silent_for(QUIET).await);
    let (s, p) = put(&env, &erin, REMOTE, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(updated(&mut outsider).await["groups"], json!([p]));
    // Every membership went with the group.
    let m0 = Actor::parse_canonical("member0@providera.com").unwrap();
    for who in [bob.id(), carol.id(), m0] {
        let left = env.state.groups.hosted_entries(&who).await.unwrap();
        assert!(left.is_empty(), "{left:?}");
    }
    assert!(
        env.state
            .groups
            .store
            .deleting(10)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn the_sweeper_names_members_an_interrupted_deletion_ended() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let carol = local(&env, "carol").await;
    let gid = id(&create_group(&env, &alice, group_body("Home", "public")).await);
    let uri = hosted(&gid);
    join(&env, &gid, &bob, "member").await;
    join(&env, &gid, &carol, "member").await;
    let mut ended = connect_from(&env, &bob, "10.0.2.1").await;
    let mut active = connect_from(&env, &carol, "10.0.2.2").await;
    let mut owner = connect_from(&env, &alice, "10.0.2.3").await;

    // A deletion that stopped after hiding the group and ending bob's
    // membership, without naming him (its write failed after committing).
    let groups = &env.state.groups;
    assert!(groups.store.mark_deleting(&gid).await.unwrap());
    let q = Ql::new("Membership.filter(.group_id == ")
        .str(&gid)
        .raw(" && .actor == ")
        .str(&bob.actor)
        .raw(").update({ status: \"ended\" })");
    env.state.db.execute(&q).await.unwrap();
    // Removing an ended membership leaves it for the sweeper to name.
    groups.store.remove_member(&gid, &bob.id()).await.unwrap();

    assert_eq!(groups.sweep(SIGNED_AT.unix_timestamp()).await.unwrap(), 1);
    for c in [&mut ended, &mut active, &mut owner] {
        let data = updated(c).await;
        assert_eq!(data["removed"], json!([uri]), "{data}");
    }
    assert!(groups.store.deleting(10).await.unwrap().is_empty());
}

#[tokio::test]
async fn a_full_backlog_closes_only_that_members_connections() {
    let env = env_with(EnvOptions {
        group_list_backlog: Some(0),
        ..Default::default()
    })
    .await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let carol = local(&env, "carol").await;
    let gid = id(&create_group(&env, &alice, group_body("Home", "public")).await);
    let mut joined = connect_from(&env, &bob, "10.0.3.1").await;
    let mut other = connect_from(&env, &carol, "10.0.3.2").await;

    join(&env, &gid, &bob, "member").await;
    let (code, events) = joined.closed().await;
    assert_eq!(code, 1013);
    assert_eq!(events.len(), 1, "{events:?}");
    let e = &events[0];
    assert_eq!(e["type"], "error", "{e}");
    assert_eq!(e["data"]["code"], "too_many_requests", "{e}");
    assert_eq!(e["data"]["status"], 429, "{e}");
    assert!(e["data"]["details"]["retryAfter"].is_u64(), "{e}");
    // Carol's connection is untouched, and pointer events need no backlog.
    assert!(other.silent_for(QUIET).await);
    let (s, p) = put(&env, &carol, REMOTE, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(updated(&mut other).await["groups"], json!([p]));
}
