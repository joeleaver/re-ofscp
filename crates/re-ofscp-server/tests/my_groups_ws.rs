//! `groups.updated` (spec §5.7 *My groups*; docs/decisions/0018) over real
//! WebSocket connections on a real rhypedb-server: pointer writes from any
//! device, and hosted memberships that begin, change role or end, reach
//! every connection of the user, and nothing else does.

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use common::groups::{
    Env, Party, call, create_group, env_with_remotes, group_body, id, join, local,
};
use common::harness::SIGNED_AT;
use common::my_groups::{delete, hosted, put};
use common::ws::{Client, serve};
use common::{assert_valid, schema};
use serde_json::{Value, json};

const REMOTE: &str = "https://b.example/api/groups/grp_9";
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
