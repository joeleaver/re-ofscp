//! Concurrent edits of groups and channels: every edit that answers `200`
//! is its own revision, none undone by another (docs/decisions/0014:
//! rhypedb's filtered updates are not compare-and-set, so edits are
//! serialized by revision claims). Over a real rhypedb-server.

mod common;

use axum::http::StatusCode;
use common::groups::{Env, call, create_channel, create_group, env_with_remotes, group_body, id};
use common::groups::{local, request};
use common::harness::{SIGNED_AT, send};
use re_ofscp_server::db::Ql;
use serde::Deserialize;
use serde_json::{Value, json};

/// Concurrent edits per race.
const WRITERS: usize = 16;

/// Races per test. The window a lost update needs is narrow (inside one
/// statement on the server), so one race alone rarely opens it.
const ROUNDS: usize = 20;

async fn env() -> Env {
    env_with_remotes(&[]).await
}

#[derive(Deserialize)]
struct Revision {
    revision: i64,
}

/// The stored revision of group `gid`.
async fn group_revision(env: &Env, gid: &str) -> i64 {
    let q = Ql::new("Group.filter(.group_id == ").str(gid).raw(")");
    let rows = env.state.db.fetch::<Revision>(&q).await.unwrap();
    rows[0].data.revision
}

/// The stored revision of channel `cid`.
async fn channel_revision(env: &Env, cid: &str) -> i64 {
    let q = Ql::new("Channel.filter(.channel_id == ").str(cid).raw(")");
    let rows = env.state.db.fetch::<Revision>(&q).await.unwrap();
    rows[0].data.revision
}

/// Send `WRITERS` PATCHes to `path` at once, the `i`th with `body(i)`, as
/// `by`. Returns the bodies of those answered `200`; any other answer
/// must be `409` (the object kept changing).
async fn race(
    env: &Env,
    by: &common::groups::Party,
    path: &str,
    body: impl Fn(usize) -> Value,
) -> Vec<Value> {
    let mut set = tokio::task::JoinSet::new();
    for i in 0..WRITERS {
        let req = request(Some(by), "PATCH", path, Some(&body(i)));
        let app = env.app.clone();
        set.spawn(async move { send(&app, req).await });
    }
    let mut landed = Vec::new();
    while let Some(r) = set.join_next().await {
        let (status, body, _, _) = r.unwrap();
        match status {
            StatusCode::OK => landed.push(body),
            StatusCode::CONFLICT => {}
            other => panic!("unexpected {other}: {body}"),
        }
    }
    landed
}

#[tokio::test]
async fn sixteen_concurrent_group_patches_each_get_their_own_revision() {
    let env = env().await;
    let alice = local(&env, "alice").await;
    let g = create_group(&env, &alice, group_body("G", "group")).await;
    let gid = id(&g);
    let path = format!("/api/groups/{gid}");
    let mut revision = 0;
    for round in 0..ROUNDS {
        let landed = race(
            &env,
            &alice,
            &path,
            |i| json!({ "name": format!("n{round}.{i}") }),
        )
        .await;
        assert!(!landed.is_empty(), "no edit landed");
        // A lost update would leave two `200`s on one revision.
        revision += landed.len() as i64;
        assert_eq!(group_revision(&env, &gid).await, revision, "round {round}");
        let (_, got) = call(&env, Some(&alice), "GET", &path, None).await;
        assert!(
            landed.iter().any(|b| b["name"] == got["name"]),
            "{got} is no landed edit"
        );
    }
}

#[tokio::test]
async fn sixteen_concurrent_channel_patches_each_get_their_own_revision() {
    let env = env().await;
    let alice = local(&env, "alice").await;
    let g = create_group(&env, &alice, group_body("G", "group")).await;
    let gid = id(&g);
    let c = create_channel(&env, &alice, &gid, json!({"type": "text"})).await;
    let cid = id(&c);
    let path = format!("/api/groups/{gid}/channels/{cid}");
    let mut revision = 0;
    for round in 0..ROUNDS {
        let landed = race(
            &env,
            &alice,
            &path,
            |i| json!({ "topic": format!("t{round}.{i}") }),
        )
        .await;
        assert!(!landed.is_empty(), "no edit landed");
        revision += landed.len() as i64;
        assert_eq!(
            channel_revision(&env, &cid).await,
            revision,
            "round {round}"
        );
    }
}

#[tokio::test]
async fn concurrent_patches_of_different_fields_both_land() {
    let env = env().await;
    let alice = local(&env, "alice").await;
    let g = create_group(&env, &alice, group_body("G", "group")).await;
    let path = format!("/api/groups/{}", id(&g));
    let a = call(
        &env,
        Some(&alice),
        "PATCH",
        &path,
        Some(json!({"name": "renamed"})),
    );
    let b = call(
        &env,
        Some(&alice),
        "PATCH",
        &path,
        Some(json!({"description": "described"})),
    );
    let ((sa, _), (sb, _)) = tokio::join!(a, b);
    assert_eq!((sa, sb), (StatusCode::OK, StatusCode::OK));
    let (_, got) = call(&env, Some(&alice), "GET", &path, None).await;
    assert_eq!(got["name"], "renamed");
    assert_eq!(got["description"], "described");
}

#[tokio::test]
async fn a_live_claim_holds_off_other_edits_of_that_revision() {
    let env = env().await;
    let alice = local(&env, "alice").await;
    let g = create_group(&env, &alice, group_body("G", "group")).await;
    let gid = id(&g);
    // Another writer holds revision 1 and is (as far as anyone knows)
    // still writing it.
    let now = SIGNED_AT.unix_timestamp();
    let key = format!("group:{gid}:1");
    assert!(env.state.groups.store.claim(&key, now).await.unwrap());
    let path = format!("/api/groups/{gid}");
    let (s, p) = call(
        &env,
        Some(&alice),
        "PATCH",
        &path,
        Some(json!({"name": "x"})),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "{p}");
    assert_eq!(group_revision(&env, &gid).await, 0);
}

#[tokio::test]
async fn an_expired_claim_is_taken_over() {
    let env = env().await;
    let alice = local(&env, "alice").await;
    let g = create_group(&env, &alice, group_body("G", "group")).await;
    let gid = id(&g);
    // A writer claimed revision 1 long ago and died before writing it.
    let long_ago = SIGNED_AT.unix_timestamp() - 10 * 60;
    let key = format!("group:{gid}:1");
    assert!(env.state.groups.store.claim(&key, long_ago).await.unwrap());
    let path = format!("/api/groups/{gid}");
    let (s, p) = call(
        &env,
        Some(&alice),
        "PATCH",
        &path,
        Some(json!({"name": "x"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{p}");
    assert_eq!(group_revision(&env, &gid).await, 1);
    // The sweeper deletes claims once expired, and only those.
    let live = format!("group:{gid}:2");
    let later = SIGNED_AT.unix_timestamp() + 10 * 60;
    assert!(env.state.groups.store.claim(&live, later).await.unwrap());
    env.state.groups.sweep(later).await.unwrap();
    assert_eq!(claims(&env, &key).await, 0);
    assert_eq!(claims(&env, &live).await, 1);
}

/// How many claims hold `key`.
async fn claims(env: &Env, key: &str) -> usize {
    let q = Ql::new("GroupClaim.filter(.key == ").str(key).raw(")");
    let rows = env
        .state
        .db
        .fetch::<serde::de::IgnoredAny>(&q)
        .await
        .unwrap();
    rows.len()
}

#[tokio::test]
async fn concurrent_edits_taking_over_one_expired_claim_never_fail() {
    let env = env().await;
    let alice = local(&env, "alice").await;
    let g = create_group(&env, &alice, group_body("G", "group")).await;
    let gid = id(&g);
    // A dead writer's claim on revision 1, long expired: every edit
    // below finds it and tries to take it over at once.
    let long_ago = SIGNED_AT.unix_timestamp() - 10 * 60;
    let key = format!("group:{gid}:1");
    assert!(env.state.groups.store.claim(&key, long_ago).await.unwrap());
    let path = format!("/api/groups/{gid}");
    let landed = race(&env, &alice, &path, |i| json!({ "name": format!("n{i}") })).await;
    assert!(!landed.is_empty(), "no edit landed");
    assert_eq!(group_revision(&env, &gid).await, landed.len() as i64);
}
