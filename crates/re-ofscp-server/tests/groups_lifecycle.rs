//! Groups and channels over time, without transactions: count limits
//! under concurrent creates, the sweeper, pending rows that never outlive
//! their group, and the membership seam (§5.7). Over a real rhypedb-server.

mod common;

use axum::http::StatusCode;
use common::groups::{
    Env, call, create_channel, create_group, env_with_remotes, group_body, id, local, request,
};
use common::harness::{SIGNED_AT, send};
use re_ofscp_server::groups::ops::GroupError;
use re_ofscp_server::groups::{MAX_CHANNELS_PER_GROUP, MAX_GROUPS_PER_OWNER, PENDING_TTL, model};
use re_ofscp_types::groups::ChannelCreateRequest;
use serde_json::json;

async fn env() -> Env {
    env_with_remotes(&[]).await
}

fn now() -> i64 {
    SIGNED_AT.unix_timestamp()
}

/// A channel written by the store alone: `pending`, as a create that died
/// before confirming it leaves it.
async fn pending_channel(env: &Env, gid: &str) -> String {
    let req: ChannelCreateRequest = serde_json::from_value(json!({"type": "text"})).unwrap();
    let (kind, fields) = model::new_channel(req).unwrap();
    let store = &env.state.groups.store;
    store
        .create_channel(gid, kind, &fields, now())
        .await
        .unwrap()
        .id
}

#[tokio::test]
async fn concurrent_creates_at_the_limit_never_pass_it() {
    let env = env().await;
    let alice = local(&env, "alice").await;
    let gid = id(&create_group(&env, &alice, group_body("G", "group")).await);
    let path = format!("/api/groups/{gid}/channels");
    for _ in 0..MAX_CHANNELS_PER_GROUP - 1 {
        create_channel(&env, &alice, &gid, json!({"type": "text"})).await;
    }
    // One place left, five creates racing for it: the post-write recheck
    // decides, so at most one lands.
    let mut burst = tokio::task::JoinSet::new();
    for _ in 0..5 {
        let req = request(Some(&alice), "POST", &path, Some(&json!({"type": "text"})));
        let app = env.app.clone();
        burst.spawn(async move { send(&app, req).await.0 });
    }
    let mut created = 0;
    while let Some(s) = burst.join_next().await {
        match s.unwrap() {
            StatusCode::CREATED => created += 1,
            StatusCode::FORBIDDEN => {}
            other => panic!("unexpected {other}"),
        }
    }
    assert!(created <= 1, "{created} creates landed");
    let (_, list) = call(&env, Some(&alice), "GET", &path, None).await;
    let count = list["items"].as_array().unwrap().len();
    assert_eq!(count, MAX_CHANNELS_PER_GROUP - 1 + created);
    if count == MAX_CHANNELS_PER_GROUP {
        let (s, p) = call(
            &env,
            Some(&alice),
            "POST",
            &path,
            Some(json!({"type": "text"})),
        )
        .await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{p}");
    }
}

#[tokio::test]
async fn an_owner_holds_a_bounded_number_of_groups() {
    let env = env().await;
    let alice = local(&env, "alice").await;
    let mut last = String::new();
    for i in 0..MAX_GROUPS_PER_OWNER {
        last = id(&create_group(&env, &alice, group_body(&format!("G{i}"), "group")).await);
    }
    let (s, p) = call(
        &env,
        Some(&alice),
        "POST",
        "/api/groups",
        Some(group_body("X", "group")),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{p}");
    // A deletion frees a place at once, before the sweeper runs.
    let (s, _) = call(
        &env,
        Some(&alice),
        "DELETE",
        &format!("/api/groups/{last}"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    create_group(&env, &alice, group_body("Y", "group")).await;
}

#[tokio::test]
async fn the_sweeper_finishes_an_interrupted_deletion() {
    let env = env().await;
    let alice = local(&env, "alice").await;
    let gid = id(&create_group(&env, &alice, group_body("G", "public")).await);
    let c = id(&create_channel(&env, &alice, &gid, json!({"type": "text"})).await);
    let groups = &env.state.groups;
    // As if the process died between marking the group and purging it.
    assert!(groups.store.mark_deleting(&gid).await.unwrap());
    let (s, _) = call(
        &env,
        Some(&alice),
        "GET",
        &format!("/api/groups/{gid}"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let pending = pending_channel(&env, &gid).await;
    assert_eq!(groups.sweep(now()).await.unwrap(), 1);
    for cid in [&c, &pending] {
        assert!(
            !groups.store.activate_channel(&gid, cid).await.unwrap(),
            "{cid} survived"
        );
    }
    assert!(groups.store.channel(&gid, &c).await.unwrap().is_none());
    assert!(groups.store.deleting(10).await.unwrap().is_empty());
    assert_eq!(groups.sweep(now()).await.unwrap(), 0);
}

#[tokio::test]
async fn pending_rows_are_invisible_and_expire() {
    let env = env().await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let gid = id(&create_group(&env, &alice, group_body("G", "public")).await);
    let groups = &env.state.groups;
    let cid = pending_channel(&env, &gid).await;
    assert!(
        groups
            .store
            .add_member(&gid, &bob.id(), "admin", now())
            .await
            .unwrap()
    );

    // Neither counts before it is confirmed.
    let (s, list) = call(
        &env,
        Some(&alice),
        "GET",
        &format!("/api/groups/{gid}/channels"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(list["items"], json!([]));
    let cpath = format!("/api/groups/{gid}/channels/{cid}");
    let (s, _) = call(&env, Some(&alice), "GET", &cpath, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(groups.store.role_of(&gid, &bob.id()).await.unwrap(), None);

    // Within the TTL the sweeper leaves them; after it, they are gone.
    groups.sweep(now()).await.unwrap();
    let later = now() + PENDING_TTL.as_secs() as i64 + 1;
    groups.sweep(later).await.unwrap();
    assert!(!groups.store.activate_channel(&gid, &cid).await.unwrap());
    assert!(!groups.store.activate_member(&gid, &bob.id()).await.unwrap());
    // The expired membership no longer blocks a real one.
    assert!(
        groups
            .add_member(&gid, &bob.id(), "admin", now())
            .await
            .unwrap()
    );
    assert_eq!(
        groups
            .store
            .role_of(&gid, &bob.id())
            .await
            .unwrap()
            .as_deref(),
        Some("admin")
    );
}

#[tokio::test]
async fn memberships_refuse_the_owner_role_and_deleted_groups() {
    let env = env().await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let gid = id(&create_group(&env, &alice, group_body("G", "group")).await);
    let groups = &env.state.groups;

    let refused = groups.add_member(&gid, &bob.id(), "owner", now()).await;
    assert!(
        matches!(refused, Err(GroupError::Invalid(_))),
        "{refused:?}"
    );
    // The owner is not also a member.
    assert!(
        !groups
            .add_member(&gid, &alice.id(), "admin", now())
            .await
            .unwrap()
    );
    assert!(
        groups
            .add_member(&gid, &bob.id(), "member", now())
            .await
            .unwrap()
    );
    assert!(
        !groups
            .add_member(&gid, &bob.id(), "admin", now())
            .await
            .unwrap(),
        "already one"
    );
    let refused = groups.set_role(&gid, &bob.id(), "owner").await;
    assert!(
        matches!(refused, Err(GroupError::Invalid(_))),
        "{refused:?}"
    );
    assert_eq!(
        groups
            .store
            .role_of(&gid, &bob.id())
            .await
            .unwrap()
            .as_deref(),
        Some("member")
    );

    let (s, _) = call(
        &env,
        Some(&alice),
        "DELETE",
        &format!("/api/groups/{gid}"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let gone = groups.add_member(&gid, &bob.id(), "member", now()).await;
    assert!(matches!(gone, Err(GroupError::NotFound(_))), "{gone:?}");
    assert_eq!(groups.store.role_of(&gid, &bob.id()).await.unwrap(), None);
}
