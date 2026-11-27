//! Join requests against a group that changes (spec §5.7; security
//! requirement 6; docs/decisions/0020): approval stops once the group is
//! joined by invitation only, the pending-request limit holds under
//! concurrent requests, and becoming a member by any path drops the
//! request.

mod common;

use axum::http::StatusCode;
use common::groups::{Env, Party, call, create_group, id, local};
use common::harness::SIGNED_AT;
use common::members::{group_with_policy, join_http};
use re_ofscp_server::groups::MAX_PENDING_REQUESTS_PER_GROUP;
use re_ofscp_types::Actor;
use serde_json::{Value, json};

async fn request_group(env: &Env, owner: &Party) -> String {
    id(&create_group(env, owner, group_with_policy("group", "request", json!({}))).await)
}

async fn edit(env: &Env, by: &Party, g: &str, patch: Value) {
    let (s, b) = call(
        env,
        Some(by),
        "PATCH",
        &format!("/api/groups/{g}"),
        Some(patch),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}");
}

async fn review(env: &Env, by: &Party, g: &str, r: &Value, verb: &str) -> StatusCode {
    let path = format!("/api/groups/{g}/requests/{}/{verb}", id(r));
    call(env, Some(by), "POST", &path, None).await.0
}

async fn pending(env: &Env, by: &Party, g: &str) -> usize {
    let (s, list) = call(
        env,
        Some(by),
        "GET",
        &format!("/api/groups/{g}/requests"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{list}");
    list["items"].as_array().unwrap().len()
}

#[tokio::test]
async fn approval_stops_once_the_group_is_joined_by_invitation_only() {
    let env = common::groups::env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let carol = local(&env, "carol").await;

    for patch in [json!({"joinPolicy": "invite"}), json!({"tier": "private"})] {
        let g = request_group(&env, &alice).await;
        let (s, r) = join_http(&env, &bob, &g, None).await;
        assert_eq!(s, StatusCode::ACCEPTED, "{r}");
        edit(&env, &alice, &g, patch.clone()).await;
        assert_eq!(
            review(&env, &alice, &g, &r, "approve").await,
            StatusCode::CONFLICT,
            "{patch}"
        );
        // The request is kept, and may still be denied.
        assert_eq!(pending(&env, &alice, &g).await, 1);
        assert_eq!(
            review(&env, &alice, &g, &r, "deny").await,
            StatusCode::NO_CONTENT
        );
        assert_eq!(pending(&env, &alice, &g).await, 0);
    }

    // A group opened up still admits its pending requesters.
    let g = request_group(&env, &alice).await;
    let (_, r) = join_http(&env, &carol, &g, None).await;
    edit(&env, &alice, &g, json!({"joinPolicy": "open"})).await;
    assert_eq!(
        review(&env, &alice, &g, &r, "approve").await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn concurrent_requests_never_pass_the_pending_limit() {
    let env = common::groups::env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let g = request_group(&env, &alice).await;
    let store = &env.state.groups.store;
    let now = SIGNED_AT.unix_timestamp();
    let filled = MAX_PENDING_REQUESTS_PER_GROUP - 2;
    for i in 0..filled {
        let who = Actor::parse_canonical(&format!("asker{i}@providerb.example")).unwrap();
        assert!(
            store
                .create_request(&g, &who, None, now)
                .await
                .unwrap()
                .is_some()
        );
    }
    let (a, b, c) = (
        local(&env, "ann").await,
        local(&env, "ben").await,
        local(&env, "cyd").await,
    );
    let (ra, rb, rc) = tokio::join!(
        join_http(&env, &a, &g, None),
        join_http(&env, &b, &g, None),
        join_http(&env, &c, &g, None),
    );
    let mut accepted = 0;
    for (s, body) in [&ra, &rb, &rc] {
        match *s {
            StatusCode::ACCEPTED => accepted += 1,
            StatusCode::FORBIDDEN => {}
            other => panic!("{other} {body}"),
        }
    }
    let stored = store
        .request_count(&g, MAX_PENDING_REQUESTS_PER_GROUP + 5)
        .await
        .unwrap();
    assert!(stored <= MAX_PENDING_REQUESTS_PER_GROUP, "{stored}");
    assert_eq!(
        stored,
        filled + accepted,
        "every request answered 202 is kept"
    );
}

#[tokio::test]
async fn becoming_a_member_by_another_path_drops_the_pending_request() {
    let env = common::groups::env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let g = request_group(&env, &alice).await;
    let (s, _) = join_http(&env, &bob, &g, None).await;
    assert_eq!(s, StatusCode::ACCEPTED);
    // As an invitation would: the §5.7 seam.
    let now = SIGNED_AT.unix_timestamp();
    assert!(
        env.state
            .groups
            .add_member(&g, &bob.id(), "member", now)
            .await
            .unwrap()
    );
    assert_eq!(pending(&env, &alice, &g).await, 0);
    let store = &env.state.groups.store;
    assert!(
        store
            .pending_request_of(&g, &bob.id())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn an_invite_only_group_refuses_approval_even_for_a_member() {
    let env = common::groups::env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let g = request_group(&env, &alice).await;
    let (_, r) = join_http(&env, &bob, &g, None).await;
    // Bob became a member while his request stayed pending (written
    // straight to the store: every route drops the request).
    let store = &env.state.groups.store;
    let now = SIGNED_AT.unix_timestamp();
    assert!(
        store
            .add_member(&g, &bob.id(), "member", None, now)
            .await
            .unwrap()
    );
    assert!(store.activate_member(&g, &bob.id()).await.unwrap());

    // The policy is checked first (lost-conn/ofscp#39).
    edit(&env, &alice, &g, json!({"joinPolicy": "invite"})).await;
    assert_eq!(
        review(&env, &alice, &g, &r, "approve").await,
        StatusCode::CONFLICT
    );
    assert_eq!(pending(&env, &alice, &g).await, 1, "kept pending");
    // Taking requests again, the member is answered as they are.
    edit(&env, &alice, &g, json!({"joinPolicy": "request"})).await;
    let path = format!("/api/groups/{g}/requests/{}/approve", id(&r));
    let (s, m) = call(&env, Some(&alice), "POST", &path, None).await;
    assert_eq!((s, &m["user"]), (StatusCode::OK, &json!(bob.actor)), "{m}");
    assert_eq!(pending(&env, &alice, &g).await, 0);
}
