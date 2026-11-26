//! Group memberships as the visibility policy sees them (§6.1
//! `sharedGroups`, §6.5 `GET /api/users/{userRef}/groups`), answered from
//! this provider's own groups. Over a real rhypedb-server; responses are
//! validated against the spec's schemas.

mod common;

use axum::http::StatusCode;
use common::groups::{
    Env, Party, call, create_group, env_with_remotes, group_body, id, join, local, remote,
};
use re_ofscp_server::privacy::Viewer;
use serde_json::{Value, json};

fn uri(gid: &str) -> String {
    format!("https://providera.com/api/groups/{gid}")
}

/// `GET /api/users/alice/groups` as `viewer`: the listed object URIs.
async fn listed(env: &Env, viewer: Option<&Party>) -> Vec<String> {
    let (s, body) = call(env, viewer, "GET", "/api/users/alice/groups", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    common::assert_valid(&common::schema("user-groups-response.json"), &body);
    let mut ids: Vec<String> = body["groups"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g["id"].as_str().unwrap().to_owned())
        .collect();
    ids.sort();
    ids
}

async fn membership_visibility(env: &Env, who: &Party, visibility: &str) {
    let body: Value = json!({ "membershipVisibility": visibility });
    let (s, p) = call(env, Some(who), "PUT", "/api/me/privacy", Some(body)).await;
    assert_eq!(s, StatusCode::OK, "{p}");
}

fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v
}

#[tokio::test]
async fn a_listing_shows_only_the_groups_the_viewer_may_read() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let carol = local(&env, "carol").await;
    let dave = local(&env, "dave").await;
    // Alice owns an open group and a members-only one, and is a member of
    // Dave's private group, which Bob also belongs to.
    let open = id(&create_group(&env, &alice, group_body("Open", "public")).await);
    let closed = id(&create_group(&env, &alice, group_body("Closed", "group")).await);
    let daves = id(&create_group(&env, &dave, group_body("Dave's", "private")).await);
    join(&env, &daves, &alice, "member").await;
    join(&env, &daves, &bob, "member").await;
    membership_visibility(&env, &alice, "public").await;

    let everything = sorted(vec![uri(&open), uri(&closed), uri(&daves)]);
    assert_eq!(listed(&env, Some(&alice)).await, everything);
    // Bob shares Dave's group; Alice's members-only group stays unknown.
    assert_eq!(
        listed(&env, Some(&bob)).await,
        sorted(vec![uri(&open), uri(&daves)])
    );
    // Strangers and anonymous viewers see only the open group.
    assert_eq!(listed(&env, Some(&carol)).await, vec![uri(&open)]);
    assert_eq!(listed(&env, None).await, vec![uri(&open)]);
    // Dave, owner of the private group, sees it and the open one.
    assert_eq!(
        listed(&env, Some(&dave)).await,
        sorted(vec![uri(&open), uri(&daves)])
    );

    // A deleted group drops out at once.
    let path = format!("/api/groups/{daves}");
    let (s, _) = call(&env, Some(&dave), "DELETE", &path, None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(
        listed(&env, Some(&alice)).await,
        sorted(vec![uri(&open), uri(&closed)])
    );
}

#[tokio::test]
async fn shared_groups_admit_exactly_who_shares_one() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let carol = local(&env, "carol").await;
    let g = id(&create_group(&env, &alice, group_body("G", "group")).await);
    join(&env, &g, &bob, "member").await;
    // membershipVisibility defaults to sharedGroups (§6.6).
    assert_eq!(listed(&env, Some(&bob)).await, vec![uri(&g)]);
    assert!(listed(&env, Some(&carol)).await.is_empty());
    assert!(listed(&env, None).await.is_empty());
}

#[tokio::test]
async fn sharing_a_group_is_by_full_actor_identity() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let bob_elsewhere = remote("bob", "providerb.com");
    let g = id(&create_group(&env, &alice, group_body("G", "group")).await);
    join(&env, &g, &bob_elsewhere, "member").await;
    let groups = &env.state.groups;
    // bob@providerb.com shares the group with Alice; bob@providera.com
    // does not, despite the handle (security requirement 1).
    assert!(
        groups
            .share_a_group(&alice.id(), &bob_elsewhere.id())
            .await
            .unwrap()
    );
    assert!(!groups.share_a_group(&alice.id(), &bob.id()).await.unwrap());
    assert!(!groups.share_a_group(&bob.id(), &alice.id()).await.unwrap());
    // The remote member sees the members-only group in Alice's list; the
    // local namesake does not.
    let viewer = Viewer::Actor(bob_elsewhere.id());
    assert_eq!(
        groups
            .groups_visible_to(&alice.id(), &viewer)
            .await
            .unwrap(),
        vec![uri(&g)]
    );
    let namesake = Viewer::Actor(bob.id());
    assert!(
        groups
            .groups_visible_to(&alice.id(), &namesake)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn pending_memberships_and_deleted_groups_share_nothing() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let carol = local(&env, "carol").await;
    let groups = &env.state.groups;
    // Bob's membership is written but never confirmed (a writer that died).
    let g = id(&create_group(&env, &alice, group_body("G", "group")).await);
    let now = common::harness::SIGNED_AT.unix_timestamp();
    assert!(
        groups
            .store
            .add_member(&g, &bob.id(), "member", now)
            .await
            .unwrap()
    );
    assert!(!groups.share_a_group(&alice.id(), &bob.id()).await.unwrap());
    // Carol is a member until the group is deleted.
    join(&env, &g, &carol, "member").await;
    assert!(
        groups
            .share_a_group(&alice.id(), &carol.id())
            .await
            .unwrap()
    );
    let path = format!("/api/groups/{g}");
    let (s, _) = call(&env, Some(&alice), "DELETE", &path, None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(
        !groups
            .share_a_group(&alice.id(), &carol.id())
            .await
            .unwrap()
    );
    assert!(
        !groups
            .share_a_group(&carol.id(), &alice.id())
            .await
            .unwrap()
    );
}
