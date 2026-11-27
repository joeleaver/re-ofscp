//! The group list's bounds and its federation-policy gate (spec §5.7 *My
//! groups*; docs/decisions/0018), on a real rhypedb-server: joins past
//! `MAX_MEMBERSHIPS_PER_ACTOR` are refused, a list over any bound is a
//! `500` rather than a partial list, and only remote pointers wait for the
//! federation policy.

mod common;

use axum::http::StatusCode;
use common::accounts::{EnvOptions, env_with};
use common::groups::{Env, call, create_group, env_with_remotes, group_body, id, local};
use common::harness::SIGNED_AT;
use common::my_groups::{hosted, put};
use futures_util::stream::{self, StreamExt};
use re_ofscp_server::db::Ql;
use re_ofscp_server::groups::model::new_group;
use re_ofscp_server::groups::{MAX_GROUPS_PER_OWNER, MAX_MEMBERSHIPS_PER_ACTOR};
use re_ofscp_server::my_groups::MAX_POINTERS_PER_ACTOR;
use re_ofscp_server::my_groups::store::PointerStore;
use re_ofscp_types::Actor;
use serde_json::{Value, json};

fn assert_problem(status: StatusCode, body: &Value, want: StatusCode, code: &str) {
    assert_eq!(status, want, "{body}");
    assert_eq!(body["errorCode"], code, "{body}");
}

/// Write `n` active memberships of `who` in groups `fake_{i}` straight to
/// the database: the count, not the groups, is what is limited.
async fn memberships(env: &Env, who: &Actor, n: usize) {
    let actor = who.to_string();
    let now = SIGNED_AT.unix_timestamp();
    stream::iter(0..n)
        .for_each_concurrent(16, |i| {
            let actor = actor.clone();
            async move {
                let group = format!("grp_fake{i}");
                let q = Ql::new("Membership.create({ key: ")
                    .str(&format!("{group} {actor}"))
                    .raw(", group_id: ")
                    .str(&group)
                    .raw(", actor: ")
                    .str(&actor)
                    .raw(", role: \"member\", status: \"active\", joined_at: ")
                    .unix_seconds(now)
                    .raw(" })");
                env.state.db.execute(&q).await.unwrap();
            }
        })
        .await;
}

async fn list_status(env: &Env, by: &common::groups::Party) -> (StatusCode, Value) {
    call(env, Some(by), "GET", "/api/me/groups", None).await
}

#[tokio::test]
async fn a_join_beyond_the_membership_limit_is_refused() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let gid = id(&create_group(&env, &alice, group_body("Home", "public")).await);
    let other = id(&create_group(&env, &alice, group_body("Other", "public")).await);
    let now = SIGNED_AT.unix_timestamp();
    let groups = &env.state.groups;
    assert!(
        groups
            .add_member(&other, &bob.id(), "member", now)
            .await
            .unwrap()
    );
    memberships(&env, &bob.id(), MAX_MEMBERSHIPS_PER_ACTOR - 1).await;

    let err = groups
        .add_member(&gid, &bob.id(), "member", now)
        .await
        .unwrap_err();
    assert!(
        matches!(err, re_ofscp_server::groups::ops::GroupError::Forbidden(_)),
        "{err:?}"
    );
    assert_eq!(groups.store.role_of(&gid, &bob.id()).await.unwrap(), None);
    // An existing membership is still one, at the limit.
    assert!(
        !groups
            .add_member(&other, &bob.id(), "member", now)
            .await
            .unwrap()
    );
    // The list is whole at the limit.
    let (s, body) = list_status(&env, &bob).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(
        body["groups"],
        json!([{
            "group": hosted(&other),
            "role": "member",
            "updatedAt": body["groups"][0]["updatedAt"],
        }])
    );
    // Leaving one makes room.
    groups.remove_member(&other, &bob.id()).await.unwrap();
    assert!(
        groups
            .add_member(&gid, &bob.id(), "member", now)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn a_list_over_the_membership_limit_is_500_not_partial() {
    let env = env_with_remotes(&[]).await;
    let bob = local(&env, "bob").await;
    memberships(&env, &bob.id(), MAX_MEMBERSHIPS_PER_ACTOR + 1).await;
    let (s, b) = list_status(&env, &bob).await;
    assert_problem(s, &b, StatusCode::INTERNAL_SERVER_ERROR, "internal_error");
}

#[tokio::test]
async fn a_list_over_the_owned_group_limit_is_500_not_partial() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let now = SIGNED_AT.unix_timestamp();
    let store = &env.state.groups.store;
    for i in 0..=MAX_GROUPS_PER_OWNER {
        let req = serde_json::from_value(group_body(&format!("G{i}"), "public")).unwrap();
        let fields = new_group(req).unwrap();
        store.create_group(&alice.id(), &fields, now).await.unwrap();
    }
    let (s, b) = list_status(&env, &alice).await;
    assert_problem(s, &b, StatusCode::INTERNAL_SERVER_ERROR, "internal_error");
}

#[tokio::test]
async fn a_list_over_the_pointer_limit_is_500_not_partial() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let store = PointerStore::new(env.state.db.clone());
    let now = SIGNED_AT.unix_timestamp();
    let owner = alice.id();
    stream::iter(0..=MAX_POINTERS_PER_ACTOR)
        .for_each_concurrent(16, |i| {
            let (store, owner) = (&store, &owner);
            async move {
                let uri = format!("https://b.example/api/groups/g{i}");
                store.create(owner, &uri, None, now).await.unwrap();
            }
        })
        .await;
    let (s, b) = list_status(&env, &alice).await;
    assert_problem(s, &b, StatusCode::INTERNAL_SERVER_ERROR, "internal_error");
}

#[tokio::test]
async fn only_remote_puts_wait_for_the_federation_policy() {
    let env = env_with(EnvOptions {
        no_federation: true,
        ..Default::default()
    })
    .await;
    let alice = local(&env, "alice").await;
    let gid = id(&create_group(&env, &alice, group_body("Home", "public")).await);

    // A hosted group involves no other provider.
    let (s, own) = put(&env, &alice, &hosted(&gid), None).await;
    assert_eq!(s, StatusCode::OK, "{own}");
    assert_eq!(own["role"], "owner");
    // A remote one is refused until the policy is known.
    let remote = "https://b.example/api/groups/grp_9";
    let (s, b) = put(&env, &alice, remote, None).await;
    assert_problem(
        s,
        &b,
        StatusCode::SERVICE_UNAVAILABLE,
        "service_unavailable",
    );
    env.state.load_federation().await.unwrap();
    let (s, b) = put(&env, &alice, remote, None).await;
    assert_eq!(s, StatusCode::OK, "{b}");
}
