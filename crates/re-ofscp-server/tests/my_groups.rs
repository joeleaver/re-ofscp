//! The user's group list at their home provider (spec §5.7 *My groups*;
//! docs/decisions/0018; security requirements 1 and 3), on a real
//! rhypedb-server: `GET /api/me/groups` and `PUT`/`DELETE
//! /api/me/groups/{groupRef}`.

mod common;

use axum::http::StatusCode;
use common::groups::{
    Env, call, create_group, env_with_remotes, group_body, id, join, local, remote,
};
use common::harness::SIGNED_AT;
use common::members::set_role;
use common::my_groups::{delete, hosted, list, pointer_path, put, uris};
use common::ws::denying;
use common::{assert_valid, schema};
use re_ofscp_server::my_groups::MAX_POINTERS_PER_ACTOR;
use re_ofscp_server::my_groups::store::PointerStore;
use re_ofscp_types::Authority;
use serde_json::{Value, json};

const REMOTE: &str = "https://b.example/api/groups/grp_9";

fn assert_problem(status: StatusCode, body: &Value, want: StatusCode, code: &str) {
    assert_eq!(status, want, "{body}");
    assert_eq!(body["errorCode"], code, "{body}");
}

async fn env() -> Env {
    env_with_remotes(&[]).await
}

#[tokio::test]
async fn remote_and_unsigned_callers_are_refused_on_every_route() {
    let carol = remote("carol", "b.example");
    let env = env_with_remotes(&[&carol]).await;
    let path = pointer_path(REMOTE);
    for (method, path, body) in [
        ("GET", "/api/me/groups", None),
        ("PUT", path.as_str(), Some(json!({"role": "member"}))),
        ("DELETE", path.as_str(), None),
    ] {
        let (s, b) = call(&env, Some(&carol), method, path, body.clone()).await;
        assert_problem(s, &b, StatusCode::FORBIDDEN, "forbidden");
        let (s, b) = call(&env, None, method, path, body).await;
        assert_problem(s, &b, StatusCode::UNAUTHORIZED, "unauthorized");
    }
    // Nothing was recorded for the remote signer.
    let store = PointerStore::new(env.state.db.clone());
    assert!(store.list(&carol.id(), 10).await.unwrap().is_empty());
}

#[tokio::test]
async fn a_pointer_is_stored_with_a_canonical_authority_and_listed() {
    let env = env().await;
    let alice = local(&env, "alice").await;
    assert!(list(&env, &alice).await.is_empty());

    let (s, p) = put(
        &env,
        &alice,
        "https://B.Example:443/api/groups/grp_9",
        Some(json!({"role": "member"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{p}");
    assert_valid(&schema("group-pointer.json"), &p);
    assert_eq!(p["group"], REMOTE);
    assert_eq!(p["role"], "member");
    assert_eq!(p["updatedAt"], "2026-01-01T12:00:00Z");

    // Every spelling of the authority names the same pointer.
    let (s, again) = put(
        &env,
        &alice,
        "https://b.example./api/groups/grp_9",
        Some(json!({"role": "member"})),
    )
    .await;
    assert_eq!((s, &again), (StatusCode::OK, &p));
    let (s, ported) = put(
        &env,
        &alice,
        "https://b.example:8443/api/groups/grp_9",
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{ported}");
    assert_eq!(ported["group"], "https://b.example:8443/api/groups/grp_9");
    assert!(ported.get("role").is_none(), "{ported}");

    let (s, body) = call(&env, Some(&alice), "GET", "/api/me/groups", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_valid(&schema("group-pointers-response.json"), &body);
    assert_eq!(body["metadata"], json!([]));
    assert_eq!(
        uris(body["groups"].as_array().unwrap()),
        vec![
            REMOTE.to_owned(),
            "https://b.example:8443/api/groups/grp_9".to_owned()
        ]
    );
    // Another user's list is their own.
    let bob = local(&env, "bob").await;
    assert!(list(&env, &bob).await.is_empty());
}

#[tokio::test]
async fn a_put_that_changes_nothing_keeps_updated_at() {
    let env = env().await;
    let alice = local(&env, "alice").await;
    let (_, first) = put(&env, &alice, REMOTE, Some(json!({"role": "member"}))).await;

    env.clock.set(SIGNED_AT + time::Duration::seconds(60));
    let (s, same) = put(&env, &alice, REMOTE, Some(json!({"role": "member"}))).await;
    assert_eq!((s, &same), (StatusCode::OK, &first));

    let (s, changed) = put(&env, &alice, REMOTE, Some(json!({"role": "admin"}))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(changed["role"], "admin");
    assert_eq!(changed["updatedAt"], "2026-01-01T12:01:00Z");

    // No body records the pointer without a hint (PUT replaces it).
    env.clock.set(SIGNED_AT + time::Duration::seconds(120));
    let (s, bare) = put(&env, &alice, REMOTE, None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(bare.get("role").is_none(), "{bare}");
    assert_eq!(bare["updatedAt"], "2026-01-01T12:02:00Z");
    assert_eq!(list(&env, &alice).await, vec![bare]);
}

#[tokio::test]
async fn a_hosted_entry_dates_from_its_role_change_or_transfer() {
    let env = env().await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let gid = id(&create_group(&env, &alice, group_body("Home", "public")).await);
    let uri = hosted(&gid);
    join(&env, &gid, &bob, "member").await;

    env.clock.set(SIGNED_AT + time::Duration::seconds(60));
    let (s, m) = set_role(&env, &alice, &gid, &bob.actor, "admin").await;
    assert_eq!(s, StatusCode::OK, "{m}");
    let (_, entry) = put(&env, &bob, &uri, None).await;
    assert_eq!(entry["role"], "admin");
    assert_eq!(entry["updatedAt"], "2026-01-01T12:01:00Z");

    // A transfer dates both parties' entries (`Group.owner_since` for the
    // new owner, the former owner's new row for them).
    env.clock.set(SIGNED_AT + time::Duration::seconds(120));
    let (s, m) = set_role(&env, &alice, &gid, &bob.actor, "owner").await;
    assert_eq!(s, StatusCode::OK, "{m}");
    let (_, entry) = put(&env, &bob, &uri, None).await;
    assert_eq!(entry["role"], "owner");
    assert_eq!(entry["updatedAt"], "2026-01-01T12:02:00Z");
    let (_, entry) = put(&env, &alice, &uri, None).await;
    assert_eq!(entry["role"], "admin");
    assert_eq!(entry["updatedAt"], "2026-01-01T12:02:00Z");
}

#[tokio::test]
async fn malformed_refs_and_bodies_are_400_and_record_nothing() {
    let env = env().await;
    let alice = local(&env, "alice").await;
    for bad in [
        "grp_9",
        "alice@b.example",
        "http://b.example/api/groups/grp_9",
        "https://b.example/api/groups/",
        "https://b.example/api/groups/grp_9/channels/chn_1",
        "https://b.example/api/groups/grp_9?x=1",
        "https://b.example/api/groups/grp_9#x",
        "https://b.example/api/users/alice",
        "https://u@b.example/api/groups/grp_9",
        "https://b..example/api/groups/grp_9",
    ] {
        let (s, b) = put(&env, &alice, bad, Some(json!({"role": "member"}))).await;
        assert_problem(s, &b, StatusCode::BAD_REQUEST, "bad_request");
        let (s, b) = delete(&env, &alice, bad).await;
        assert_problem(s, &b, StatusCode::BAD_REQUEST, "bad_request");
    }
    for body in [
        json!({"role": null}),
        json!({"role": 3}),
        json!({"role": ["member"]}),
        json!({"role": {}}),
        json!({"role": ""}),
        json!([]),
        json!("member"),
    ] {
        let (s, b) = put(&env, &alice, REMOTE, Some(body)).await;
        assert_problem(s, &b, StatusCode::BAD_REQUEST, "bad_request");
    }
    assert!(list(&env, &alice).await.is_empty());
}

#[tokio::test]
async fn a_denied_provider_is_403_after_the_400_checks() {
    let env = env().await;
    let alice = local(&env, "alice").await;
    let policy = env.state.federation.policy();
    policy.install(denying(&Authority::parse_canonical("b.example").unwrap()));

    let (s, b) = put(&env, &alice, "https://B.EXAMPLE/api/groups/grp_9", None).await;
    assert_problem(s, &b, StatusCode::FORBIDDEN, "forbidden");
    // A malformed request is still 400, whatever the policy.
    let (s, b) = put(&env, &alice, REMOTE, Some(json!({"role": 1}))).await;
    assert_problem(s, &b, StatusCode::BAD_REQUEST, "bad_request");
    assert!(list(&env, &alice).await.is_empty());
    // Other providers are unaffected, and removing a pointer always works.
    let (s, _) = put(&env, &alice, "https://c.example/api/groups/g", None).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = delete(&env, &alice, REMOTE).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn hosted_groups_are_derived_from_membership_never_stored() {
    let env = env().await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let carol = local(&env, "carol").await;
    let gid = id(&create_group(&env, &alice, group_body("Home", "public")).await);
    let uri = hosted(&gid);

    // The owner's entry: role `owner`, also for a non-canonical spelling.
    let shouty = format!("https://PROVIDERA.COM:443/api/groups/{gid}");
    let (s, own) = put(&env, &alice, &shouty, Some(json!({"role": "member"}))).await;
    assert_eq!(s, StatusCode::OK, "{own}");
    assert_valid(&schema("group-pointer.json"), &own);
    assert_eq!(own["group"], uri);
    assert_eq!(own["role"], "owner");

    // Not a member: 404; a member: their current role, the hint ignored.
    let (s, b) = put(&env, &bob, &uri, None).await;
    assert_problem(s, &b, StatusCode::NOT_FOUND, "not_found");
    join(&env, &gid, &bob, "member").await;
    let (s, entry) = put(&env, &bob, &uri, Some(json!({"role": "admin"}))).await;
    assert_eq!(s, StatusCode::OK, "{entry}");
    assert_eq!(entry["role"], "member");
    let (s, b) = put(
        &env,
        &carol,
        "https://providera.com/api/groups/grp_nope",
        None,
    )
    .await;
    assert_problem(s, &b, StatusCode::NOT_FOUND, "not_found");

    // Nothing was stored for a hosted group.
    let store = PointerStore::new(env.state.db.clone());
    assert!(store.list(&alice.id(), 10).await.unwrap().is_empty());
    assert!(store.list(&bob.id(), 10).await.unwrap().is_empty());

    // A member or the owner cannot remove it this way; anyone else may.
    let (s, b) = delete(&env, &bob, &uri).await;
    assert_problem(s, &b, StatusCode::CONFLICT, "conflict");
    let (s, b) = delete(&env, &alice, &uri).await;
    assert_problem(s, &b, StatusCode::CONFLICT, "conflict");
    let (s, _) = delete(&env, &carol, &uri).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn the_list_holds_every_hosted_membership_and_every_pointer() {
    let env = env().await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let owned = id(&create_group(&env, &alice, group_body("Owned", "private")).await);
    let joined = id(&create_group(&env, &bob, group_body("Joined", "group")).await);
    let other = id(&create_group(&env, &bob, group_body("Other", "public")).await);
    join(&env, &joined, &alice, "admin").await;
    let (s, _) = put(&env, &alice, REMOTE, Some(json!({"role": "guest"}))).await;
    assert_eq!(s, StatusCode::OK);

    let (s, body) = call(&env, Some(&alice), "GET", "/api/me/groups", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_valid(&schema("group-pointers-response.json"), &body);
    let entries = body["groups"].as_array().unwrap();
    let roles: Vec<(String, String)> = entries
        .iter()
        .map(|e| {
            (
                e["group"].as_str().unwrap().to_owned(),
                e["role"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    let mut want = vec![
        (hosted(&owned), "owner".to_owned()),
        (hosted(&joined), "admin".to_owned()),
    ];
    want.sort();
    want.push((REMOTE.to_owned(), "guest".to_owned()));
    assert_eq!(roles, want);
    assert!(!uris(entries).contains(&hosted(&other)));

    // A deleted group leaves the list; a membership ended leaves it too.
    let (s, _) = call(
        &env,
        Some(&alice),
        "DELETE",
        &format!("/api/groups/{owned}"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    env.state
        .groups
        .remove_member(&joined, &alice.id())
        .await
        .unwrap();
    assert_eq!(uris(&list(&env, &alice).await), vec![REMOTE.to_owned()]);
}

#[tokio::test]
async fn delete_removes_a_pointer_and_is_204_when_there_is_none() {
    let env = env().await;
    let alice = local(&env, "alice").await;
    let (s, _) = put(&env, &alice, REMOTE, None).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = delete(&env, &alice, "https://B.example:443/api/groups/grp_9").await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(list(&env, &alice).await.is_empty());
    let (s, _) = delete(&env, &alice, REMOTE).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn pointers_beyond_the_provider_limit_are_refused() {
    let env = env().await;
    let alice = local(&env, "alice").await;
    let store = PointerStore::new(env.state.db.clone());
    let now = SIGNED_AT.unix_timestamp();
    for i in 0..MAX_POINTERS_PER_ACTOR {
        let uri = format!("https://b.example/api/groups/g{i}");
        store.create(&alice.id(), &uri, None, now).await.unwrap();
    }
    let (s, b) = put(&env, &alice, "https://c.example/api/groups/one_more", None).await;
    assert_problem(s, &b, StatusCode::CONFLICT, "conflict");
    // Existing pointers can still be changed and removed.
    let (s, _) = put(
        &env,
        &alice,
        "https://b.example/api/groups/g0",
        Some(json!({"role": "member"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = delete(&env, &alice, "https://b.example/api/groups/g1").await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = put(&env, &alice, "https://c.example/api/groups/one_more", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(list(&env, &alice).await.len(), MAX_POINTERS_PER_ACTOR);
}
