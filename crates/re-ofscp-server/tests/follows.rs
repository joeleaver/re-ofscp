//! Follows (spec §7.6; docs/decisions/0022; security requirements 1 and
//! 5), on a real rhypedb-server: `GET`/`POST /api/me/follows` and `DELETE
//! /api/me/follows/{channelRef}`.

mod common;

use axum::http::StatusCode;
use common::follows::{follow, list, remote_follows, unfollow};
use common::groups::{Env, Party, call, env_with_remotes, join, local, remote};
use common::members::kick;
use common::messages::{Chan, group_and_channel, public_channel};
use common::my_groups::segment;
use common::ws::denying;
use common::{assert_valid, schema};
use re_ofscp_server::follows::MAX_FOLLOWS_PER_ACTOR;
use re_ofscp_server::follows::store::FollowStore;
use re_ofscp_types::Authority;
use serde_json::{Value, json};

const REMOTE: &str = "https://b.example/api/groups/grp_2/channels/chn_9";
const REMOTE_GROUP: &str = "https://b.example/api/groups/grp_2";

fn assert_problem(status: StatusCode, body: &Value, want: StatusCode, code: &str) {
    assert_eq!(status, want, "{body}");
    assert_eq!(body["errorCode"], code, "{body}");
}

fn channels(follows: &[Value]) -> Vec<&str> {
    follows
        .iter()
        .map(|f| f["channel"].as_str().unwrap())
        .collect()
}

/// A channel in a `group`-tier group owned by `owner`, readable by members.
async fn members_channel(env: &Env, owner: &Party) -> Chan {
    group_and_channel(
        env,
        owner,
        "group",
        json!({}),
        json!({"type": "text", "tier": "group"}),
    )
    .await
}

#[tokio::test]
async fn remote_and_unsigned_callers_are_refused_on_every_route() {
    let carol = remote("carol", "b.example");
    let env = env_with_remotes(&[&carol]).await;
    let path = format!("/api/me/follows/{}", segment(REMOTE));
    for (method, path, body) in [
        ("GET", "/api/me/follows", None),
        ("POST", "/api/me/follows", Some(json!({"channel": REMOTE}))),
        ("DELETE", path.as_str(), None),
    ] {
        let (s, b) = call(&env, Some(&carol), method, path, body.clone()).await;
        assert_problem(s, &b, StatusCode::FORBIDDEN, "forbidden");
        let (s, b) = call(&env, None, method, path, body).await;
        assert_problem(s, &b, StatusCode::UNAUTHORIZED, "unauthorized");
    }
    let store = FollowStore::new(env.state.db.clone());
    assert!(store.list(&carol.id(), 10).await.unwrap().is_empty());
}

#[tokio::test]
async fn every_spelling_of_a_channel_is_one_follow() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let chan = public_channel(&env, &alice).await;
    let local_uri = format!("https://PROVIDERA.com:443{}", chan.channel());

    let (s, f) = follow(&env, &alice, &chan.c).await;
    assert_eq!(s, StatusCode::CREATED, "{f}");
    assert_valid(&schema("follow.json"), &f);
    assert_eq!(f["channel"], chan.c.as_str());
    assert_eq!(f["groupId"], chan.g.as_str());
    assert_eq!(f["createdAt"], "2026-01-01T12:00:00Z");
    assert_eq!(f["metadata"], json!([]));
    // The local channel's URI names the same follow: 200, not a second one.
    let (s, again) = follow(&env, &alice, &local_uri).await;
    assert_eq!((s, &again), (StatusCode::OK, &f));

    // A remote channel is stored canonical, with its group's URI.
    let (s, r) = follow(
        &env,
        &alice,
        "https://B.Example.:443/api/groups/grp_2/channels/chn_9",
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{r}");
    assert_valid(&schema("follow.json"), &r);
    assert_eq!(r["channel"], REMOTE);
    assert_eq!(r["groupId"], REMOTE_GROUP);
    let (s, _) = follow(&env, &alice, REMOTE).await;
    assert_eq!(s, StatusCode::OK);

    assert_eq!(
        channels(&list(&env, &alice).await),
        [chan.c.as_str(), REMOTE]
    );
    // Unfollowing by either spelling removes it; again is still 204.
    assert_eq!(
        unfollow(&env, &alice, &local_uri).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        unfollow(
            &env,
            &alice,
            "https://b.example./api/groups/grp_2/channels/chn_9"
        )
        .await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(unfollow(&env, &alice, REMOTE).await, StatusCode::NO_CONTENT);
    assert!(list(&env, &alice).await.is_empty());
}

#[tokio::test]
async fn malformed_requests_are_400_and_unreadable_channels_404() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let hidden = members_channel(&env, &alice).await;
    let open = public_channel(&env, &alice).await;

    for body in [
        json!({}),
        json!({"channel": ""}),
        json!({"channel": 7}),
        json!({"channel": "chn_1", "groupId": 1}),
        json!({"channel": "http://b.example/api/groups/g/channels/c"}),
        json!({"channel": "https://b.example/api/groups/g"}),
    ] {
        let (s, b) = call(&env, Some(&bob), "POST", "/api/me/follows", Some(body)).await;
        assert_problem(s, &b, StatusCode::BAD_REQUEST, "bad_request");
    }
    assert_eq!(
        unfollow(&env, &bob, "https://b.example/api/groups/g").await,
        StatusCode::BAD_REQUEST
    );

    // A channel bob cannot read is indistinguishable from none (§11.3).
    let hidden_uri = format!("https://providera.com{}", hidden.channel());
    for channel in [hidden.c.as_str(), hidden_uri.as_str(), "chn_nosuch"] {
        let (s, b) = follow(&env, &bob, channel).await;
        assert_problem(s, &b, StatusCode::NOT_FOUND, "not_found");
    }
    // A local URI naming the wrong group names no channel.
    let wrong = format!(
        "https://providera.com/api/groups/{}/channels/{}",
        hidden.g, open.c
    );
    let (s, b) = follow(&env, &bob, &wrong).await;
    assert_problem(s, &b, StatusCode::NOT_FOUND, "not_found");
    assert!(list(&env, &bob).await.is_empty());

    // Once a member, bob can follow it.
    join(&env, &hidden.g, &bob, "member").await;
    let (s, _) = follow(&env, &bob, &hidden.c).await;
    assert_eq!(s, StatusCode::CREATED);
}

#[tokio::test]
async fn a_follow_is_listed_only_while_its_channel_is_readable() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let chan = members_channel(&env, &alice).await;
    join(&env, &chan.g, &bob, "member").await;
    let (s, _) = follow(&env, &bob, &chan.c).await;
    assert_eq!(s, StatusCode::CREATED);
    let (s, _) = follow(&env, &bob, REMOTE).await;
    assert_eq!(s, StatusCode::CREATED);

    // Kicked: the local follow disappears from the list (requirement 5),
    // but is kept, so it is back once bob is.
    assert_eq!(
        kick(&env, &alice, &chan.g, "bob").await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(channels(&list(&env, &bob).await), [REMOTE]);
    let store = FollowStore::new(env.state.db.clone());
    assert_eq!(store.list(&bob.id(), 10).await.unwrap().len(), 2);
    join(&env, &chan.g, &bob, "member").await;
    assert_eq!(channels(&list(&env, &bob).await), [chan.c.as_str(), REMOTE]);

    // A deleted channel's follow is pruned.
    let (s, _) = call(&env, Some(&alice), "DELETE", &chan.channel(), None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(channels(&list(&env, &bob).await), [REMOTE]);
    let rows = store.list(&bob.id(), 10).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].channel, REMOTE);
}

#[tokio::test]
async fn the_federation_policy_gates_new_remote_follows_only() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let (s, _) = follow(&env, &alice, REMOTE).await;
    assert_eq!(s, StatusCode::CREATED);
    let policy = env.state.federation.policy();
    policy.install(denying(&Authority::parse_canonical("b.example").unwrap()));

    let (s, b) = follow(
        &env,
        &alice,
        "https://b.example/api/groups/grp_2/channels/chn_8",
    )
    .await;
    assert_problem(s, &b, StatusCode::FORBIDDEN, "forbidden");
    // A malformed request is still 400, whatever the policy.
    let (s, b) = call(
        &env,
        Some(&alice),
        "POST",
        "/api/me/follows",
        Some(json!({})),
    )
    .await;
    assert_problem(s, &b, StatusCode::BAD_REQUEST, "bad_request");
    // Local channels and other providers are unaffected; the existing
    // follow is still listed, and can always be removed.
    let chan = public_channel(&env, &alice).await;
    assert_eq!(follow(&env, &alice, &chan.c).await.0, StatusCode::CREATED);
    let other = "https://c.example/api/groups/g/channels/c";
    assert_eq!(follow(&env, &alice, other).await.0, StatusCode::CREATED);
    // Follows made in the same second are listed by channel.
    assert_eq!(
        channels(&list(&env, &alice).await),
        [chan.c.as_str(), REMOTE, other]
    );
    assert_eq!(unfollow(&env, &alice, REMOTE).await, StatusCode::NO_CONTENT);
    assert_eq!(
        channels(&list(&env, &alice).await),
        [chan.c.as_str(), other]
    );
}

#[tokio::test]
async fn follows_beyond_the_limit_are_refused_unless_stale_ones_can_go() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let chan = members_channel(&env, &alice).await;
    join(&env, &chan.g, &bob, "member").await;
    assert_eq!(follow(&env, &bob, &chan.c).await.0, StatusCode::CREATED);
    remote_follows(&env, &bob, MAX_FOLLOWS_PER_ACTOR - 1).await;

    let (s, b) = follow(&env, &bob, REMOTE).await;
    assert_problem(s, &b, StatusCode::CONFLICT, "conflict");
    // Following what is already followed is not a new follow.
    assert_eq!(follow(&env, &bob, &chan.c).await.0, StatusCode::OK);
    assert_eq!(list(&env, &bob).await.len(), MAX_FOLLOWS_PER_ACTOR);

    // Once bob cannot read the local channel, its hidden follow makes room.
    assert_eq!(
        kick(&env, &alice, &chan.g, "bob").await,
        StatusCode::NO_CONTENT
    );
    let (s, f) = follow(&env, &bob, REMOTE).await;
    assert_eq!(s, StatusCode::CREATED, "{f}");
    let store = FollowStore::new(env.state.db.clone());
    let rows = store
        .list(&bob.id(), MAX_FOLLOWS_PER_ACTOR + 1)
        .await
        .unwrap();
    assert_eq!(rows.len(), MAX_FOLLOWS_PER_ACTOR);
    assert!(rows.iter().all(|r| r.channel != chan.c));
}

#[tokio::test]
async fn a_list_over_the_limit_is_a_500_not_a_partial_list() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    remote_follows(&env, &alice, MAX_FOLLOWS_PER_ACTOR + 1).await;
    let (s, b) = call(&env, Some(&alice), "GET", "/api/me/follows", None).await;
    assert_problem(s, &b, StatusCode::INTERNAL_SERVER_ERROR, "internal_error");
}
