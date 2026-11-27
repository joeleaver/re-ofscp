//! Concurrent follows (spec §7.6; docs/decisions/0022) on a real
//! rhypedb-server: one row per followed channel however many requests
//! race, and never more follows than the per-user limit.

mod common;

use axum::http::StatusCode;
use common::follows::{follow, list, remote_channel, remote_follows};
use common::groups::{env_with_remotes, local};
use common::races::RACERS;
use futures_util::future::join_all;
use re_ofscp_server::follows::MAX_FOLLOWS_PER_ACTOR;
use re_ofscp_server::follows::store::FollowStore;

#[tokio::test]
async fn concurrent_follows_of_one_channel_make_one_row() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let channel = remote_channel(7);
    let answers = join_all((0..RACERS).map(|_| follow(&env, &alice, &channel))).await;
    let created = answers
        .iter()
        .filter(|(s, _)| *s == StatusCode::CREATED)
        .count();
    let existing = answers.iter().filter(|(s, _)| *s == StatusCode::OK).count();
    assert_eq!((created, existing), (1, RACERS - 1), "{answers:?}");
    // Every answer is the one stored follow.
    let first = &answers[0].1;
    assert!(answers.iter().all(|(_, f)| f == first), "{answers:?}");
    let rows = FollowStore::new(env.state.db.clone())
        .list(&alice.id(), MAX_FOLLOWS_PER_ACTOR + 1)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(list(&env, &alice).await.len(), 1);
}

#[tokio::test]
async fn concurrent_follows_at_the_limit_admit_exactly_one() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    remote_follows(&env, &alice, MAX_FOLLOWS_PER_ACTOR - 1).await;
    // Channels not among the ones already followed.
    let channels: Vec<String> = (0..RACERS)
        .map(|i| remote_channel(MAX_FOLLOWS_PER_ACTOR + i))
        .collect();
    let answers = join_all(channels.iter().map(|c| follow(&env, &alice, c))).await;
    let created = answers
        .iter()
        .filter(|(s, _)| *s == StatusCode::CREATED)
        .count();
    let refused = answers
        .iter()
        .filter(|(s, b)| *s == StatusCode::CONFLICT && b["errorCode"] == "conflict")
        .count();
    assert_eq!((created, refused), (1, RACERS - 1), "{answers:?}");
    let rows = FollowStore::new(env.state.db.clone())
        .list(&alice.id(), MAX_FOLLOWS_PER_ACTOR + 1)
        .await
        .unwrap();
    assert_eq!(rows.len(), MAX_FOLLOWS_PER_ACTOR);
    // The one admitted is listed; the limit holds from then on.
    assert_eq!(list(&env, &alice).await.len(), MAX_FOLLOWS_PER_ACTOR);
    let (s, _) = follow(&env, &alice, &remote_channel(5 * MAX_FOLLOWS_PER_ACTOR)).await;
    assert_eq!(s, StatusCode::CONFLICT);
}
