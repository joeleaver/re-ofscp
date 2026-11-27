//! Concurrent invite redemptions (spec §5.6; docs/decisions/0019, 0012)
//! on a real rhypedb-server: a limited invite's use slots decide who gets
//! in, so concurrent redemptions never admit more than `maxUses`, and a
//! redemption that does not join gives its slot back.

mod common;

use axum::http::StatusCode;
use common::groups::{Env, Party, create_group, env_with_remotes, id, local, request};
use common::harness::send;
use common::invites::{create_invite, rows_of_group, token, uses};
use common::members::{group_with_policy, roster};
use serde_json::{Value, json};

/// Redeemers per race.
const RACERS: usize = 12;
/// Races per test: the window is narrow, so one race alone rarely opens it.
const ROUNDS: usize = 5;

async fn private_group(env: &Env, owner: &Party) -> String {
    id(&create_group(
        env,
        owner,
        group_with_policy("private", "invite", json!({})),
    )
    .await)
}

/// Every one of `who` redeems `token` at once: the statuses, in no order.
async fn race(env: &Env, who: &[&Party], token: &str) -> Vec<(StatusCode, Value)> {
    let path = format!("/api/invites/{token}/redeem");
    let mut set = tokio::task::JoinSet::new();
    for p in who {
        let req = request(Some(p), "POST", &path, Some(&json!({})));
        let app = env.app.clone();
        set.spawn(async move { send(&app, req).await });
    }
    let mut out = Vec::new();
    while let Some(r) = set.join_next().await {
        let (s, body, _, _) = r.unwrap();
        out.push((s, body));
    }
    out
}

#[tokio::test]
async fn concurrent_redemptions_of_a_single_use_invite_admit_one() {
    let env = env_with_remotes(&[]).await;
    let owner = local(&env, "olive").await;
    let mut racers = Vec::new();
    for i in 0..RACERS {
        racers.push(local(&env, &format!("racer{i}")).await);
    }
    let who: Vec<&Party> = racers.iter().collect();
    for round in 0..ROUNDS {
        let g = private_group(&env, &owner).await;
        let inv = create_invite(&env, &owner, &g, json!({"maxUses": 1})).await;
        let results = race(&env, &who, &token(&inv)).await;
        let admitted = results.iter().filter(|(s, _)| *s == StatusCode::OK).count();
        for (s, body) in &results {
            assert!(
                *s == StatusCode::OK || *s == StatusCode::CONFLICT,
                "round {round}: unexpected {s}: {body}"
            );
        }
        assert_eq!(admitted, 1, "round {round}: {results:?}");
        // The owner and exactly one racer.
        assert_eq!(roster(&env, &owner, &g).await.len(), 2, "round {round}");
        assert_eq!(rows_of_group(&env, "GroupInviteUse", &g).await, 1);
        assert_eq!(uses(&env, &owner, &g, &id(&inv)).await, 1);
    }
}

#[tokio::test]
async fn concurrent_redemptions_never_exceed_max_uses() {
    let env = env_with_remotes(&[]).await;
    let owner = local(&env, "olive").await;
    let mut racers = Vec::new();
    for i in 0..RACERS {
        racers.push(local(&env, &format!("racer{i}")).await);
    }
    let who: Vec<&Party> = racers.iter().collect();
    let g = private_group(&env, &owner).await;
    let inv = create_invite(&env, &owner, &g, json!({"maxUses": 5})).await;
    let results = race(&env, &who, &token(&inv)).await;
    let admitted = results.iter().filter(|(s, _)| *s == StatusCode::OK).count();
    assert_eq!(admitted, 5, "{results:?}");
    assert_eq!(roster(&env, &owner, &g).await.len(), 6);
    assert_eq!(uses(&env, &owner, &g, &id(&inv)).await, 5);
}

#[tokio::test]
async fn one_actor_redeeming_twice_at_once_uses_one_slot() {
    let env = env_with_remotes(&[]).await;
    let owner = local(&env, "olive").await;
    let bob = local(&env, "bob").await;
    for round in 0..ROUNDS {
        let g = private_group(&env, &owner).await;
        let inv = create_invite(&env, &owner, &g, json!({"maxUses": 3})).await;
        let results = race(&env, &[&bob, &bob, &bob], &token(&inv)).await;
        for (s, body) in &results {
            // A redemption that met the other's membership row still being
            // recorded may be told to retry; none may fail otherwise.
            assert!(
                *s == StatusCode::OK || *s == StatusCode::CONFLICT,
                "round {round}: unexpected {s}: {body}"
            );
        }
        assert!(results.iter().any(|(s, _)| *s == StatusCode::OK));
        assert_eq!(roster(&env, &owner, &g).await.len(), 2, "round {round}");
        // The redemptions that did not join gave their slots back.
        assert_eq!(uses(&env, &owner, &g, &id(&inv)).await, 1, "round {round}");
    }
}

#[tokio::test]
async fn concurrent_redemptions_of_an_unlimited_invite_are_all_counted() {
    let env = env_with_remotes(&[]).await;
    let owner = local(&env, "olive").await;
    let mut racers = Vec::new();
    for i in 0..RACERS {
        racers.push(local(&env, &format!("racer{i}")).await);
    }
    let who: Vec<&Party> = racers.iter().collect();
    let g = private_group(&env, &owner).await;
    let inv = create_invite(&env, &owner, &g, json!({})).await;
    let results = race(&env, &who, &token(&inv)).await;
    assert!(
        results.iter().all(|(s, _)| *s == StatusCode::OK),
        "{results:?}"
    );
    assert_eq!(roster(&env, &owner, &g).await.len(), RACERS + 1);
    assert_eq!(uses(&env, &owner, &g, &id(&inv)).await, RACERS as u64);
}
