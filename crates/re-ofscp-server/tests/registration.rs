//! Registration by account invite (spec §4.1.1, lost-conn/ofscp#18) and the
//! auth endpoints' body limit, against a real rhypedb-server.

mod common;

use axum::http::StatusCode;
use common::accounts::*;
use common::harness::*;
use re_ofscp_server::accounts::invites::token_hash;
use re_ofscp_server::accounts::{CreateError, Held, InviteError};
use serde_json::{Value, json};

fn now() -> i64 {
    SIGNED_AT.unix_timestamp()
}

async fn invite(env: &Env, handle: Option<&str>) -> String {
    env.state
        .accounts
        .create_invite(handle, None, "admin:test", now())
        .await
        .unwrap()
        .token
}

/// Register with a schema-valid request body.
async fn register(env: &Env, body: Value, ip: &str) -> (StatusCode, Value) {
    common::assert_valid(&common::schema("auth-registration-request.json"), &body);
    register_unchecked(env, body, ip).await
}

/// Register with any body, valid or not.
async fn register_unchecked(env: &Env, body: Value, ip: &str) -> (StatusCode, Value) {
    let (s, j, _, _) = send(&env.app, post_json("/api/auth/register", body, ip)).await;
    (s, j)
}

fn assert_problem(s: StatusCode, j: &Value, status: StatusCode, code: &str) {
    assert_eq!(s, status, "{j}");
    common::assert_valid(&common::schema("problem-details.json"), j);
    assert_eq!(j["errorCode"], code);
    assert_eq!(
        j["type"],
        format!("https://providera.com/problems/{code}"),
        "{j}"
    );
}

#[tokio::test]
async fn an_invite_registers_an_account_once() {
    let env = env().await;
    let token = invite(&env, None).await;

    let (s, boot) = register(
        &env,
        json!({"handle": "carol", "password": "correct horse battery", "inviteToken": token}),
        "10.2.0.1",
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{boot}");
    common::assert_valid(&common::schema("auth-bootstrap-response.json"), &boot);

    // The bootstrap token registers a device key, and the password logs in.
    let (s, created) = register_key(
        &env,
        boot["bootstrap_token"].as_str().unwrap(),
        &new_key(),
        "10.2.0.1",
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{created}");
    let (s, _, _) = login(&env, "carol", "correct horse battery", "10.2.0.1").await;
    assert_eq!(s, StatusCode::OK);
    let carol = env.state.accounts.store.find_user("carol").await.unwrap();
    assert_eq!(carol.unwrap().display_name, "carol");

    // Spent: a retry (or anyone else) gets invite_required.
    let (s, j) = register(
        &env,
        json!({"handle": "dave", "password": "correct horse battery", "inviteToken": token}),
        "10.2.0.2",
    )
    .await;
    assert_problem(s, &j, StatusCode::FORBIDDEN, "invite_required");
}

#[tokio::test]
async fn without_a_usable_invite_nothing_about_handles_is_revealed() {
    let env = env().await;
    create(&env, "taken", "correct horse battery").await;
    let expired = env
        .state
        .accounts
        .create_invite(None, Some(10), "admin:test", now() - 100)
        .await
        .unwrap()
        .token;
    let pinned = invite(&env, Some("erin")).await;

    let mut answers = Vec::new();
    for (i, body) in [
        json!({"handle": "fresh", "password": "correct horse battery"}),
        json!({"handle": "taken", "password": "correct horse battery"}),
        json!({"handle": "NOT VALID", "password": "short"}),
        json!({"handle": "taken", "password": "correct horse battery", "inviteToken": "ai_bogus"}),
        json!({"handle": "taken", "password": "correct horse battery", "inviteToken": "bt_other"}),
        json!({"handle": "fresh", "password": "correct horse battery", "inviteToken": expired}),
        json!({"handle": "fresh", "password": "correct horse battery", "inviteToken": pinned}),
    ]
    .into_iter()
    .enumerate()
    {
        // (One body is not even schema-valid: the invite is still checked
        // first.)
        let (s, j) = register_unchecked(&env, body, &format!("10.2.1.{i}")).await;
        assert_problem(s, &j, StatusCode::FORBIDDEN, "invite_required");
        answers.push(j);
    }
    // One indistinguishable answer for every case.
    assert!(answers.windows(2).all(|w| w[0] == w[1]), "{answers:?}");

    // The pinned invite still works for its own handle.
    let (s, j) = register(
        &env,
        json!({"handle": "erin", "password": "correct horse battery", "inviteToken": pinned}),
        "10.2.1.9",
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
}

#[tokio::test]
async fn a_failed_registration_leaves_the_invite_usable() {
    let env = env().await;
    create(&env, "taken", "correct horse battery").await;
    let token = invite(&env, None).await;

    let (s, j) = register(
        &env,
        json!({"handle": "taken", "password": "correct horse battery", "inviteToken": token}),
        "10.2.2.1",
    )
    .await;
    assert_problem(s, &j, StatusCode::CONFLICT, "conflict");
    for (i, body) in [
        json!({"handle": "Bad Handle", "password": "correct horse battery", "inviteToken": token}),
        json!({"handle": "guest_x", "password": "correct horse battery", "inviteToken": token}),
        json!({"handle": "frank", "password": "x".repeat(1025), "inviteToken": token}),
    ]
    .into_iter()
    .enumerate()
    {
        let (s, j) = register(&env, body, &format!("10.2.2.{}", i + 2)).await;
        assert_problem(s, &j, StatusCode::BAD_REQUEST, "bad_request");
    }

    let (s, j) = register(
        &env,
        json!({"handle": "frank", "password": "correct horse battery", "inviteToken": token}),
        "10.2.2.9",
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
}

#[tokio::test]
async fn concurrent_registrations_cannot_share_an_invite() {
    let env = env().await;
    let token = invite(&env, None).await;
    let mut tasks = tokio::task::JoinSet::new();
    for i in 0..6 {
        let app = env.app.clone();
        let req = post_json(
            "/api/auth/register",
            json!({"handle": format!("racer{i}"), "password": "correct horse battery", "inviteToken": token}),
            &format!("10.2.3.{i}"),
        );
        tasks.spawn(async move { send(&app, req).await.0 });
    }
    let statuses: Vec<StatusCode> = tasks.join_all().await;
    let created = statuses
        .iter()
        .filter(|s| **s == StatusCode::CREATED)
        .count();
    assert_eq!(created, 1, "{statuses:?}");
    assert!(
        statuses
            .iter()
            .all(|s| *s == StatusCode::CREATED || *s == StatusCode::FORBIDDEN)
    );
}

#[tokio::test]
async fn a_closed_provider_refuses_every_registration() {
    let env = env_with(EnvOptions {
        registration: Some("closed"),
        ..EnvOptions::default()
    })
    .await;
    let token = invite(&env, None).await;
    for (i, body) in [
        json!({"handle": "mallory", "password": "password123"}),
        json!({"handle": "mallory", "password": "password123", "inviteToken": token}),
    ]
    .into_iter()
    .enumerate()
    {
        let (s, j) = register(&env, body, &format!("10.2.4.{i}")).await;
        assert_problem(s, &j, StatusCode::FORBIDDEN, "registration_closed");
    }
}

#[tokio::test]
async fn unknown_fields_are_rejected() {
    let env = env().await;
    let (s, j, _, _) = send(
        &env.app,
        post_json(
            "/api/auth/register",
            json!({"handle": "carol", "password": "correct horse battery", "admin": true}),
            "10.2.5.1",
        ),
    )
    .await;
    assert_problem(s, &j, StatusCode::BAD_REQUEST, "bad_request");
}

#[tokio::test]
async fn invites_are_validated_when_issued() {
    let env = env().await;
    create(&env, "taken", "correct horse battery").await;
    let a = &env.state.accounts;
    let t = now();
    assert_eq!(
        a.create_invite(Some("guest_x"), None, "admin:test", t)
            .await,
        Err(InviteError::InvalidHandle(CreateError::ReservedHandle))
    );
    assert_eq!(
        a.create_invite(Some("taken"), None, "admin:test", t).await,
        Err(InviteError::HandleTaken)
    );
    assert_eq!(
        a.create_invite(None, Some(0), "admin:test", t).await,
        Err(InviteError::InvalidLifetime)
    );
    assert_eq!(
        a.create_invite(None, Some(31 * 86_400), "admin:test", t)
            .await,
        Err(InviteError::InvalidLifetime)
    );
    let issued = a
        .create_invite(Some("grace"), None, "admin:test", t)
        .await
        .unwrap();
    assert_eq!(
        issued.link,
        format!("https://providera.com/register?invite={}", issued.token)
    );
    assert_eq!(issued.handle.as_deref(), Some("grace"));
    assert_eq!(issued.expires_at, t + 7 * 86_400);
}

#[tokio::test]
async fn auth_bodies_are_capped() {
    let env = env().await;
    let big = json!({"handle": "carol", "password": "x".repeat(20 * 1024)});
    for path in [
        "/api/auth/login",
        "/api/auth/register",
        "/api/auth/device-keys",
    ] {
        let (s, j, _, _) = send(&env.app, post_json(path, big.clone(), "10.2.6.1")).await;
        assert_problem(s, &j, StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large");
    }
}

/// A registration whose request redeemed the invite (and marked it used)
/// but crashed before making the account: only the same handle resumes it,
/// and once the account exists the invite is spent for good.
#[tokio::test]
async fn a_used_invite_resumes_only_its_own_unmade_handle() {
    let env = env().await;
    let token = invite(&env, None).await;
    let hash = token_hash(&token).unwrap();
    assert!(
        env.state
            .accounts
            .invites
            .redeem(&hash, "dave", now())
            .await
            .unwrap()
    );
    let (s, j) = register(
        &env,
        json!({"handle": "erin", "password": "correct horse battery", "inviteToken": token}),
        "10.2.7.1",
    )
    .await;
    assert_problem(s, &j, StatusCode::FORBIDDEN, "invite_required");
    let (s, j) = register(
        &env,
        json!({"handle": "dave", "password": "correct horse battery", "inviteToken": token}),
        "10.2.7.2",
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let (s, _, _) = login(&env, "dave", "correct horse battery", "10.2.7.2").await;
    assert_eq!(s, StatusCode::OK);
    // Used by dave, whose account now exists: spent, even for dave.
    let (s, j) = register(
        &env,
        json!({"handle": "dave", "password": "correct horse battery", "inviteToken": token}),
        "10.2.7.3",
    )
    .await;
    assert_problem(s, &j, StatusCode::FORBIDDEN, "invite_required");
}

/// A registration that crashed after holding its handle: the pending
/// account cannot log in and has no profile; a retry with its invite and
/// another password is a rival (409), and one with the same password
/// finishes it.
#[tokio::test]
async fn a_stranded_registration_is_finished_by_its_own_retry() {
    let env = env().await;
    let token = invite(&env, None).await;
    let hash = token_hash(&token).unwrap();
    let accounts = &env.state.accounts;
    let phc = accounts
        .passwords
        .hash("correct horse battery")
        .await
        .unwrap();
    let held = accounts
        .store
        .create_pending("frank", "frank", &phc, &hash, now())
        .await
        .unwrap();
    assert!(matches!(held, Held::Created(_)));
    let (s, _, _) = login(&env, "frank", "correct horse battery", "10.2.8.1").await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert!(
        env.state
            .profiles
            .store
            .profile("frank")
            .await
            .unwrap()
            .is_none()
    );
    let summary = accounts.store.summary("frank").await.unwrap().unwrap();
    assert_eq!(summary.status, "pending");

    let (s, j) = register(
        &env,
        json!({"handle": "frank", "password": "another long password", "inviteToken": token}),
        "10.2.8.2",
    )
    .await;
    assert_problem(s, &j, StatusCode::CONFLICT, "conflict");
    let (s, j) = register(
        &env,
        json!({"handle": "frank", "password": "correct horse battery", "inviteToken": token}),
        "10.2.8.3",
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let (s, _, _) = login(&env, "frank", "correct horse battery", "10.2.8.4").await;
    assert_eq!(s, StatusCode::OK);
    let summary = accounts.store.summary("frank").await.unwrap().unwrap();
    assert_eq!(summary.status, "active");
}
