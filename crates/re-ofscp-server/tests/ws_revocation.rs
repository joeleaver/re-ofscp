//! Revoking a local key (logout, §4.7.1–§4.7.2) or disabling an account
//! closes the live WebSocket connections it authenticated with 4003, over
//! a real rhypedb-server.

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use common::accounts::{Env, NOW, create, env, login, register_key};
use common::harness::{SIGNED_AT, new_key, send, signed};
use common::ws::{Client, serve};
use ed25519_dalek::SigningKey;
use serde_json::json;

/// A device key for `handle`, registered through login: its id.
async fn device(env: &Env, handle: &str, key: &SigningKey) -> String {
    let (_, boot, _) = login(env, handle, "correct horse battery", "10.0.0.1").await;
    let token = boot["bootstrap_token"].as_str().unwrap();
    let (status, created) = register_key(env, token, key, "10.0.0.1").await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    created["key_id"].as_str().unwrap().to_owned()
}

async fn connect(env: &Env, actor: &str, key_id: &str, key: &SigningKey) -> Client {
    let addr = serve(env.app.clone()).await;
    let mut c = Client::connect(addr, "10.0.0.2").await;
    c.authenticate(actor, key_id, key, SIGNED_AT.unix_timestamp())
        .await;
    c
}

async fn assert_open(c: &mut Client) {
    c.command("ping", json!({})).await;
    assert_eq!(c.event().await["type"], "pong");
}

#[tokio::test]
async fn logging_out_closes_that_keys_connections_only() {
    let env = env().await;
    create(&env, "alice", "correct horse battery").await;
    let (laptop, phone) = (new_key(), new_key());
    let laptop_id = device(&env, "alice", &laptop).await;
    let phone_id = device(&env, "alice", &phone).await;
    let mut on_laptop = connect(&env, "alice@providera.com", &laptop_id, &laptop).await;
    let mut on_phone = connect(&env, "alice@providera.com", &phone_id, &phone).await;

    let path = format!("/api/auth/device-keys/{laptop_id}");
    let req = signed(
        &laptop,
        "alice@providera.com",
        &laptop_id,
        "DELETE",
        &path,
        "",
        NOW,
    );
    assert_eq!(send(&env.app, req).await.0, StatusCode::NO_CONTENT);

    assert_eq!(on_laptop.closed().await.0, 4003);
    assert!(on_phone.silent_for(Duration::from_millis(200)).await);
    assert_open(&mut on_phone).await;
}

#[tokio::test]
async fn disabling_an_account_closes_all_its_connections() {
    let env = env().await;
    create(&env, "carol", "correct horse battery").await;
    create(&env, "dave", "correct horse battery").await;
    let (carol_key, dave_key) = (new_key(), new_key());
    let carol_id = device(&env, "carol", &carol_key).await;
    let dave_id = device(&env, "dave", &dave_key).await;
    let mut carol = connect(&env, "carol@providera.com", &carol_id, &carol_key).await;
    let mut dave = connect(&env, "dave@providera.com", &dave_id, &dave_key).await;

    let accounts = &env.state.accounts;
    let user = accounts.store.find_user("carol").await.unwrap().unwrap();
    accounts
        .disable_account(&user, SIGNED_AT.unix_timestamp())
        .await
        .unwrap();

    assert_eq!(carol.closed().await.0, 4003);
    assert_open(&mut dave).await;
}
