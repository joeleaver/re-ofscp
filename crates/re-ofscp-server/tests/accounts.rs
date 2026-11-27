//! Accounts, login, bootstrap tokens, device keys and the keys endpoint
//! (spec §4.1–§4.7), against a real rhypedb-server.

mod common;

use axum::http::{StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use common::accounts::*;
use common::harness::*;
use std::sync::{Arc, Mutex};

use re_ofscp_server::accounts::{
    CreateError, MAX_DEVICE_KEYS, Revocation, RevocationListener, StoreError,
};
use re_ofscp_server::signing::StaticKeys;
use re_ofscp_types::Actor;
use serde_json::{Value, json};

/// Records the revocations announced.
#[derive(Debug, Default)]
struct Recorder(Mutex<Vec<Revocation>>);

impl Recorder {
    fn take(&self) -> Vec<Revocation> {
        std::mem::take(&mut self.0.lock().unwrap())
    }
}

impl RevocationListener for Recorder {
    fn revoked(&self, r: &Revocation) {
        self.0.lock().unwrap().push(r.clone());
    }
}

#[tokio::test]
async fn login_register_a_key_sign_list_and_revoke() {
    let env = env().await;
    create(&env, "alice", "correct horse battery").await;

    // Login → bootstrap token (schema-valid).
    let (status, boot, _) = login(&env, "alice", "correct horse battery", "10.0.0.1").await;
    assert_eq!(status, StatusCode::OK, "{boot}");
    common::assert_valid(&common::schema("auth-bootstrap-response.json"), &boot);
    assert_eq!(boot["token_type"], "bootstrap");
    assert_eq!(boot["expires_in"], 300);
    let token = boot["bootstrap_token"].as_str().unwrap().to_owned();

    // Register a device key with it (schema-valid response).
    let device = new_key();
    let (status, created) = register_key(&env, &token, &device, "10.0.0.1").await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    common::assert_valid(&common::schema("device-key-response.json"), &created);
    let key_id = created["key_id"].as_str().unwrap().to_owned();
    assert!(key_id.starts_with("dk_"));

    // The token was single-use.
    let (status, _) = register_key(&env, &token, &new_key(), "10.0.0.1").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // The keys endpoint publishes it.
    let (status, keys, _, _) = send(&env.app, get("/.well-known/ofscp/users/alice/keys")).await;
    assert_eq!(status, StatusCode::OK, "{keys}");
    common::assert_valid(&common::schema("user-keys-response.json"), &keys);
    assert_eq!(keys["actor"], "alice@providera.com");
    assert_eq!(keys["keys"][0]["key_id"], key_id.as_str());
    assert_eq!(
        keys["keys"][0]["public_key"],
        B64.encode(device.verifying_key().to_bytes())
    );

    // A request signed with the new key authenticates: list own keys.
    let req = signed(
        &device,
        "alice@providera.com",
        &key_id,
        "GET",
        "/api/auth/device-keys",
        "",
        NOW,
    );
    let (status, list, _, _) = send(&env.app, req).await;
    assert_eq!(status, StatusCode::OK, "{list}");
    common::assert_valid(&common::schema("device-keys-response.json"), &list);
    assert_eq!(list["keys"].as_array().unwrap().len(), 1);
    assert_eq!(list["keys"][0]["device_name"], "Firefox on Linux");

    // Revoke it with a request signed by itself (logout, §4.7.2).
    let revocations = Arc::new(Recorder::default());
    env.state.accounts.on_revocation(revocations.clone());
    let path = format!("/api/auth/device-keys/{key_id}");
    let req = signed(
        &device,
        "alice@providera.com",
        &key_id,
        "DELETE",
        &path,
        "",
        NOW,
    );
    let (status, body, _, _) = send(&env.app, req).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let r = revocations.take().pop().unwrap();
    assert_eq!(r.handle, "alice");
    assert_eq!(r.key_id.as_deref(), Some(key_id.as_str()));

    // Gone from the keys endpoint, and it no longer verifies.
    let (_, keys, _, _) = send(&env.app, get("/.well-known/ofscp/users/alice/keys")).await;
    assert_eq!(keys["keys"].as_array().unwrap().len(), 0);
    let req = signed(
        &device,
        "alice@providera.com",
        &key_id,
        "GET",
        "/api/auth/device-keys",
        "",
        NOW,
    );
    let (status, body, _, _) = send(&env.app, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    // Revoking again: 404.
    let other = new_key();
    let (_, boot, _) = login(&env, "alice", "correct horse battery", "10.0.0.1").await;
    let (_, created) = register_key(
        &env,
        boot["bootstrap_token"].as_str().unwrap(),
        &other,
        "10.0.0.1",
    )
    .await;
    let other_id = created["key_id"].as_str().unwrap();
    let req = signed(
        &other,
        "alice@providera.com",
        other_id,
        "DELETE",
        &path,
        "",
        NOW,
    );
    assert_eq!(send(&env.app, req).await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn failed_logins_reveal_nothing_and_lock_out_progressively() {
    let env = env().await;
    create(&env, "alice", "correct horse battery").await;

    let (s1, wrong, _) = login(&env, "alice", "wrong password!", "10.0.0.2").await;
    let (s2, unknown, _) = login(&env, "nobody", "wrong password!", "10.0.0.3").await;
    let (s3, invalid, _) = login(&env, "NOT VALID", "wrong password!", "10.0.0.4").await;
    for (s, body) in [(s1, &wrong), (s2, &unknown), (s3, &invalid)] {
        assert_eq!(s, StatusCode::UNAUTHORIZED);
        common::assert_valid(&common::schema("problem-details.json"), body);
    }
    // Identical answers: nothing distinguishes a wrong password from an
    // unknown or impossible handle.
    assert_eq!(wrong, unknown);
    assert_eq!(wrong, invalid);

    // Five free attempts (one done above); the sixth is refused without
    // being tried, and so is the right password during the lockout.
    for i in 0..4 {
        let (s, _, _) = login(&env, "alice", "wrong password!", &format!("10.1.0.{i}")).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
    }
    let (s, _, retry) = login(&env, "alice", "wrong password!", "10.1.1.1").await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(retry.as_deref(), Some("60"));
    let (s, body, retry) = login(&env, "alice", "correct horse battery", "10.1.1.2").await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["errorCode"], "too_many_requests");
    assert_eq!(retry.as_deref(), Some("60"));
}

#[tokio::test]
async fn one_source_address_is_rate_limited() {
    let env = env().await;
    // Distinct handles, so the per-handle lockout is not what trips.
    for i in 0..10 {
        let (s, _, _) = login(&env, &format!("nobody{i}"), "wrong password!", "10.9.9.9").await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
    }
    let (s, _, retry) = login(&env, "nobody10", "wrong password!", "10.9.9.9").await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    assert!(retry.is_some());
    // Another address is unaffected.
    let (s, _, _) = login(&env, "nobody11", "wrong password!", "10.9.9.8").await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn disabled_accounts_cannot_log_in_and_their_keys_stop_verifying() {
    let env = env().await;
    create(&env, "carol", "correct horse battery").await;
    let (_, boot, _) = login(&env, "carol", "correct horse battery", "10.0.1.1").await;
    let device = new_key();
    let (_, created) = register_key(
        &env,
        boot["bootstrap_token"].as_str().unwrap(),
        &device,
        "10.0.1.1",
    )
    .await;
    let key_id = created["key_id"].as_str().unwrap().to_owned();
    // An outstanding token too.
    let (_, boot2, _) = login(&env, "carol", "correct horse battery", "10.0.1.1").await;

    let user = env
        .state
        .accounts
        .store
        .find_user("carol")
        .await
        .unwrap()
        .unwrap();
    env.state
        .accounts
        .disable_account(&user, SIGNED_AT.unix_timestamp())
        .await
        .unwrap();

    let (s, _, _) = login(&env, "carol", "correct horse battery", "10.0.1.2").await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = register_key(
        &env,
        boot2["bootstrap_token"].as_str().unwrap(),
        &new_key(),
        "10.0.1.2",
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "outstanding tokens died");
    let req = signed(
        &device,
        "carol@providera.com",
        &key_id,
        "GET",
        "/api/auth/device-keys",
        "",
        NOW,
    );
    assert_eq!(send(&env.app, req).await.0, StatusCode::UNAUTHORIZED);
    // The keys endpoint answers as for a handle that was never registered.
    let (s, carol, _, _) = send(&env.app, get("/.well-known/ofscp/users/carol/keys")).await;
    let (_, nobody, _, _) = send(&env.app, get("/.well-known/ofscp/users/nobody/keys")).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(carol["keys"], json!([]));
    assert_eq!(carol["keys"], nobody["keys"]);
}

#[tokio::test]
async fn device_key_registration_validates_before_consuming_the_token() {
    let env = env().await;
    create(&env, "dave", "correct horse battery").await;
    let (_, boot, _) = login(&env, "dave", "correct horse battery", "10.0.2.1").await;
    let token = boot["bootstrap_token"].as_str().unwrap().to_owned();
    let bad = |body: Value| {
        let mut r = post_json("/api/auth/device-keys", body, "10.0.2.1");
        r.headers_mut().insert(
            header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        r
    };
    for body in [
        json!({"public_key": "not base64!", "device_name": "x"}),
        json!({"public_key": B64.encode([0u8; 31]), "device_name": "x"}),
        json!({"public_key": B64.encode(new_key().verifying_key().to_bytes()), "algorithm": "RSA", "device_name": "x"}),
        json!({"public_key": B64.encode(new_key().verifying_key().to_bytes()), "device_name": "x".repeat(201)}),
    ] {
        let (s, j, _, _) = send(&env.app, bad(body)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    }
    // Wrong scheme / no token.
    let mut r = post_json(
        "/api/auth/device-keys",
        json!({"public_key": B64.encode(new_key().verifying_key().to_bytes()), "device_name": "x"}),
        "10.0.2.1",
    );
    r.headers_mut().insert(
        header::AUTHORIZATION,
        format!("Basic {token}").parse().unwrap(),
    );
    assert_eq!(send(&env.app, r).await.0, StatusCode::UNAUTHORIZED);
    // The token survived every failed attempt; algorithm may be omitted.
    let mut r = post_json(
        "/api/auth/device-keys",
        json!({"public_key": B64.encode(new_key().verifying_key().to_bytes()), "device_name": "Phone"}),
        "10.0.2.1",
    );
    r.headers_mut().insert(
        header::AUTHORIZATION,
        format!("bearer {token}").parse().unwrap(),
    );
    assert_eq!(send(&env.app, r).await.0, StatusCode::CREATED);
}

#[tokio::test]
async fn an_account_holds_at_most_the_maximum_number_of_keys() {
    let env = env().await;
    create(&env, "erin", "correct horse battery").await;
    for i in 0..MAX_DEVICE_KEYS {
        let ip = format!("10.2.{}.{}", i / 200, i % 200);
        let (_, boot, _) = login(&env, "erin", "correct horse battery", &ip).await;
        let (s, j) = register_key(
            &env,
            boot["bootstrap_token"].as_str().unwrap(),
            &new_key(),
            &ip,
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "key {i}: {j}");
    }
    let (_, boot, _) = login(&env, "erin", "correct horse battery", "10.3.0.1").await;
    let (s, j) = register_key(
        &env,
        boot["bootstrap_token"].as_str().unwrap(),
        &new_key(),
        "10.3.0.1",
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "{j}");
    assert_eq!(j["errorCode"], "conflict");
}

#[tokio::test]
async fn remote_actors_cannot_use_local_account_endpoints() {
    let bob = new_key();
    let bob_actor = Actor::parse_canonical("bob@providerb.com").unwrap();
    let env = env_with(EnvOptions {
        remote: Some(StaticKeys::default().with(bob_actor, "dk_bob", bob.verifying_key())),
        ..EnvOptions::default()
    })
    .await;
    // Even with a local "bob" present, bob@providerb.com is someone else.
    create(&env, "bob", "correct horse battery").await;
    let req = signed(
        &bob,
        "bob@providerb.com",
        "dk_bob",
        "GET",
        "/api/auth/device-keys",
        "",
        NOW,
    );
    let (s, j, _, _) = send(&env.app, req).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["detail"], "this endpoint is for local accounts only");
}

#[tokio::test]
async fn account_creation_validates_handles_and_rejects_duplicates() {
    let env = env().await;
    let a = &env.state.accounts;
    let t = SIGNED_AT.unix_timestamp();
    assert_eq!(
        a.create_account("guest_x", "G", "correct horse battery", t)
            .await,
        Err(CreateError::ReservedHandle)
    );
    assert_eq!(
        a.create_account("Frank", "F", "correct horse battery", t)
            .await,
        Err(CreateError::InvalidHandle)
    );
    assert_eq!(
        a.create_account("frank", "  ", "correct horse battery", t)
            .await,
        Err(CreateError::InvalidDisplayName)
    );
    assert!(matches!(
        a.create_account("frank", "F", "short", t).await,
        Err(CreateError::Password(_))
    ));
    a.create_account("frank", "Frank", "correct horse battery", t)
        .await
        .unwrap();
    assert_eq!(
        a.create_account("frank", "F2", "correct horse battery", t)
            .await,
        Err(CreateError::Store(StoreError::HandleTaken))
    );
    // Unknown handles do not reveal that they are unknown (schema-valid,
    // no keys); impossible ones are simply not found.
    let (s, nobody, _, _) = send(&env.app, get("/.well-known/ofscp/users/nobody/keys")).await;
    assert_eq!(s, StatusCode::OK);
    common::assert_valid(&common::schema("user-keys-response.json"), &nobody);
    assert_eq!(nobody["actor"], "nobody@providera.com");
    assert_eq!(nobody["keys"], json!([]));
    assert_eq!(
        send(&env.app, get("/.well-known/ofscp/users/BAD/keys"))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
}

/// A local actor cannot borrow the provider signing key: actor signatures
/// resolve only against the actor's own device keys (§4.5, §8.1).
#[tokio::test]
async fn a_local_actor_signing_with_the_provider_key_is_401() {
    let env = env().await;
    create(&env, "alice", "correct horse battery").await;
    let own = &env.state.config.provider_key;
    let req = signed(
        own.signing_key(),
        "alice@providera.com",
        own.key_id(),
        "GET",
        "/api/auth/device-keys",
        "",
        NOW,
    );
    let (status, json, _, _) = send(&env.app, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{json}");
    assert_eq!(json["errorCode"], "unauthorized");
}
