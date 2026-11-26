//! The federation allow/deny policy through the admin API, against a real
//! rhypedb-server: roles, validation, the audit log, persistence across a
//! restart, and its effect on remote signers (spec §8 *Authorization*,
//! §4.6; docs/decisions/0008).

mod common;

use axum::http::{Method, StatusCode};
use common::accounts::{
    EnvOptions, env, env_with, login as account_login, register_key, restarted,
};
use common::admin::*;
use common::harness::{new_key, send as send_signed, signed};
use re_ofscp_server::signing::{Signer, StaticKeys};
use re_ofscp_types::Actor;
use re_ofscp_types::federation::FederationMode;
use serde_json::{Value, json};

const TIMESTAMP: &str = "2026-01-01T12:00:00Z";

fn rule(list: &str, scope: &str, value: &str) -> Value {
    json!({"list": list, "scope": scope, "value": value})
}

#[tokio::test]
async fn the_policy_starts_open_and_roles_gate_each_change() {
    let env = env().await;
    let root = owner(&env).await;
    let ops = admin_with_role(&env, &root, "ops", "operator").await;
    let viewer = admin_with_role(&env, &root, "viewer", "read_only").await;

    let res = call(&env, Method::GET, "/api/admin/federation", None, &viewer).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(res.json, json!({"mode": "open", "allow": [], "deny": []}));

    // read_only cannot add rules; operators cannot change the mode.
    let add = rule("deny", "domain", "Evil.Example");
    let res = call(
        &env,
        Method::POST,
        "/api/admin/federation/rules",
        Some(add.clone()),
        &viewer,
    )
    .await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    let mode = json!({"mode": "denylist"});
    let res = call(
        &env,
        Method::PUT,
        "/api/admin/federation/mode",
        Some(mode.clone()),
        &ops,
    )
    .await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);

    let res = call(
        &env,
        Method::POST,
        "/api/admin/federation/rules",
        Some(add),
        &ops,
    )
    .await;
    assert_eq!(res.status, StatusCode::CREATED, "{}", res.json);
    assert_eq!(res.json["value"], "evil.example");
    assert_eq!(res.json["scope"], "domain");
    assert_eq!(res.json["createdBy"], "ops");
    let id = res.json["id"].as_str().unwrap().to_owned();

    let res = call(
        &env,
        Method::PUT,
        "/api/admin/federation/mode",
        Some(mode),
        &root,
    )
    .await;
    assert_eq!(res.status, StatusCode::NO_CONTENT, "{}", res.json);

    let res = call(&env, Method::GET, "/api/admin/federation", None, &viewer).await;
    assert_eq!(res.json["mode"], "denylist");
    assert_eq!(res.json["modeSetBy"], "root");
    assert_eq!(res.json["deny"][0]["id"], id.as_str());
    assert_eq!(res.json["allow"], json!([]));

    // Every change and refusal is in the audit log, naming the admin.
    let entries = audit(&env, &root).await;
    let find = |action: &str, outcome: &str| {
        entries
            .iter()
            .find(|e| e["action"] == action && e["outcome"] == outcome)
            .cloned()
            .unwrap_or_else(|| panic!("no {action} {outcome} in {entries:#?}"))
    };
    let added = find("federation.rule_add", "ok");
    assert_eq!(added["admin"], "ops");
    assert_eq!(added["target"], "deny domain Evil.Example");
    let set = find("federation.mode", "ok");
    assert_eq!(set["admin"], "root");
    assert_eq!(set["target"], "denylist");
    assert!(
        set["detail"].as_str().unwrap().contains("was open"),
        "{set}"
    );
    assert_eq!(find("federation.mode", "denied")["admin"], "ops");
    assert_eq!(find("federation.rule_add", "denied")["admin"], "viewer");

    let path = format!("/api/admin/federation/rules/{id}");
    let res = call(&env, Method::DELETE, &path, None, &viewer).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    let res = call(&env, Method::DELETE, &path, None, &ops).await;
    assert_eq!(res.status, StatusCode::NO_CONTENT, "{}", res.json);
    let res = call(&env, Method::DELETE, &path, None, &ops).await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    let removed = audit(&env, &root).await;
    assert!(
        removed
            .iter()
            .any(|e| e["action"] == "federation.rule_remove"
                && e["outcome"] == "ok"
                && e["detail"] == "deny domain evil.example")
    );
}

#[tokio::test]
async fn bad_rules_are_refused() {
    let env = env().await;
    let root = owner(&env).await;
    let post = |body: Value| {
        let env = &env;
        let root = &root;
        async move {
            call(
                env,
                Method::POST,
                "/api/admin/federation/rules",
                Some(body),
                root,
            )
            .await
        }
    };
    for (body, why) in [
        (rule("deny", "domain", "co.uk"), "public suffix"),
        (rule("deny", "domain", "com"), "two labels"),
        (
            rule("deny", "domain", "evil.example:8443"),
            "without a port",
        ),
        (
            rule("deny", "authority", "https://evil.example"),
            "authority",
        ),
        // The provider itself (DOMAIN=providera.com in the test env).
        (
            rule("deny", "authority", "ProviderA.com"),
            "own federation policy",
        ),
    ] {
        let res = post(body.clone()).await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{body}: {}", res.json);
        let detail = res.json["detail"].as_str().unwrap();
        assert!(detail.contains(why), "{body}: {detail}");
    }
    let long =
        json!({"list": "allow", "scope": "domain", "value": "a.example", "note": "x".repeat(201)});
    assert_eq!(post(long).await.status, StatusCode::BAD_REQUEST);
    let unknown = json!({"list": "maybe", "scope": "domain", "value": "a.example"});
    assert_eq!(post(unknown).await.status.as_u16() / 100, 4);

    // The same rule twice, however spelled, is a conflict; the same value
    // on the other list or with the other scope is a different rule.
    assert_eq!(
        post(rule("allow", "domain", "a.example")).await.status,
        StatusCode::CREATED
    );
    assert_eq!(
        post(rule("allow", "domain", "A.Example.")).await.status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        post(rule("deny", "domain", "a.example")).await.status,
        StatusCode::CREATED
    );
    assert_eq!(
        post(rule("allow", "authority", "a.example")).await.status,
        StatusCode::CREATED
    );
    // A private-section suffix is one operator's names: allowed.
    assert_eq!(
        post(rule("deny", "domain", "github.io")).await.status,
        StatusCode::CREATED
    );

    let res = call(
        &env,
        Method::PUT,
        "/api/admin/federation/mode",
        Some(json!({"mode": "closed"})),
        &root,
    )
    .await;
    assert_eq!(res.status.as_u16() / 100, 4);
}

#[tokio::test]
async fn the_policy_survives_a_restart() {
    let env = env().await;
    let root = owner(&env).await;
    for body in [
        rule("allow", "domain", "friend.example"),
        rule("allow", "authority", "peer.example:8443"),
        rule("deny", "domain", "evil.example"),
    ] {
        let res = call(
            &env,
            Method::POST,
            "/api/admin/federation/rules",
            Some(body),
            &root,
        )
        .await;
        assert_eq!(res.status, StatusCode::CREATED, "{}", res.json);
    }
    let res = call(
        &env,
        Method::PUT,
        "/api/admin/federation/mode",
        Some(json!({"mode": "allowlist"})),
        &root,
    )
    .await;
    assert_eq!(res.status, StatusCode::NO_CONTENT);

    let before = env.state.federation.policy().snapshot().unwrap();
    let after = restarted(&env)
        .await
        .federation
        .policy()
        .snapshot()
        .unwrap();
    assert_eq!(*before, *after);
    assert_eq!(after.mode, FederationMode::Allowlist);
    assert_eq!(after.allow.len(), 2);
    assert_eq!(after.deny.len(), 1);
}

#[tokio::test]
async fn a_denied_remote_signer_gets_403_and_a_local_one_never_does() {
    let key = new_key();
    let bob = Actor::parse_canonical("bob@chat.evil.example").unwrap();
    let remote =
        StaticKeys::default().with(Signer::Actor(bob.clone()), "dk_bob", key.verifying_key());
    let env = env_with(EnvOptions {
        remote: Some(remote),
        ..EnvOptions::default()
    })
    .await;
    let root = owner(&env).await;
    let health = || {
        signed(
            &key,
            "bob@chat.evil.example",
            "dk_bob",
            "GET",
            "/api/health",
            "",
            TIMESTAMP,
        )
    };

    let (status, json, _, _) = send_signed(&env.app, health()).await;
    assert_eq!(status, StatusCode::OK, "{json}");

    let res = call(
        &env,
        Method::POST,
        "/api/admin/federation/rules",
        Some(rule("deny", "domain", "evil.example")),
        &root,
    )
    .await;
    assert_eq!(res.status, StatusCode::CREATED);
    let id = res.json["id"].as_str().unwrap().to_owned();
    // A deny rule is not in force while the mode is open.
    assert_eq!(send_signed(&env.app, health()).await.0, StatusCode::OK);

    let res = call(
        &env,
        Method::PUT,
        "/api/admin/federation/mode",
        Some(json!({"mode": "denylist"})),
        &root,
    )
    .await;
    assert_eq!(res.status, StatusCode::NO_CONTENT);
    let (status, json, _, _) = send_signed(&env.app, health()).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{json}");
    assert_eq!(json["errorCode"], "forbidden");
    assert_eq!(json["type"], "https://providera.com/problems/forbidden");

    // Allowlist mode with an empty allowlist: every remote signer is
    // refused, but this provider's own accounts are not federation.
    let res = call(
        &env,
        Method::PUT,
        "/api/admin/federation/mode",
        Some(json!({"mode": "allowlist"})),
        &root,
    )
    .await;
    assert_eq!(res.status, StatusCode::NO_CONTENT);
    assert_eq!(
        send_signed(&env.app, health()).await.0,
        StatusCode::FORBIDDEN
    );
    common::accounts::create(&env, "alice", "alice password").await;
    let (_, boot, _) = account_login(&env, "alice", "alice password", "10.0.0.1").await;
    let alice_key = new_key();
    let (status, created) = register_key(
        &env,
        boot["bootstrap_token"].as_str().unwrap(),
        &alice_key,
        "10.0.0.1",
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let alice_key_id = created["key_id"].as_str().unwrap();
    let local = signed(
        &alice_key,
        "alice@providera.com",
        alice_key_id,
        "GET",
        "/api/health",
        "",
        TIMESTAMP,
    );
    let (status, json, _, _) = send_signed(&env.app, local).await;
    assert_eq!(status, StatusCode::OK, "{json}");

    // Back to a denylist without the rule: bob is let in again.
    let res = call(
        &env,
        Method::PUT,
        "/api/admin/federation/mode",
        Some(json!({"mode": "denylist"})),
        &root,
    )
    .await;
    assert_eq!(res.status, StatusCode::NO_CONTENT);
    let res = call(
        &env,
        Method::DELETE,
        &format!("/api/admin/federation/rules/{id}"),
        None,
        &root,
    )
    .await;
    assert_eq!(res.status, StatusCode::NO_CONTENT);
    assert_eq!(send_signed(&env.app, health()).await.0, StatusCode::OK);
}
