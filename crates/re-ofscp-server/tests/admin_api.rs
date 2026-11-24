//! The admin API over OFSCP accounts and invites, roles, admin management
//! and the audit log, against a real rhypedb-server.

mod common;

use axum::http::{Method, StatusCode};
use common::accounts::{env, login as account_login, post_json};
use common::admin::*;
use serde_json::{Value, json};

#[tokio::test]
async fn operators_create_and_disable_accounts() {
    let env = env().await;
    let root = owner(&env).await;
    let ops = admin_with_role(&env, &root, "ops", "operator").await;

    let body = json!({"handle": "alice", "displayName": "Alice", "password": "alice password"});
    let res = call(
        &env,
        Method::POST,
        "/api/admin/accounts",
        Some(body.clone()),
        &ops,
    )
    .await;
    assert_eq!(res.status, StatusCode::CREATED, "{}", res.json);
    assert_eq!(res.json["handle"], "alice");
    assert_eq!(res.json["status"], "active");
    let res = call(&env, Method::POST, "/api/admin/accounts", Some(body), &ops).await;
    assert_eq!(res.status, StatusCode::CONFLICT);
    let bad = json!({"handle": "guest_x", "password": "alice password"});
    let res = call(&env, Method::POST, "/api/admin/accounts", Some(bad), &ops).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);

    let (s, _, _) = account_login(&env, "alice", "alice password", "203.0.113.1").await;
    assert_eq!(s, StatusCode::OK);

    let res = call(&env, Method::GET, "/api/admin/accounts?q=lic", None, &ops).await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(res.json["accounts"][0]["handle"], "alice");
    assert_eq!(res.json["truncated"], false);
    let res = call(&env, Method::GET, "/api/admin/accounts/alice", None, &ops).await;
    assert_eq!(res.json["displayName"], "Alice");
    assert!(res.json.get("passwordHash").is_none());

    let res = call(
        &env,
        Method::POST,
        "/api/admin/accounts/alice/disable",
        None,
        &ops,
    )
    .await;
    assert_eq!(res.status, StatusCode::NO_CONTENT, "{}", res.json);
    let (s, _, _) = account_login(&env, "alice", "alice password", "203.0.113.2").await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let res = call(&env, Method::GET, "/api/admin/accounts/alice", None, &ops).await;
    assert_eq!(res.json["status"], "disabled");
    let res = call(
        &env,
        Method::POST,
        "/api/admin/accounts/nobody/disable",
        None,
        &ops,
    )
    .await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn invites_are_issued_listed_used_and_revoked() {
    let env = env().await;
    let root = owner(&env).await;

    let res = call(
        &env,
        Method::POST,
        "/api/admin/invites",
        Some(json!({"handle": "bob"})),
        &root,
    )
    .await;
    assert_eq!(res.status, StatusCode::CREATED, "{}", res.json);
    let token = res.json["token"].as_str().unwrap().to_owned();
    let used_id = res.json["id"].as_str().unwrap().to_owned();
    assert_eq!(
        res.json["link"],
        format!("https://providera.com/register?invite={token}")
    );
    let res = call(
        &env,
        Method::POST,
        "/api/admin/invites",
        Some(json!({"ttlSecs": 3600})),
        &root,
    )
    .await;
    let open_id = res.json["id"].as_str().unwrap().to_owned();
    let res = call(
        &env,
        Method::POST,
        "/api/admin/invites",
        Some(json!({"ttlSecs": 0})),
        &root,
    )
    .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);

    let res = call(&env, Method::GET, "/api/admin/invites", None, &root).await;
    let listed: Vec<&Value> = res.json["invites"].as_array().unwrap().iter().collect();
    assert_eq!(listed.len(), 2);
    assert!(
        listed
            .iter()
            .all(|i| i.get("token").is_none() && i["createdBy"] == "root")
    );

    // The pinned invite registers bob.
    let reg = json!({"handle": "bob", "password": "bob password", "inviteToken": token});
    let (s, j, _, _) = common::harness::send(
        &env.app,
        post_json("/api/auth/register", reg, "203.0.113.5"),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{j}");

    let path = |id: &str| format!("/api/admin/invites/{id}");
    let res = call(&env, Method::DELETE, &path(&used_id), None, &root).await;
    assert_eq!(res.status, StatusCode::CONFLICT);
    let res = call(&env, Method::DELETE, &path(&open_id), None, &root).await;
    assert_eq!(res.status, StatusCode::NO_CONTENT);
    let res = call(&env, Method::DELETE, &path(&open_id), None, &root).await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    let res = call(&env, Method::GET, "/api/admin/invites", None, &root).await;
    assert_eq!(res.json["invites"].as_array().unwrap().len(), 0);

    // The log has the ids, never a token.
    let entries = audit(&env, &root).await;
    let text = serde_json::to_string(&entries).unwrap();
    assert!(!text.contains(&token));
    assert!(entries.iter().any(|e| e["action"] == "invite.revoke"
        && e["target"] == open_id.as_str()
        && e["outcome"] == "ok"));
}

#[tokio::test]
async fn roles_limit_what_each_admin_can_do() {
    let env = env().await;
    let root = owner(&env).await;
    let ops = admin_with_role(&env, &root, "ops", "operator").await;
    let viewer = admin_with_role(&env, &root, "viewer", "read_only").await;
    let account = json!({"handle": "carol", "password": "carol password"});

    let res = call(
        &env,
        Method::POST,
        "/api/admin/accounts",
        Some(account.clone()),
        &viewer,
    )
    .await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    let res = call(
        &env,
        Method::POST,
        "/api/admin/invites",
        Some(json!({})),
        &viewer,
    )
    .await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    for path in [
        "/api/admin/accounts",
        "/api/admin/invites",
        "/api/admin/audit",
    ] {
        assert_eq!(
            call(&env, Method::GET, path, None, &viewer).await.status,
            StatusCode::OK,
            "{path}"
        );
    }
    for who in [&viewer, &ops] {
        let res = call(&env, Method::GET, "/api/admin/admins", None, who).await;
        assert_eq!(res.status, StatusCode::FORBIDDEN);
        let body = json!({"username": "x-admin", "password": "some password", "role": "owner"});
        let res = call(&env, Method::POST, "/api/admin/admins", Some(body), who).await;
        assert_eq!(res.status, StatusCode::FORBIDDEN);
    }
    let res = call(
        &env,
        Method::POST,
        "/api/admin/accounts",
        Some(account),
        &ops,
    )
    .await;
    assert_eq!(res.status, StatusCode::CREATED);

    // A role change applies to the next request.
    let res = call(
        &env,
        Method::PATCH,
        "/api/admin/admins/viewer",
        Some(json!({"role": "operator"})),
        &root,
    )
    .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    let res = call(
        &env,
        Method::POST,
        "/api/admin/invites",
        Some(json!({})),
        &viewer,
    )
    .await;
    assert_eq!(res.status, StatusCode::CREATED);

    let denied: Vec<Value> = audit(&env, &root)
        .await
        .into_iter()
        .filter(|e| e["outcome"] == "denied")
        .collect();
    assert!(denied.iter().any(|e| e["admin"] == "viewer"
        && e["action"] == "account.create"
        && e["target"] == "carol"));
    assert!(
        denied
            .iter()
            .any(|e| e["admin"] == "ops" && e["action"] == "admin.create")
    );
}

#[tokio::test]
async fn new_admins_must_change_their_password_and_enroll() {
    let env = env().await;
    let root = owner(&env).await;
    let body = json!({"username": "newbie", "password": "initial password", "role": "operator"});
    let res = call(
        &env,
        Method::POST,
        "/api/admin/admins",
        Some(body.clone()),
        &root,
    )
    .await;
    assert_eq!(res.status, StatusCode::CREATED);
    assert_eq!(res.json["passwordChangeRequired"], true);
    let res = call(&env, Method::POST, "/api/admin/admins", Some(body), &root).await;
    assert_eq!(res.status, StatusCode::CONFLICT);

    let mut newbie = sign_in(&env, "newbie", "initial password", None).await;
    enroll(&env, &mut newbie).await;
    // Enrolled, but the password still has to change.
    let res = call(&env, Method::GET, "/api/admin/accounts", None, &newbie).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    let same = json!({"currentPassword": "initial password", "newPassword": "initial password"});
    let res = call(
        &env,
        Method::POST,
        "/api/admin/password",
        Some(same),
        &newbie,
    )
    .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    let change = json!({"currentPassword": "initial password", "newPassword": "chosen password"});
    let res = call(
        &env,
        Method::POST,
        "/api/admin/password",
        Some(change),
        &newbie,
    )
    .await;
    assert_eq!(res.status, StatusCode::NO_CONTENT);
    let res = call(&env, Method::GET, "/api/admin/accounts", None, &newbie).await;
    assert_eq!(res.status, StatusCode::OK);
}

#[tokio::test]
async fn there_is_always_an_active_owner_and_disabling_is_final() {
    let env = env().await;
    let root = owner(&env).await;
    let patch = |who: &str| format!("/api/admin/admins/{who}");

    let res = call(
        &env,
        Method::PATCH,
        &patch("root"),
        Some(json!({"role": "operator"})),
        &root,
    )
    .await;
    assert_eq!(res.status, StatusCode::CONFLICT);
    let res = call(
        &env,
        Method::PATCH,
        &patch("root"),
        Some(json!({"disabled": true})),
        &root,
    )
    .await;
    assert_eq!(res.status, StatusCode::CONFLICT);

    let second = admin_with_role(&env, &root, "second", "owner").await;
    let res = call(&env, Method::GET, "/api/admin/session", None, &second).await;
    assert_eq!(res.json["role"], "owner");

    // Disabling ends their sessions at once.
    let res = call(
        &env,
        Method::PATCH,
        &patch("second"),
        Some(json!({"disabled": true})),
        &root,
    )
    .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(res.json["status"], "disabled");
    let res = call(&env, Method::GET, "/api/admin/session", None, &second).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    let c = code(&env, second.secret.as_ref().unwrap());
    let res = login(&env, "second", &second.password, Some(&c)).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    let res = call(
        &env,
        Method::PATCH,
        &patch("second"),
        Some(json!({"disabled": false})),
        &root,
    )
    .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    let res = call(
        &env,
        Method::PATCH,
        &patch("second"),
        Some(json!({"role": "owner"})),
        &root,
    )
    .await;
    assert_eq!(res.status, StatusCode::CONFLICT);
    let res = call(
        &env,
        Method::PATCH,
        &patch("ghost"),
        Some(json!({"role": "owner"})),
        &root,
    )
    .await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);

    let res = call(&env, Method::GET, "/api/admin/admins", None, &root).await;
    let names: Vec<&str> = res.json["admins"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["username"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["root", "second"]);
}

#[tokio::test]
async fn owners_reset_another_admins_totp() {
    let env = env().await;
    let root = owner(&env).await;
    let ops = admin_with_role(&env, &root, "ops", "operator").await;
    let reset = |who: &str| format!("/api/admin/admins/{who}/totp/reset");

    let res = call(&env, Method::POST, &reset("root"), None, &root).await;
    assert_eq!(res.status, StatusCode::CONFLICT, "not one's own");
    let res = call(&env, Method::POST, &reset("ops"), None, &root).await;
    assert_eq!(res.status, StatusCode::NO_CONTENT);
    let res = call(&env, Method::GET, "/api/admin/session", None, &ops).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "sessions end");
    // The password alone now gives a restricted session to enroll again.
    let mut again = sign_in(&env, "ops", &ops.password, None).await;
    let res = call(&env, Method::GET, "/api/admin/session", None, &again).await;
    assert_eq!(res.json["restricted"], true);
    enroll(&env, &mut again).await;
    let res = call(&env, Method::GET, "/api/admin/accounts", None, &again).await;
    assert_eq!(res.status, StatusCode::OK);
}

#[tokio::test]
async fn the_audit_log_names_the_admin_and_filters() {
    let env = env().await;
    let root = owner(&env).await;
    let ops = admin_with_role(&env, &root, "ops", "operator").await;
    let body = json!({"handle": "dave", "password": "dave password"});
    call(&env, Method::POST, "/api/admin/accounts", Some(body), &ops).await;

    let entries = audit(&env, &root).await;
    let first = &entries[0];
    assert_eq!(first["action"], "account.create");
    assert_eq!(first["admin"], "ops");
    assert_eq!(first["target"], "dave");
    assert_eq!(first["outcome"], "ok");
    assert_eq!(first["source"], "198.51.100.1");
    for action in [
        "admin.setup",
        "session.login",
        "totp.enroll",
        "totp.confirm",
        "admin.create",
        "password.change",
    ] {
        assert!(
            entries.iter().any(|e| e["action"] == action),
            "{action} missing"
        );
    }
    assert!(entries.iter().all(|e| e["outcome"] != "pending"));
    let text = serde_json::to_string(&entries).unwrap();
    assert!(!text.contains("dave password") && !text.contains("$argon2id"));

    let res = call(&env, Method::GET, "/api/admin/audit?admin=ops", None, &root).await;
    let only: Vec<Value> = res.json["entries"].as_array().unwrap().clone();
    assert!(!only.is_empty() && only.iter().all(|e| e["admin"] == "ops"));
    let res = call(
        &env,
        Method::GET,
        "/api/admin/audit?since=2025-01-01T00:00:00Z&until=2026-01-01T00:00:00Z",
        None,
        &root,
    )
    .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST, "over 31 days");
    let res = call(
        &env,
        Method::GET,
        "/api/admin/audit?since=yesterday",
        None,
        &root,
    )
    .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
}
