//! Admin identity: setup, sign-in, TOTP, sessions, CSRF and lockout,
//! against a real rhypedb-server.

mod common;

use axum::http::{Method, StatusCode, header};
use common::accounts::{EnvOptions, env, env_with};
use common::admin::*;
use re_ofscp_server::admin::sessions::IDLE_SECS;
use serde_json::json;

#[tokio::test]
async fn setup_creates_one_owner_then_closes() {
    let env = env().await;
    let wrong =
        json!({"setupToken": "x".repeat(40), "username": "root", "password": "owner password 1"});
    let res = send(
        &env,
        request(Method::POST, "/api/admin/setup", Some(wrong), None),
    )
    .await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);

    let mut cross = request(
        Method::POST,
        "/api/admin/setup",
        Some(
            json!({"setupToken": common::accounts::SETUP_TOKEN, "username": "root", "password": "owner password 1"}),
        ),
        None,
    );
    cross
        .headers_mut()
        .insert("origin", "https://evil.example".parse().unwrap());
    assert_eq!(send(&env, cross).await.status, StatusCode::FORBIDDEN);

    assert_eq!(
        setup(&env, "Root", "owner password 1").await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        setup(&env, "root", "short").await.status,
        StatusCode::BAD_REQUEST
    );
    let res = setup(&env, "root", "owner password 1").await;
    assert_eq!(res.status, StatusCode::CREATED, "{}", res.json);
    assert_eq!(res.json["role"], "owner");
    assert_eq!(res.json["createdBy"], "setup");
    assert!(res.json.get("passwordHash").is_none());
    // Over, even with the right token.
    assert_eq!(
        setup(&env, "second", "owner password 2").await.status,
        StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn the_admin_api_is_off_without_a_secret_key() {
    let env = env_with(EnvOptions {
        no_admin: true,
        ..EnvOptions::default()
    })
    .await;
    assert_eq!(
        setup(&env, "root", "owner password 1").await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        login(&env, "root", "owner password 1", None).await.status,
        StatusCode::NOT_FOUND
    );
    let res = send(&env, request(Method::GET, "/api/admin/session", None, None)).await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn sessions_are_restricted_until_totp_is_enrolled() {
    let env = env().await;
    setup(&env, "root", "owner password 1").await;
    let res = login(&env, "root", "owner password 1", None).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    let set_cookie = res.headers[header::SET_COOKIE].to_str().unwrap().to_owned();
    for attr in ["HttpOnly", "Secure", "SameSite=Strict", "Path=/api/admin"] {
        assert!(set_cookie.contains(attr), "{set_cookie}");
    }
    assert_eq!(res.json["restricted"], true);
    assert_eq!(res.json["totpEnabled"], false);
    let mut root = sign_in(&env, "root", "owner password 1", None).await;

    let res = call(&env, Method::GET, "/api/admin/accounts", None, &root).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN, "{}", res.json);

    // A wrong code does not enroll.
    let res = call(&env, Method::POST, "/api/admin/totp/enroll", None, &root).await;
    assert_eq!(res.status, StatusCode::OK);
    let uri = res.json["otpauthUri"].as_str().unwrap();
    assert!(
        uri.starts_with("otpauth://totp/providera.com:root?secret="),
        "{uri}"
    );
    let res = call(
        &env,
        Method::POST,
        "/api/admin/totp/confirm",
        Some(json!({"code": "000000"})),
        &root,
    )
    .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);

    enroll(&env, &mut root).await;
    let res = call(&env, Method::GET, "/api/admin/session", None, &root).await;
    assert_eq!(res.json["restricted"], false);
    assert_eq!(res.json["totpEnabled"], true);
    assert_eq!(res.json["csrfToken"], root.csrf.as_str());
    let res = call(&env, Method::GET, "/api/admin/accounts", None, &root).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    // Enrolled already.
    let res = call(&env, Method::POST, "/api/admin/totp/enroll", None, &root).await;
    assert_eq!(res.status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn enrolled_admins_need_a_fresh_code_every_time() {
    let env = env().await;
    let root = owner(&env).await;
    let secret = root.secret.clone().unwrap();
    let res = login(&env, "root", "owner password 1", None).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    let c = code(&env, &secret);
    let res = login(&env, "root", "owner password 1", Some(&c)).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    assert_eq!(res.json["restricted"], false);
    // The same code never works twice.
    let again = login(&env, "root", "owner password 1", Some(&c)).await;
    assert_eq!(again.status, StatusCode::UNAUTHORIZED);
    // Wrong password with a right code: the same answer.
    next_step(&env);
    let c = code(&env, &secret);
    let wrong = login(&env, "root", "wrong password", Some(&c)).await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong.json["detail"], again.json["detail"]);
    let unknown = login(&env, "nobody", "owner password 1", Some(&c)).await;
    assert_eq!(unknown.json, wrong.json);
    let res = login(&env, "root", "owner password 1", Some(&c)).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
}

#[tokio::test]
async fn mutations_need_the_csrf_token_and_the_same_origin() {
    let env = env().await;
    let root = owner(&env).await;
    let body = json!({"handle": "alice", "password": "alice password"});

    let mut no_csrf = request(
        Method::POST,
        "/api/admin/accounts",
        Some(body.clone()),
        None,
    );
    no_csrf.headers_mut().insert(
        header::COOKIE,
        format!("{COOKIE}={}", root.cookie).parse().unwrap(),
    );
    assert_eq!(send(&env, no_csrf).await.status, StatusCode::FORBIDDEN);

    let forged = Admin {
        csrf: "forged".into(),
        ..root.clone()
    };
    let res = call(
        &env,
        Method::POST,
        "/api/admin/accounts",
        Some(body.clone()),
        &forged,
    )
    .await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);

    let mut cross = request(
        Method::POST,
        "/api/admin/accounts",
        Some(body.clone()),
        Some(&root),
    );
    cross
        .headers_mut()
        .insert("sec-fetch-site", "cross-site".parse().unwrap());
    assert_eq!(send(&env, cross).await.status, StatusCode::FORBIDDEN);

    // No session at all.
    let res = send(
        &env,
        request(Method::GET, "/api/admin/accounts", None, None),
    )
    .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);

    let mut same = request(Method::POST, "/api/admin/accounts", Some(body), Some(&root));
    same.headers_mut()
        .insert("origin", "https://providera.com".parse().unwrap());
    let res = send(&env, same).await;
    assert_eq!(res.status, StatusCode::CREATED, "{}", res.json);

    let denied: Vec<_> = audit(&env, &root)
        .await
        .into_iter()
        .filter(|e| e["action"] == "csrf")
        .collect();
    // The missing and the forged token, both with a valid session.
    assert_eq!(denied.len(), 2);
    assert!(
        denied
            .iter()
            .all(|e| e["admin"] == "root" && e["outcome"] == "denied")
    );
}

#[tokio::test]
async fn repeated_failures_lock_the_username() {
    let env = env().await;
    let root = owner(&env).await;
    for _ in 0..5 {
        let res = login(&env, "root", "wrong password", Some("123456")).await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    }
    let c = code(&env, root.secret.as_ref().unwrap());
    let res = login(&env, "root", "owner password 1", Some(&c)).await;
    assert_eq!(res.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(res.headers.contains_key("retry-after"));
    // Failures of a real admin are audited (seen by the still-valid session).
    let failed = audit(&env, &root)
        .await
        .into_iter()
        .filter(|e| e["action"] == "session.login" && e["outcome"] == "failed")
        .count();
    assert_eq!(failed, 6);
}

#[tokio::test]
async fn the_source_address_is_rate_limited() {
    let env = env().await;
    let mut limited = false;
    for _ in 0..20 {
        let res = login_from(&env, "nobody", "some password", None, "192.0.2.9").await;
        if res.status == StatusCode::TOO_MANY_REQUESTS {
            limited = true;
            break;
        }
        assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    }
    assert!(limited);
}

#[tokio::test]
async fn sessions_end_on_logout_idleness_and_password_change() {
    let env = env().await;
    let root = owner(&env).await;
    let get = |a: &Admin| request(Method::GET, "/api/admin/session", None, Some(a));

    // Logout ends this session only.
    next_step(&env);
    let other = sign_in(&env, "root", "owner password 1", root.secret.clone()).await;
    let res = call(&env, Method::POST, "/api/admin/logout", None, &other).await;
    assert_eq!(res.status, StatusCode::NO_CONTENT);
    assert!(
        res.headers[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    assert_eq!(
        send(&env, get(&other)).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(send(&env, get(&root)).await.status, StatusCode::OK);

    // A password change ends every other session.
    next_step(&env);
    let other = sign_in(&env, "root", "owner password 1", root.secret.clone()).await;
    let body = json!({"currentPassword": "owner password 1", "newPassword": "owner password 2"});
    let res = call(&env, Method::POST, "/api/admin/password", Some(body), &root).await;
    assert_eq!(res.status, StatusCode::NO_CONTENT, "{}", res.json);
    assert_eq!(
        send(&env, get(&other)).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(send(&env, get(&root)).await.status, StatusCode::OK);
    let wrong = json!({"currentPassword": "nope nope", "newPassword": "owner password 3"});
    let res = call(
        &env,
        Method::POST,
        "/api/admin/password",
        Some(wrong),
        &root,
    )
    .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);

    // Idleness ends it.
    let t = now(&env) + IDLE_SECS;
    env.clock
        .set(time::OffsetDateTime::from_unix_timestamp(t).unwrap());
    assert_eq!(
        send(&env, get(&root)).await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn activity_keeps_a_session_alive_until_its_absolute_end() {
    let env = env().await;
    let root = owner(&env).await;
    let get = || request(Method::GET, "/api/admin/session", None, Some(&root));
    let start = now(&env);
    let expires = start + re_ofscp_server::admin::sessions::ABSOLUTE_SECS;
    let mut t = start;
    while t + IDLE_SECS / 2 < expires {
        t += IDLE_SECS / 2;
        env.clock
            .set(time::OffsetDateTime::from_unix_timestamp(t).unwrap());
        assert_eq!(
            send(&env, get()).await.status,
            StatusCode::OK,
            "at +{}",
            t - start
        );
    }
    env.clock
        .set(time::OffsetDateTime::from_unix_timestamp(expires).unwrap());
    assert_eq!(send(&env, get()).await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn conflicting_session_cookies_are_refused() {
    let env = env().await;
    let root = owner(&env).await;
    let mut req = request(Method::GET, "/api/admin/session", None, Some(&root));
    req.headers_mut().append(
        header::COOKIE,
        format!("{COOKIE}=as_planted").parse().unwrap(),
    );
    assert_eq!(send(&env, req).await.status, StatusCode::UNAUTHORIZED);
}
