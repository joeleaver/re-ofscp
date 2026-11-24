//! Requests against the admin API (tests/admin*.rs).

use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use re_ofscp_server::admin::totp;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::accounts::{Env, SETUP_TOKEN};

/// The session cookie's name.
pub const COOKIE: &str = "__Secure-re-ofscp-admin";

/// A response: status, JSON body, headers.
pub struct Res {
    pub status: StatusCode,
    pub json: Value,
    pub headers: HeaderMap,
}

impl Res {
    /// The session token the response's `Set-Cookie` carries.
    pub fn cookie(&self) -> Option<String> {
        let v = self.headers.get(header::SET_COOKIE)?.to_str().ok()?;
        let (pair, _) = v.split_once(';')?;
        let (name, value) = pair.split_once('=')?;
        (name == COOKIE && !value.is_empty()).then(|| value.to_owned())
    }
}

/// A signed-in admin as a browser would hold them.
#[derive(Clone)]
pub struct Admin {
    pub username: String,
    pub password: String,
    pub cookie: String,
    pub csrf: String,
    /// The TOTP secret, once enrolled.
    pub secret: Option<Vec<u8>>,
}

/// Build a request. `session` adds the cookie and, on mutations, the CSRF
/// header.
pub fn request(
    method: Method,
    path: &str,
    body: Option<Value>,
    session: Option<&Admin>,
) -> Request<Body> {
    request_from(method, path, body, session, "198.51.100.1")
}

/// [`request`] from client address `ip`.
pub fn request_from(
    method: Method,
    path: &str,
    body: Option<Value>,
    session: Option<&Admin>,
    ip: &str,
) -> Request<Body> {
    let mut b = Request::builder()
        .method(method.clone())
        .uri(path)
        .header("host", "providera.com")
        .header("x-test-ip", ip);
    if body.is_some() {
        b = b.header("content-type", "application/json");
    }
    if let Some(s) = session {
        b = b.header(header::COOKIE, format!("{COOKIE}={}", s.cookie));
        if method != Method::GET {
            b = b.header("x-csrf-token", &s.csrf);
        }
    }
    b.body(body.map_or_else(Body::empty, |v| Body::from(v.to_string())))
        .unwrap()
}

/// Send a request.
pub async fn send(env: &Env, req: Request<Body>) -> Res {
    let res = env.app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    Res {
        status,
        json: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        headers,
    }
}

/// `method path` as `session`, with `body`.
pub async fn call(
    env: &Env,
    method: Method,
    path: &str,
    body: Option<Value>,
    session: &Admin,
) -> Res {
    send(env, request(method, path, body, Some(session))).await
}

/// Unix seconds now, by the env's clock.
pub fn now(env: &Env) -> i64 {
    env.state.verifier.now()
}

/// The current code for `secret`.
pub fn code(env: &Env, secret: &[u8]) -> String {
    format!("{:06}", totp::code_at(secret, totp::step_at(now(env))))
}

/// Move the clock on by one TOTP step, so a fresh code is accepted.
pub fn next_step(env: &Env) {
    let t = now(env) + totp::STEP_SECS;
    env.clock
        .set(time::OffsetDateTime::from_unix_timestamp(t).unwrap());
}

/// `POST /api/admin/setup`.
pub async fn setup(env: &Env, username: &str, password: &str) -> Res {
    let body = json!({"setupToken": SETUP_TOKEN, "username": username, "password": password});
    send(
        env,
        request(Method::POST, "/api/admin/setup", Some(body), None),
    )
    .await
}

/// `POST /api/admin/login`, each from a fresh client address (so only the
/// per-username lockout applies).
pub async fn login(env: &Env, username: &str, password: &str, code: Option<&str>) -> Res {
    use std::sync::atomic::{AtomicU32, Ordering};
    static NEXT: AtomicU32 = AtomicU32::new(1);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let ip = format!("10.{}.{}.{}", (n >> 16) & 255, (n >> 8) & 255, n & 255);
    login_from(env, username, password, code, &ip).await
}

/// `POST /api/admin/login` from client address `ip`.
pub async fn login_from(
    env: &Env,
    username: &str,
    password: &str,
    code: Option<&str>,
    ip: &str,
) -> Res {
    let mut body = json!({"username": username, "password": password});
    if let Some(c) = code {
        body["code"] = json!(c);
    }
    send(
        env,
        request_from(Method::POST, "/api/admin/login", Some(body), None, ip),
    )
    .await
}

/// Sign in and keep the session (asserting success).
pub async fn sign_in(env: &Env, username: &str, password: &str, secret: Option<Vec<u8>>) -> Admin {
    let c = secret.as_ref().map(|s| code(env, s));
    let res = login(env, username, password, c.as_deref()).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    Admin {
        username: username.to_owned(),
        password: password.to_owned(),
        cookie: res.cookie().expect("session cookie"),
        csrf: res.json["csrfToken"].as_str().unwrap().to_owned(),
        secret,
    }
}

/// Enroll and confirm TOTP for a signed-in admin (asserting success).
pub async fn enroll(env: &Env, admin: &mut Admin) {
    let res = call(env, Method::POST, "/api/admin/totp/enroll", None, admin).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    let secret = data_encoding::BASE32_NOPAD
        .decode(res.json["secret"].as_str().unwrap().as_bytes())
        .unwrap();
    let body = json!({"code": code(env, &secret)});
    let res = call(
        env,
        Method::POST,
        "/api/admin/totp/confirm",
        Some(body),
        admin,
    )
    .await;
    assert_eq!(res.status, StatusCode::NO_CONTENT, "{}", res.json);
    admin.secret = Some(secret);
    // The confirming code's step is used; later sign-ins need a later one.
    next_step(env);
}

/// The first owner, set up, signed in and enrolled: a full session.
pub async fn owner(env: &Env) -> Admin {
    let res = setup(env, "root", "owner password 1").await;
    assert_eq!(res.status, StatusCode::CREATED, "{}", res.json);
    let mut admin = sign_in(env, "root", "owner password 1", None).await;
    enroll(env, &mut admin).await;
    admin
}

/// An admin created by `owner` with `role`, who has changed the initial
/// password and enrolled: a full session.
pub async fn admin_with_role(env: &Env, owner: &Admin, username: &str, role: &str) -> Admin {
    let body = json!({"username": username, "password": "initial password", "role": role});
    let res = call(env, Method::POST, "/api/admin/admins", Some(body), owner).await;
    assert_eq!(res.status, StatusCode::CREATED, "{}", res.json);
    let mut admin = sign_in(env, username, "initial password", None).await;
    let body = json!({"currentPassword": "initial password", "newPassword": "chosen password"});
    let res = call(env, Method::POST, "/api/admin/password", Some(body), &admin).await;
    assert_eq!(res.status, StatusCode::NO_CONTENT, "{}", res.json);
    admin.password = "chosen password".to_owned();
    enroll(env, &mut admin).await;
    admin
}

/// The audit log's entries (newest first) over the last day.
pub async fn audit(env: &Env, viewer: &Admin) -> Vec<Value> {
    let res = call(env, Method::GET, "/api/admin/audit", None, viewer).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.json);
    res.json["entries"].as_array().unwrap().clone()
}
