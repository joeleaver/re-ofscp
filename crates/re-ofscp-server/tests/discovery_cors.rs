//! The discovery document (§3.1) and cross-origin access (§3.4), through
//! the full router over a real rhypedb-server.

mod common;

use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use common::accounts::{Env, EnvOptions, env, env_with};
use http_body_util::BodyExt as _;
use re_ofscp_server::cors::{ALLOW_HEADERS, ALLOW_METHODS, EXPOSE_HEADERS};
use re_ofscp_server::discovery::CACHE_CONTROL_VALUE;
use tower::ServiceExt as _;

/// Forumall's web client.
const ORIGIN: &str = "https://lostconnection.dev";

/// What a browser sends before a signed cross-origin GET.
const REQUESTED_HEADERS: &str =
    "x-ofscp-actor,x-ofscp-signature,x-ofscp-timestamp,x-ofscp-nonce,x-ofscp-key-id";

async fn call(env: &Env, req: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
    let res = env.app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let body = res.into_body().collect().await.unwrap().to_bytes().to_vec();
    (status, headers, body)
}

fn request(method: Method, path: &str, extra: &[(&str, &str)]) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "providera.com")
        .header("x-test-ip", "198.51.100.7");
    for (k, v) in extra {
        b = b.header(*k, *v);
    }
    b.body(Body::empty()).unwrap()
}

fn preflight(path: &str) -> Request<Body> {
    request(
        Method::OPTIONS,
        path,
        &[
            ("origin", ORIGIN),
            ("access-control-request-method", "GET"),
            ("access-control-request-headers", REQUESTED_HEADERS),
        ],
    )
}

fn header<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get(name).map(|v| v.to_str().unwrap())
}

fn varies_on_origin(h: &HeaderMap) -> bool {
    h.get_all(header::VARY)
        .iter()
        .flat_map(|v| v.to_str().unwrap().split(','))
        .any(|v| v.trim().eq_ignore_ascii_case("origin"))
}

/// No CORS header of any kind.
fn assert_no_cors(h: &HeaderMap, what: &str) {
    for name in [
        "access-control-allow-origin",
        "access-control-allow-methods",
        "access-control-allow-headers",
        "access-control-expose-headers",
        "access-control-allow-credentials",
        "access-control-max-age",
    ] {
        assert!(h.get(name).is_none(), "{what}: unexpected {name}");
    }
}

/// The headers every response to a request with `Origin` carries (§3.4).
fn assert_cors_response(h: &HeaderMap, what: &str) {
    assert_eq!(
        header(h, "access-control-allow-origin"),
        Some("*"),
        "{what}"
    );
    assert_eq!(
        header(h, "access-control-expose-headers"),
        Some(EXPOSE_HEADERS),
        "{what}"
    );
    assert!(varies_on_origin(h), "{what}: Vary: Origin");
    assert!(
        h.get("access-control-allow-credentials").is_none(),
        "{what}: credentials must never be allowed"
    );
}

#[tokio::test]
async fn discovery_validates_against_the_spec_schema() {
    let env = env().await;
    let (status, h, body) = call(
        &env,
        request(Method::GET, "/.well-known/ofscp-provider", &[]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(header(&h, "content-type"), Some("application/json"));
    assert_eq!(header(&h, "cache-control"), Some(CACHE_CONTROL_VALUE));
    assert!(header(&h, "etag").is_some());

    let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let schema = common::schema("provider-discovery.json");
    let errors: Vec<String> = schema.iter_errors(&doc).map(|e| e.to_string()).collect();
    assert!(errors.is_empty(), "schema errors: {errors:?}\n{doc:#}");

    let p = &doc["provider"];
    assert_eq!(p["domain"], "providera.com");
    assert_eq!(p["protocolVersion"], "0.1.0");
    assert_eq!(p["software"]["name"], "re-ofscp");
    assert_eq!(p["contact"], "mailto:admin@providera.com");
    let auth = &p["authentication"];
    assert_eq!(
        auth["login_endpoint"],
        "https://providera.com/api/auth/login"
    );
    assert_eq!(
        auth["registration_endpoint"],
        "https://providera.com/api/auth/register"
    );
    assert_eq!(auth["registration"], "invite");

    // The one published key is the configured one; no private material.
    let expected = env.state.config.provider_key.public_entry();
    let keys = p["publicKeys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["key_id"], expected.key_id);
    assert_eq!(keys[0]["algorithm"], "Ed25519");
    assert_eq!(keys[0]["public_key"], expected.public_key);
    assert!(!String::from_utf8_lossy(&body).contains(common::PROVIDER_SIGNING_KEY));

    let caps = &doc["capabilities"];
    assert_eq!(caps["federation"]["realtimeDelivery"], "none");
    assert_eq!(caps["discovery"]["sharesKnownProviders"], false);
    assert_eq!(caps["discovery"]["discoverFeed"], false);
}

#[tokio::test]
async fn closed_provider_discovery_validates_without_registration_endpoint() {
    let env = env_with(EnvOptions {
        registration: Some("closed"),
        ..EnvOptions::default()
    })
    .await;
    let (status, _, body) = call(
        &env,
        request(Method::GET, "/.well-known/ofscp-provider", &[]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let schema = common::schema("provider-discovery.json");
    assert!(schema.is_valid(&doc), "{doc:#}");
    let auth = &doc["provider"]["authentication"];
    assert_eq!(auth["registration"], "closed");
    assert!(auth.get("registration_endpoint").is_none());
}

#[tokio::test]
async fn discovery_answers_conditional_requests_with_304() {
    let env = env().await;
    let (_, h, _) = call(
        &env,
        request(Method::GET, "/.well-known/ofscp-provider", &[]),
    )
    .await;
    let etag = header(&h, "etag").unwrap().to_owned();

    let (status, h, body) = call(
        &env,
        request(
            Method::GET,
            "/.well-known/ofscp-provider",
            &[("if-none-match", &etag)],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_MODIFIED);
    assert!(body.is_empty());
    assert_eq!(header(&h, "etag"), Some(etag.as_str()));
    assert_eq!(header(&h, "cache-control"), Some(CACHE_CONTROL_VALUE));

    let (status, _, _) = call(
        &env,
        request(
            Method::GET,
            "/.well-known/ofscp-provider",
            &[("if-none-match", "\"stale\"")],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn preflight_is_allowed_on_ofscp_paths() {
    let env = env().await;
    for path in [
        "/api/health",
        "/api/auth/device-keys",
        "/api/no-such-endpoint",
        "/.well-known/ofscp-provider",
        "/.well-known/ofscp/users/alice/keys",
    ] {
        let (status, h, body) = call(&env, preflight(path)).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{path}");
        assert!(body.is_empty(), "{path}");
        assert_cors_response(&h, path);
        assert_eq!(
            header(&h, "access-control-allow-methods"),
            Some(ALLOW_METHODS)
        );
        assert_eq!(
            header(&h, "access-control-allow-headers"),
            Some(ALLOW_HEADERS)
        );
        assert_eq!(header(&h, "access-control-max-age"), Some("600"));
        // Every header Forumall's client asks for is allowed.
        let allowed: Vec<&str> = ALLOW_HEADERS.split(", ").collect();
        for wanted in REQUESTED_HEADERS.split(',') {
            assert!(allowed.contains(&wanted), "{path}: {wanted}");
        }
    }
}

#[tokio::test]
async fn admin_paths_get_no_cors() {
    let env = env().await;
    for path in [
        "/api/admin/session",
        "/api/admin/login",
        "/admin",
        "/admin/",
    ] {
        let (status, h, _) = call(&env, preflight(path)).await;
        assert_ne!(status, StatusCode::NO_CONTENT, "{path}");
        assert!(!status.is_success(), "{path}: {status}");
        assert_no_cors(&h, path);

        let (_, h, _) = call(&env, request(Method::GET, path, &[("origin", ORIGIN)])).await;
        assert_no_cors(&h, path);
    }
}

#[tokio::test]
async fn responses_to_cross_origin_requests_carry_cors_headers() {
    let env = env().await;
    // Success, a problem response, and a signature rejection alike.
    for (path, want) in [
        ("/api/health", StatusCode::OK),
        ("/.well-known/ofscp-provider", StatusCode::OK),
        ("/api/no-such-endpoint", StatusCode::NOT_FOUND),
        ("/api/auth/device-keys", StatusCode::UNAUTHORIZED),
    ] {
        let (status, h, _) = call(&env, request(Method::GET, path, &[("origin", ORIGIN)])).await;
        assert_eq!(status, want, "{path}");
        assert_cors_response(&h, path);
    }
}

#[tokio::test]
async fn options_without_a_requested_method_is_not_a_preflight() {
    let env = env().await;
    let (status, h, _) = call(
        &env,
        request(Method::OPTIONS, "/api/health", &[("origin", ORIGIN)]),
    )
    .await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    // Still a response to a request with Origin.
    assert_cors_response(&h, "plain OPTIONS");
    assert!(h.get("access-control-allow-methods").is_none());
}

#[tokio::test]
async fn same_origin_requests_get_vary_but_no_cors_headers() {
    let env = env().await;
    let (status, h, _) = call(
        &env,
        request(Method::GET, "/.well-known/ofscp-provider", &[]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(varies_on_origin(&h));
    assert_no_cors(&h, "no Origin");
}
