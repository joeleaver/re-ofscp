//! Error responses conform to §2.6/§7.3 and the spec's problem-details schema.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use re_ofscp_server::problem::{EXTENSIONS, REGISTRY};
use re_ofscp_server::signing::StaticKeys;
use re_ofscp_server::{AppState, Config, router};
use tower::ServiceExt;

fn app() -> axum::Router {
    let config = Config::from_lookup(|k| match k {
        "DOMAIN" => Some("social.example".into()),
        "RHYPEDB_ADDR" => Some("127.0.0.1:9".into()),
        _ => None,
    })
    .unwrap();
    router(AppState::new(config, Arc::new(StaticKeys::default())))
}

async fn call(req: Request<Body>) -> (StatusCode, String, Vec<u8>) {
    let res = app().oneshot(req).await.unwrap();
    let status = res.status();
    let ct = res
        .headers()
        .get(header::CONTENT_TYPE)
        .map(|v| v.to_str().unwrap().to_owned())
        .unwrap_or_default();
    let body = res.into_body().collect().await.unwrap().to_bytes().to_vec();
    (status, ct, body)
}

#[tokio::test]
async fn router_errors_are_schema_valid_problems_on_our_authority() {
    let validator = common::schema("problem-details.json");
    let cases = [
        (
            Request::get("/nope").body(Body::empty()).unwrap(),
            404,
            "not_found",
        ),
        (
            Request::post("/api/health").body(Body::empty()).unwrap(),
            405,
            "method_not_allowed",
        ),
        (
            // Half-signed: rejected by the signature layer.
            Request::get("/api/health")
                .header("host", "social.example")
                .header("x-ofscp-nonce", "n")
                .body(Body::empty())
                .unwrap(),
            401,
            "unauthorized",
        ),
    ];
    for (req, status, code) in cases {
        let (got, ct, body) = call(req).await;
        assert_eq!(got.as_u16(), status);
        assert_eq!(ct, "application/problem+json");
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        common::assert_valid(&validator, &json);
        assert_eq!(json["errorCode"], code);
        assert_eq!(json["status"], status);
        assert_eq!(
            json["type"],
            format!("https://social.example/problems/{code}")
        );
    }
}

#[tokio::test]
async fn every_code_we_emit_fits_the_schema() {
    let validator = common::schema("problem-details.json");
    for c in REGISTRY.iter().chain(EXTENSIONS) {
        let instance = serde_json::json!({
            "type": format!("https://social.example/problems/{}", c.code),
            "title": c.title,
            "status": c.status,
            "errorCode": c.code,
        });
        common::assert_valid(&validator, &instance);
    }
}

#[test]
fn schema_check_is_not_vacuous() {
    // The pre-#17 shape (shared base, hyphenated slug, no errorCode) fails.
    let validator = common::schema("problem-details.json");
    let old = serde_json::json!({
        "type": "https://ofscp.org/problems/service-unavailable",
        "title": "Service Unavailable",
        "status": 503,
    });
    assert!(!validator.is_valid(&old));
}

#[tokio::test]
async fn type_urls_serve_descriptions() {
    for c in REGISTRY.iter().chain(EXTENSIONS) {
        let (status, ct, body) = call(
            Request::get(format!("/problems/{}", c.code))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(ct.starts_with("text/plain"));
        let text = String::from_utf8(body).unwrap();
        assert!(text.starts_with(c.code), "{text}");
    }
    let (status, ct, _) = call(
        Request::get("/problems/made_up")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(ct, "application/problem+json");
}

/// axum's own rejections (bad path encoding, JSON errors, missing content
/// type) leave as problems too.
#[tokio::test]
async fn framework_rejections_become_problems() {
    use axum::Json;
    use axum::routing::post;
    use re_ofscp_server::problem::{self, ProblemBase};
    use re_ofscp_types::Authority;

    #[derive(serde::Deserialize)]
    struct Body1 {
        #[allow(dead_code)]
        n: u32,
    }
    let base = ProblemBase::new(&Authority::parse_canonical("social.example").unwrap());
    let test_app = axum::Router::new()
        .route("/j", post(|Json(_): Json<Body1>| async { "ok" }))
        .layer(axum::middleware::map_response_with_state(
            base,
            problem::render,
        ));
    let validator = common::schema("problem-details.json");
    let cases = [
        // Malformed JSON → 400.
        (
            Request::post("/j")
                .header("content-type", "application/json")
                .body(Body::from("{"))
                .unwrap(),
            400,
            "bad_request",
        ),
        // Well-formed but wrong shape (axum: 422) → 400.
        (
            Request::post("/j")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"n":"x"}"#))
                .unwrap(),
            400,
            "bad_request",
        ),
        // No content type → 415.
        (
            Request::post("/j").body(Body::from("{}")).unwrap(),
            415,
            "unsupported_media_type",
        ),
    ];
    for (req, status, code) in cases {
        let res = test_app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status().as_u16(), status);
        assert_eq!(
            res.headers()[header::CONTENT_TYPE],
            "application/problem+json"
        );
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        common::assert_valid(&validator, &json);
        assert_eq!(json["errorCode"], code);
        assert!(json["detail"].as_str().is_some_and(|d| !d.is_empty()));
    }

    // And a bad path segment on the real router.
    let (status, ct, body) = call(Request::get("/problems/%FF").body(Body::empty()).unwrap()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(ct, "application/problem+json");
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    common::assert_valid(&validator, &json);
}

#[tokio::test]
async fn method_not_allowed_keeps_allow_header() {
    let res = app()
        .oneshot(Request::post("/api/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert!(res.headers().contains_key(header::ALLOW));
}
