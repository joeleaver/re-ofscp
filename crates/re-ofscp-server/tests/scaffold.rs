//! Scaffold-level checks: the deployed schema parses, and health answers.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use re_ofscp_server::{AppState, Config, router};
use re_ofscp_types::Health;
use tower::ServiceExt;

#[test]
fn schema_rhype_parses() {
    let src = include_str!("../../../schema.rhype");
    rhypedb_schema::parser::parse_schema(src).expect("schema.rhype must parse");
}

#[tokio::test]
async fn health_reports_degraded_without_a_database() {
    let config = Config::from_lookup(|k| match k {
        "DOMAIN" => Some("test.example".into()),
        // Nothing listens here, so the database probe must fail fast.
        "RHYPEDB_ADDR" => Some("127.0.0.1:9".into()),
        _ => None,
    })
    .unwrap();
    let app = router(AppState {
        config: Arc::new(config),
    });

    let res = app
        .oneshot(Request::get("/api/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.into_body().collect().await.unwrap().to_bytes();
    let health: Health = serde_json::from_slice(&body).unwrap();
    assert_eq!(health.domain, "test.example");
    assert_eq!(health.status, "degraded");
    assert!(!health.database);
}
