//! Group invite tokens never reach the logs (spec §5.6: providers SHOULD
//! NOT log invite tokens; docs/decisions/0019). Every request below names
//! a live token in its path; the provider's log output, captured at every
//! level, must name the route with a placeholder instead.

mod common;

use std::io;
use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use common::groups::{create_group, env_with_remotes, id, local, remote, request};
use common::harness::send;
use common::invites::{create_invite, token};
use common::members::group_with_policy;
use serde_json::json;
use tracing::level_filters::LevelFilter;

/// Log output, shared with the subscriber that writes it.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Captured {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

// A current-thread runtime, so the thread-local subscriber sees every
// span and event the requests make.
#[tokio::test(flavor = "current_thread")]
async fn invite_tokens_never_reach_the_logs() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let g = id(&create_group(
        &env,
        &alice,
        group_with_policy("private", "invite", json!({})),
    )
    .await);
    let t = token(&create_invite(&env, &alice, &g, json!({})).await);

    let logs = Captured::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_current_span(true)
        .with_span_list(true)
        .with_max_level(LevelFilter::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let redeem = format!("/api/invites/{t}/redeem");
    let guest = format!("/api/invites/{t}/guest");
    // Redeemed; redeemed again (already a member); unsigned; signed by an
    // unknown key (the signed-request rejection logs its path); and the
    // guest route.
    let (s, _, _, _) = send(
        &env.app,
        request(Some(&bob), "POST", &redeem, Some(&json!({}))),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, _, _) = send(
        &env.app,
        request(Some(&bob), "POST", &redeem, Some(&json!({}))),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, _, _) = send(&env.app, request(None, "POST", &redeem, Some(&json!({})))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let stranger = remote("mallory", "providerb.example");
    let (s, _, _, _) = send(
        &env.app,
        request(Some(&stranger), "POST", &redeem, Some(&json!({}))),
    )
    .await;
    assert!(s.is_client_error(), "{s}");
    let (s, _, _, _) = send(&env.app, request(None, "POST", &guest, Some(&json!({})))).await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    let text = logs.text();
    // The requests were logged, by route, with the token replaced.
    assert!(
        text.contains("/api/invites/{token}/redeem"),
        "no request was logged:\n{text}"
    );
    assert!(text.contains("rejected signed request"), "{text}");
    // Neither the token nor its random part appears anywhere.
    let secret = t.trim_start_matches("gi_");
    assert!(
        !text.contains(secret),
        "an invite token was logged:\n{text}"
    );
}
