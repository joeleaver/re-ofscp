//! Signed requests from remote actors and remote providers, verified through
//! the production router against keys fetched from a local https "remote
//! provider" (spec §4.5 step 6, §4.6, §8.1; docs/decisions/0006).

mod common;

use std::sync::Arc;

use axum::Router;
use axum::http::StatusCode;
use common::harness::{SIGNED_AT, SettableClock, new_key, send, signed_as};
use common::remote_peer::{DISCOVERY_PATH, RemotePeer, Reply, discovery_doc, keys_doc, keys_path};
use re_ofscp_server::outbound::OutboundClient;
use re_ofscp_server::replay::NoLedger;
use re_ofscp_server::timefmt::rfc3339;
use re_ofscp_server::{AppState, Config, router};

const TIMESTAMP: &str = "2026-01-01T12:00:00Z";

/// The production router for `providera.com`, past its replay warm-up,
/// allowing `peer` as an internal peer (as `OUTBOUND_ALLOW_HOSTS` would)
/// and trusting its test CA.
fn app(peer: &RemotePeer) -> Router {
    let allow = peer.authority().to_string();
    let config = Config::from_lookup(|k| match k {
        "DOMAIN" => Some("providera.com".into()),
        // No database: remote signers never touch the account store.
        "RHYPEDB_ADDR" => Some("127.0.0.1:9".into()),
        "OUTBOUND_ALLOW_HOSTS" => Some(allow.clone()),
        _ => None,
    })
    .unwrap();
    let client = OutboundClient::new(&peer.config(config.outbound_allow_hosts.clone())).unwrap();
    let clock = SettableClock::at(SIGNED_AT - time::Duration::seconds(301));
    let state = AppState::builder(config)
        .ledger(Arc::new(NoLedger))
        .outbound(Arc::new(client))
        .clock(clock.clone())
        .build()
        .unwrap();
    clock.set(SIGNED_AT);
    router(state)
}

#[tokio::test]
async fn a_remote_actor_is_verified_with_keys_from_its_provider() {
    let peer = RemotePeer::start().await;
    let key = new_key();
    let actor = format!("alice@{}", peer.authority());
    let until = rfc3339(SIGNED_AT.unix_timestamp() + 600);
    peer.set(
        &keys_path("alice"),
        Reply::json(
            200,
            &keys_doc(&actor, &[("dk_1", key.verifying_key())], &until),
        ),
    );
    let app = app(&peer);
    let req = || {
        signed_as(
            &key,
            ("x-ofscp-actor", &actor),
            "dk_1",
            "GET",
            "/api/health",
            "",
            TIMESTAMP,
        )
    };
    let (status, _, text, _) = send(&app, req()).await;
    assert_eq!(status, StatusCode::OK, "{text}");
    // A second request uses the cache.
    assert_eq!(send(&app, req()).await.0, StatusCode::OK);
    assert_eq!(peer.hits(&keys_path("alice")), 1);

    // A key the provider does not publish: one re-fetch, then 401.
    let other = new_key();
    let forged = signed_as(
        &other,
        ("x-ofscp-actor", &actor),
        "dk_2",
        "GET",
        "/api/health",
        "",
        TIMESTAMP,
    );
    let (status, json, _, _) = send(&app, forged).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["detail"], "unknown or revoked key");
    assert_eq!(peer.hits(&keys_path("alice")), 2);

    // Someone else's key under alice's key id: the cached key fails, the
    // re-fetch is rate-limited and the cached key still fails: 401.
    let wrong = signed_as(
        &other,
        ("x-ofscp-actor", &actor),
        "dk_1",
        "GET",
        "/api/health",
        "",
        TIMESTAMP,
    );
    let (status, json, _, _) = send(&app, wrong).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["detail"], "signature does not verify");
    assert_eq!(peer.hits(&keys_path("alice")), 2);
}

#[tokio::test]
async fn a_remote_provider_is_verified_with_its_discovery_keys() {
    let peer = RemotePeer::start().await;
    let key = new_key();
    let authority = peer.authority().to_string();
    peer.set(
        DISCOVERY_PATH,
        Reply::json(
            200,
            &discovery_doc(&authority, &[("pk_1", key.verifying_key())]),
        ),
    );
    let app = app(&peer);
    let req = signed_as(
        &key,
        ("x-ofscp-provider", &authority),
        "pk_1",
        "GET",
        "/api/health",
        "",
        TIMESTAMP,
    );
    let (status, _, text, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(peer.hits(DISCOVERY_PATH), 1);
}

#[tokio::test]
async fn an_unreachable_provider_is_503_with_retry_after() {
    let peer = RemotePeer::start().await;
    peer.set(&keys_path("alice"), Reply::new(502, ""));
    let app = app(&peer);
    let actor = format!("alice@{}", peer.authority());
    let req = signed_as(
        &new_key(),
        ("x-ofscp-actor", &actor),
        "dk_1",
        "GET",
        "/api/health",
        "",
        TIMESTAMP,
    );
    let (status, json, _, retry) = send(&app, req).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json["errorCode"], "service_unavailable");
    assert_eq!(retry.as_deref(), Some("5"));
}

#[tokio::test]
async fn a_provider_on_a_refused_address_is_401() {
    // Not in OUTBOUND_ALLOW_HOSTS: loopback is refused, deterministically.
    let peer = RemotePeer::start().await;
    let app = app(&peer);
    let actor = format!("alice@{}", peer.ip_authority());
    let req = signed_as(
        &new_key(),
        ("x-ofscp-actor", &actor),
        "dk_1",
        "GET",
        "/api/health",
        "",
        TIMESTAMP,
    );
    let (status, json, _, retry) = send(&app, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["errorCode"], "unauthorized");
    assert_eq!(retry, None);
    assert_eq!(peer.total_hits(), 0);
}
