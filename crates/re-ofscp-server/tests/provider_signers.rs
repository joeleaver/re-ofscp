//! Provider-signed requests (`X-OFSCP-Provider`) through the production
//! router (spec §4.5 *Anonymous viewers* and *Restarts*, §5.5, §8
//! *Authorization*, §8.1; lost-conn/ofscp#42, merged at spec 8ffa97b;
//! docs/decisions/0021).
//!
//! No route of this provider accepts provider signatures. A provider-signed
//! request passes or fails §4.5 steps 1–5, then gets `403` from a denied
//! provider and `401` from any other, on every route: signed ones,
//! anonymous-reader ones (never treated as an anonymous viewer), discovery
//! and the keys endpoint. The signer's discovery document is never fetched,
//! the signature never checked and the nonce never recorded, so the
//! replay store's restart warm-up does not apply to these answers.

mod common;

use std::sync::Arc;

use axum::Router;
use axum::http::StatusCode;
use common::harness::{SIGNED_AT, SettableClock, new_key, send, signed_as};
use common::remote_peer::{DISCOVERY_PATH, RemotePeer, Reply, discovery_doc};
use ed25519_dalek::SigningKey;
use re_ofscp_server::federation::{FederationPolicy, Rule, Snapshot};
use re_ofscp_server::outbound::OutboundClient;
use re_ofscp_server::replay::NoLedger;
use re_ofscp_server::{AppState, Config, router};
use re_ofscp_types::federation::{FederationMode, RuleList, RuleScope};

const TIMESTAMP: &str = "2026-01-01T12:00:00Z";

/// One route of each kind: (method, path, body). A signed-only route, an
/// anonymous-reader route (§5.5 GET group), discovery (§3.1) and the keys
/// endpoint (§4.6).
const ROUTES: [(&str, &str, &str); 5] = [
    ("POST", "/api/groups", r#"{"name":"g"}"#),
    ("GET", "/api/me", ""),
    ("GET", "/api/groups/g_1", ""),
    ("GET", "/.well-known/ofscp-provider", ""),
    ("GET", "/.well-known/ofscp/users/alice/keys", ""),
];

/// The production router for `providera.com`, with `peer` reachable (as
/// `OUTBOUND_ALLOW_HOSTS` would allow) under `policy`, its replay store
/// started `warmed` seconds before the request timestamp. Also returns the
/// state, to inspect its replay store.
fn production(peer: &RemotePeer, policy: Arc<FederationPolicy>, warmed: i64) -> (Router, AppState) {
    let allow = peer.authority().to_string();
    let config = Config::from_lookup(|k| match k {
        "DOMAIN" => Some("providera.com".into()),
        "PROVIDER_SIGNING_KEY" => Some(common::PROVIDER_SIGNING_KEY.into()),
        // No database: nothing here may reach a handler or the account store.
        "RHYPEDB_ADDR" => Some("127.0.0.1:9".into()),
        "OUTBOUND_ALLOW_HOSTS" => Some(allow.clone()),
        _ => None,
    })
    .unwrap();
    let mut outbound = peer.config(config.outbound_allow_hosts.clone());
    outbound.policy = policy;
    let client = OutboundClient::new(&outbound).unwrap();
    let clock = SettableClock::at(SIGNED_AT - time::Duration::seconds(warmed));
    let state = AppState::builder(config)
        .ledger(Arc::new(NoLedger))
        .outbound(Arc::new(client))
        .clock(clock.clone())
        .build()
        .unwrap();
    clock.set(SIGNED_AT);
    (router(state.clone()), state)
}

/// A peer that would answer a discovery fetch with `key` as `pk_1`, so a
/// fetch (if one were made) would succeed and the signature would verify.
async fn peer_publishing(key: &SigningKey) -> RemotePeer {
    let peer = RemotePeer::start().await;
    let authority = peer.authority().to_string();
    peer.set(
        DISCOVERY_PATH,
        Reply::json(
            200,
            &discovery_doc(&authority, &[("pk_1", key.verifying_key())]),
        ),
    );
    peer
}

/// A genuine request signed by `peer` as a provider.
fn from_provider(
    key: &SigningKey,
    peer: &RemotePeer,
    method: &str,
    path: &str,
    body: &str,
) -> axum::http::Request<axum::body::Body> {
    let authority = peer.authority().to_string();
    signed_as(
        key,
        ("x-ofscp-provider", &authority),
        "pk_1",
        method,
        path,
        body,
        TIMESTAMP,
    )
}

fn deny(peer: &RemotePeer) -> Arc<FederationPolicy> {
    let mut s = Snapshot {
        mode: FederationMode::Denylist,
        ..Snapshot::default()
    };
    s.list_mut(RuleList::Deny).insert(Rule {
        id: "r0".to_owned(),
        list: RuleList::Deny,
        scope: RuleScope::Authority,
        value: peer.authority().to_string(),
        note: String::new(),
        created_by: "test".to_owned(),
        created_at: 0,
    });
    Arc::new(FederationPolicy::with(s))
}

/// Every route answers `status` with `error_code` to a genuine provider
/// signature from `peer`, twice (the first recorded no nonce, so the second
/// is no replay), and nothing is fetched or recorded.
async fn every_route_answers(
    app: &Router,
    state: &AppState,
    peer: &RemotePeer,
    key: &SigningKey,
    status: StatusCode,
    error_code: &str,
) {
    for (method, path, body) in ROUTES {
        for attempt in 0..2 {
            let req = from_provider(key, peer, method, path, body);
            let (got, json, _, retry) = send(app, req).await;
            assert_eq!(got, status, "{method} {path} #{attempt}: {json}");
            assert_eq!(json["errorCode"], error_code, "{method} {path}");
            assert_eq!(
                json["type"],
                format!("https://providera.com/problems/{error_code}"),
            );
            assert_eq!(retry, None, "{method} {path}");
        }
    }
    assert_eq!(peer.total_hits(), 0, "no discovery or key fetch");
    let now = SIGNED_AT.unix_timestamp();
    assert!(state.verifier.replay_store().is_empty(now), "no nonce");
}

#[tokio::test]
async fn a_permitted_provider_gets_401_on_every_route_without_a_fetch() {
    let key = new_key();
    let peer = peer_publishing(&key).await;
    let (app, state) = production(&peer, Arc::new(FederationPolicy::open()), 301);
    every_route_answers(
        &app,
        &state,
        &peer,
        &key,
        StatusCode::UNAUTHORIZED,
        "unauthorized",
    )
    .await;
    let req = from_provider(&key, &peer, "GET", "/api/groups/g_1", "");
    let json = send(&app, req).await.1;
    assert_eq!(
        json["detail"],
        "this route does not accept provider signatures"
    );
}

#[tokio::test]
async fn our_own_provider_signature_is_401_too() {
    // This provider's own authority is never subject to its policy, and its
    // own signature is no more accepted than anyone's.
    let peer = RemotePeer::start().await;
    let (app, state) = production(&peer, Arc::new(FederationPolicy::open()), 301);
    let ours = state.config.provider_key.clone();
    let req = signed_as(
        ours.signing_key(),
        ("x-ofscp-provider", "providera.com"),
        ours.key_id(),
        "GET",
        "/api/groups/g_1",
        "",
        TIMESTAMP,
    );
    let (status, json, _, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{json}");
    assert_eq!(
        json["detail"],
        "this route does not accept provider signatures"
    );
    assert!(
        state
            .verifier
            .replay_store()
            .is_empty(SIGNED_AT.unix_timestamp())
    );
}

#[tokio::test]
async fn a_denied_provider_gets_403_on_every_route_without_a_fetch() {
    let key = new_key();
    let peer = peer_publishing(&key).await;
    let (app, state) = production(&peer, deny(&peer), 301);
    every_route_answers(
        &app,
        &state,
        &peer,
        &key,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
}

#[tokio::test]
async fn steps_one_to_five_still_answer_first() {
    let key = new_key();
    let peer = peer_publishing(&key).await;
    for policy in [Arc::new(FederationPolicy::open()), deny(&peer)] {
        let (app, _) = production(&peer, policy, 301);
        // Step 3: a stale timestamp is 401 whatever the policy says.
        let authority = peer.authority().to_string();
        let stale = signed_as(
            &key,
            ("x-ofscp-provider", &authority),
            "pk_1",
            "GET",
            "/api/health",
            "",
            "2026-01-01T11:00:00Z",
        );
        let (status, json, _, _) = send(&app, stale).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{json}");
        assert_eq!(
            json["detail"],
            "X-OFSCP-Timestamp is outside the allowed clock skew"
        );
        // Step 5: a body that does not match its digest is 400.
        let mut tampered = from_provider(&key, &peer, "POST", "/api/groups", "{}");
        *tampered.body_mut() = axum::body::Body::from(r#"{"name":"x"}"#);
        assert_eq!(send(&app, tampered).await.0, StatusCode::BAD_REQUEST);
    }
    assert_eq!(peer.total_hits(), 0);
}

#[tokio::test]
async fn during_the_warm_up_providers_still_get_401_or_403() {
    // Started exactly at the request timestamp: deep inside the warm-up,
    // where a signature that would be verified gets 503 (§4.5 *Restarts*).
    let key = new_key();
    let peer = peer_publishing(&key).await;
    let (app, state) = production(&peer, Arc::new(FederationPolicy::open()), 0);
    let actor = format!("alice@{}", peer.authority());
    let req = signed_as(
        &key,
        ("x-ofscp-actor", &actor),
        "dk_1",
        "GET",
        "/api/groups/g_1",
        "",
        TIMESTAMP,
    );
    let (status, json, _, retry) = send(&app, req).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{json}");
    assert_eq!(retry.as_deref(), Some("301"));
    every_route_answers(
        &app,
        &state,
        &peer,
        &key,
        StatusCode::UNAUTHORIZED,
        "unauthorized",
    )
    .await;

    let (app, state) = production(&peer, deny(&peer), 0);
    every_route_answers(
        &app,
        &state,
        &peer,
        &key,
        StatusCode::FORBIDDEN,
        "forbidden",
    )
    .await;
}
