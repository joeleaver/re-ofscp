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
use common::harness::{SIGNED_AT, SettableClock, alice_keys, key, new_key, send, signed_as};
use common::remote_peer::{DISCOVERY_PATH, RemotePeer, Reply, discovery_doc};
use ed25519_dalek::SigningKey;
use re_ofscp_server::federation::{FederationPolicy, Rule, Snapshot};
use re_ofscp_server::outbound::OutboundClient;
use re_ofscp_server::replay::NoLedger;
use re_ofscp_server::{AppState, Config, router};
use re_ofscp_types::federation::{FederationMode, RuleList, RuleScope};

const TIMESTAMP: &str = "2026-01-01T12:00:00Z";
const ALICE: &str = "alice@providera.com";
const ALICE_KEY_ID: &str = "dk_abc123xyz";

#[tokio::test]
async fn during_the_warm_up_a_denied_actor_still_gets_403() {
    // The §8 deny check comes before the warm-up `503`: a denied actor's
    // signature is never verified, so it gets its `403` during the warm-up
    // too, with no key fetched and no nonce recorded (§4.5 *Restarts*).
    let key = new_key();
    let peer = peer_publishing(&key).await;
    let (app, state) = production(&peer, deny(&peer), 0);
    let actor = format!("alice@{}", peer.authority());
    for (method, path, body) in ROUTES {
        let req = signed_as(
            &key,
            ("x-ofscp-actor", &actor),
            "dk_1",
            method,
            path,
            body,
            TIMESTAMP,
        );
        let (status, json, _, retry) = send(&app, req).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}: {json}");
        assert_eq!(json["errorCode"], "forbidden", "{method} {path}");
        assert_eq!(retry, None, "{method} {path}");
    }
    // A bad digest is still answered first (§8 *Authorization*: "a digest
    // `400` from those steps wins").
    let mut tampered = signed_as(
        &key,
        ("x-ofscp-actor", &actor),
        "dk_1",
        "POST",
        "/api/groups",
        "{}",
        TIMESTAMP,
    );
    *tampered.body_mut() = axum::body::Body::from(r#"{"name":"x"}"#);
    assert_eq!(send(&app, tampered).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(peer.total_hits(), 0, "no key fetch");
    let now = SIGNED_AT.unix_timestamp();
    assert!(state.verifier.replay_store().is_empty(now), "no nonce");
}

#[tokio::test]
async fn a_provider_signed_websocket_upgrade_is_refused_before_upgrading() {
    // `/api/ws` is a route of this specification, and an upgrade carrying
    // `X-OFSCP-Provider` is a signed request (§4.5), so it gets `401` (or
    // `403`) like every other route instead of a socket (§8 *Authorization*;
    // docs/decisions/0021).
    let key = new_key();
    let peer = peer_publishing(&key).await;
    for (policy, status) in [
        (Arc::new(FederationPolicy::open()), 401),
        (deny(&peer), 403),
    ] {
        let (app, state) = production(&peer, policy, 301);
        let addr = common::ws::serve(app).await;
        let signed = from_provider(&key, &peer, "GET", "/api/ws", "");
        let refused = common::ws::Client::try_connect_with(addr, signed.headers()).await;
        assert_eq!(refused.err(), Some(status));
        let now = SIGNED_AT.unix_timestamp();
        assert!(state.verifier.replay_store().is_empty(now), "no nonce");
    }
    assert_eq!(peer.total_hits(), 0, "no discovery or key fetch");
}

#[tokio::test]
async fn an_actor_signed_websocket_upgrade_verifies_then_authenticates_in_band() {
    // An upgrade signed by a local user's device key is verified like any
    // signed `GET` (its nonce recorded), the socket opens, and the ordinary
    // `authenticate` handshake then runs inside it (§4.5, §7.1;
    // docs/decisions/0021).
    let provider = common::ws::Provider::with_alice(
        common::ws::fast_config(),
        re_ofscp_server::ws::Seams::default(),
    )
    .await;
    let signed = signed_as(
        &key(),
        ("x-ofscp-actor", ALICE),
        ALICE_KEY_ID,
        "GET",
        "/api/ws",
        "",
        TIMESTAMP,
    );
    let mut headers = signed.headers().clone();
    headers.insert("x-test-ip", "198.51.100.7".parse().unwrap());
    let client = common::ws::Client::try_connect_with(provider.addr, &headers).await;
    let mut client = client.unwrap_or_else(|status| panic!("upgrade refused: {status}"));
    let now = SIGNED_AT.unix_timestamp();
    assert!(
        !provider.state.verifier.replay_store().is_empty(now),
        "the verified upgrade's nonce is recorded"
    );
    client
        .authenticate(ALICE, ALICE_KEY_ID, &key(), provider.now())
        .await;

    // During the replay store's restart warm-up the same upgrade would be
    // verified, so it gets `503` (§4.5 *Restarts*); an unsigned upgrade
    // still opens and authenticates in band.
    let warming = common::ws::Provider::started_ago(0, None, common::ws::fast_config(), |b| {
        b.keys(Arc::new(alice_keys()))
    })
    .await;
    let signed = signed_as(
        &key(),
        ("x-ofscp-actor", ALICE),
        ALICE_KEY_ID,
        "GET",
        "/api/ws",
        "",
        TIMESTAMP,
    );
    let refused = common::ws::Client::try_connect_with(warming.addr, signed.headers()).await;
    assert_eq!(refused.err(), Some(503));
    warming.alice("198.51.100.8").await;
}

/// One route of each kind: (method, path, body). A signed-only route, an
/// anonymous-reader route (§5.5 GET group), discovery (§3.1), the keys
/// endpoint (§4.6) and the WebSocket upgrade (§7.1).
const ROUTES: [(&str, &str, &str); 6] = [
    ("POST", "/api/groups", r#"{"name":"g"}"#),
    ("GET", "/api/me", ""),
    ("GET", "/api/groups/g_1", ""),
    ("GET", "/.well-known/ofscp-provider", ""),
    ("GET", "/.well-known/ofscp/users/alice/keys", ""),
    ("GET", "/api/ws", ""),
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
