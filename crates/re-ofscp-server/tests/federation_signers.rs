//! The federation policy in the verifier and the outbound path (spec §4.5
//! step 6, §4.6 "No fetch is allowed", §8 *Authorization*;
//! docs/decisions/0008): a denied signer gets `403` after the replay check
//! and the digest, before any key (cached or fetched) is used, and its
//! nonce is never recorded; nothing is ever sent to a denied provider.

mod common;

use std::sync::Arc;

use axum::Router;
use axum::http::StatusCode;
use common::harness::{
    Req, SIGNED_AT, SettableClock, alice_keys, harness_policy, key, limits, new_key, send,
    signed_as,
};
use common::remote_peer::{RemotePeer, Reply, keys_doc, keys_path};
use re_ofscp_server::federation::{FederationPolicy, Rule, Snapshot};
use re_ofscp_server::outbound::{OutboundClient, OutboundError};
use re_ofscp_server::replay::NoLedger;
use re_ofscp_server::signing::Signer;
use re_ofscp_server::timefmt::rfc3339;
use re_ofscp_server::{AppState, Config, router};
use re_ofscp_types::federation::{FederationMode, RuleList, RuleScope};
use re_ofscp_types::{Actor, Authority};

const TIMESTAMP: &str = "2026-01-01T12:00:00Z";
const BOB: &str = "bob@chat.evil.example";

fn snapshot(mode: FederationMode, rules: &[(RuleList, RuleScope, &str)]) -> Snapshot {
    let mut s = Snapshot {
        mode,
        ..Snapshot::default()
    };
    for (i, (list, scope, value)) in rules.iter().enumerate() {
        s.list_mut(*list).insert(Rule {
            id: format!("r{i}"),
            list: *list,
            scope: *scope,
            value: (*value).to_owned(),
            note: String::new(),
            created_by: "test".to_owned(),
            created_at: 0,
        });
    }
    s
}

fn deny(value: &str) -> Snapshot {
    snapshot(
        FederationMode::Denylist,
        &[(RuleList::Deny, RuleScope::Domain, value)],
    )
}

/// The signature harness, with bob at `chat.evil.example` and the
/// provider `evil.example` known beside alice (local), under `policy`.
fn app(policy: Arc<FederationPolicy>) -> Router {
    let keys = alice_keys()
        .with(
            Signer::Actor(Actor::parse_canonical(BOB).unwrap()),
            "dk_abc123xyz",
            key().verifying_key(),
        )
        .with(
            Signer::Provider(Authority::parse_canonical("evil.example").unwrap()),
            "dk_abc123xyz",
            key().verifying_key(),
        );
    harness_policy(Arc::new(keys), SIGNED_AT, limits(1000), None, policy).app
}

/// Bob signs with the vector key under the same key id as alice, so he
/// needs his own nonce (the replay store is per key id, §4.5 step 4).
fn from_bob() -> Req {
    Req {
        identity: ("x-ofscp-actor", BOB.into()),
        nonce: "bob-nonce-1".into(),
        ..Req::vector()
    }
}

#[tokio::test]
async fn a_denied_signer_gets_403_and_its_nonce_stays_unused() {
    let policy = Arc::new(FederationPolicy::with(deny("evil.example")));
    let app = app(policy.clone());
    let (status, json, _, _) = send(&app, from_bob().build()).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{json}");
    assert_eq!(json["errorCode"], "forbidden");

    // A provider signer from the denied domain likewise.
    let provider = Req {
        identity: ("x-ofscp-provider", "evil.example".into()),
        nonce: "provider-nonce-1".into(),
        ..Req::vector()
    };
    assert_eq!(send(&app, provider.build()).await.0, StatusCode::FORBIDDEN);

    // Once federation is allowed, the very same request (same nonce) is
    // accepted: the refused one recorded nothing.
    policy.install(Snapshot::default());
    let (status, text) = {
        let (s, _, t, _) = send(&app, from_bob().build()).await;
        (s, t)
    };
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(text, format!("actor {BOB} dk_abc123xyz"));
}

#[tokio::test]
async fn earlier_steps_answer_first() {
    let policy = Arc::new(FederationPolicy::open());
    let app = app(policy.clone());
    // Accepted while open, so the nonce is used.
    assert_eq!(send(&app, from_bob().build()).await.0, StatusCode::OK);
    policy.install(deny("evil.example"));
    // Step 4 (replay) precedes the policy: 401, not 403.
    let (status, json, _, _) = send(&app, from_bob().build()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{json}");
    assert_eq!(json["detail"], "nonce already used for this key");
    // Step 5 (digest) precedes it too: 400.
    let tampered = Req {
        nonce: "fresh-nonce-2".into(),
        send_body: Some("{}".into()),
        ..from_bob()
    };
    assert_eq!(
        send(&app, tampered.build()).await.0,
        StatusCode::BAD_REQUEST
    );
    // A bad signature from a denied signer is never checked: 403.
    let forged = Req {
        nonce: "fresh-nonce-3".into(),
        signature: Some("AAAA".into()),
        ..from_bob()
    };
    assert_eq!(send(&app, forged.build()).await.0, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn local_signers_are_never_judged_by_the_policy() {
    // An allowlist naming nobody denies every remote provider.
    let policy = Arc::new(FederationPolicy::with(snapshot(
        FederationMode::Allowlist,
        &[],
    )));
    let app = app(policy);
    let (status, _, text, _) = send(&app, Req::vector().build()).await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(
        send(&app, from_bob().build()).await.0,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn an_unloaded_policy_refuses_remote_signers_temporarily() {
    let policy = Arc::new(FederationPolicy::unloaded());
    let app = app(policy.clone());
    let (status, json, _, retry) = send(&app, from_bob().build()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{json}");
    assert_eq!(retry.as_deref(), Some("5"));
    // Local signers do not wait for it.
    assert_eq!(send(&app, Req::vector().build()).await.0, StatusCode::OK);
    policy.install(Snapshot::default());
    assert_eq!(send(&app, from_bob().build()).await.0, StatusCode::OK);
}

/// The production router for `providera.com` with `peer` reachable, under
/// the outbound client's `policy`.
fn production(peer: &RemotePeer, policy: Arc<FederationPolicy>) -> Router {
    let allow = peer.authority().to_string();
    let config = Config::from_lookup(|k| match k {
        "DOMAIN" => Some("providera.com".into()),
        "PROVIDER_SIGNING_KEY" => Some(common::PROVIDER_SIGNING_KEY.into()),
        "RHYPEDB_ADDR" => Some("127.0.0.1:9".into()),
        "OUTBOUND_ALLOW_HOSTS" => Some(allow.clone()),
        _ => None,
    })
    .unwrap();
    let mut outbound = peer.config(config.outbound_allow_hosts.clone());
    outbound.policy = policy;
    let client = OutboundClient::new(&outbound).unwrap();
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
async fn a_cached_key_does_not_rescue_a_denied_actor_and_nothing_is_fetched() {
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
    let policy = Arc::new(FederationPolicy::open());
    let app = production(&peer, policy.clone());
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
    assert_eq!(send(&app, req()).await.0, StatusCode::OK);
    assert_eq!(peer.total_hits(), 1);

    // Deny exactly this provider (host and port).
    let exact = peer.authority().to_string();
    policy.install(snapshot(
        FederationMode::Denylist,
        &[(RuleList::Deny, RuleScope::Authority, &exact)],
    ));
    let (status, json, _, _) = send(&app, req()).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{json}");
    // An unknown key id would force a re-fetch; denied, it fetches nothing.
    let other = signed_as(
        &key,
        ("x-ofscp-actor", &actor),
        "dk_9",
        "GET",
        "/api/health",
        "",
        TIMESTAMP,
    );
    assert_eq!(send(&app, other).await.0, StatusCode::FORBIDDEN);
    assert_eq!(peer.total_hits(), 1);

    // An allowlist naming it lets it back in, from the cache.
    policy.install(snapshot(
        FederationMode::Allowlist,
        &[(RuleList::Allow, RuleScope::Authority, &exact)],
    ));
    assert_eq!(send(&app, req()).await.0, StatusCode::OK);
    assert_eq!(peer.total_hits(), 1);
}

#[tokio::test]
async fn the_outbound_client_never_contacts_a_denied_provider() {
    let peer = RemotePeer::start().await;
    peer.set("/doc", Reply::json(200, &serde_json::json!({})));
    let client = peer.allowed_client();
    let target = peer.authority();
    assert!(client.get(&target, "/doc").await.is_ok());
    assert_eq!(peer.total_hits(), 1);

    // Denial overrides the operator's internal-peer allowance.
    let exact = target.to_string();
    client.policy().install(snapshot(
        FederationMode::Denylist,
        &[(RuleList::Deny, RuleScope::Authority, &exact)],
    ));
    let err = client.get(&target, "/doc").await.unwrap_err();
    assert_eq!(err, OutboundError::Denied(exact.clone()));
    assert!(matches!(
        client.target(&target, "/doc"),
        Err(OutboundError::Denied(_))
    ));

    // A reservation made before a denial is not sent after it.
    client.policy().install(Snapshot::default());
    let reservation = client.reserve(&target, "/doc").unwrap();
    client.policy().install(snapshot(
        FederationMode::Denylist,
        &[(RuleList::Deny, RuleScope::Authority, &exact)],
    ));
    let err = client.get_reserved(reservation).await.unwrap_err();
    assert_eq!(err, OutboundError::Denied(exact));

    // Before the policy loads nothing is sent at all.
    let unloaded = {
        let mut config = peer.config(vec![target.clone()]);
        config.policy = Arc::new(FederationPolicy::unloaded());
        OutboundClient::new(&config).unwrap()
    };
    assert_eq!(
        unloaded.get(&target, "/doc").await.unwrap_err(),
        OutboundError::PolicyUnknown
    );
    assert_eq!(peer.total_hits(), 1);
}
