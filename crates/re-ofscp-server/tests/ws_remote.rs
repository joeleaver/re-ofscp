//! WebSocket connections of remote actors (spec §7.1 "For a connection
//! from a remote actor", lost-conn/ofscp#20; §8 federation policy),
//! against a local https "remote provider".

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::harness::new_key;
use common::remote_peer::{RemotePeer, Reply, keys_doc, keys_path};
use common::ws::{Client, Provider, fast_config};
use ed25519_dalek::SigningKey;
use re_ofscp_server::federation::{FederationPolicy, Rule, Snapshot};
use re_ofscp_server::outbound::OutboundClient;
use re_ofscp_server::timefmt::rfc3339;
use re_ofscp_types::Authority;
use re_ofscp_types::federation::{FederationMode, RuleList, RuleScope};
use serde_json::json;

/// A denylist policy denying `provider`.
fn denying(provider: &Authority) -> Snapshot {
    let mut s = Snapshot {
        mode: FederationMode::Denylist,
        ..Snapshot::default()
    };
    s.deny.insert(Rule {
        id: "r1".to_owned(),
        list: RuleList::Deny,
        scope: RuleScope::Authority,
        value: provider.to_string(),
        note: String::new(),
        created_by: "owner".to_owned(),
        created_at: 0,
    });
    s
}

struct Remote {
    peer: RemotePeer,
    provider: Provider,
    key: SigningKey,
}

impl Remote {
    async fn start() -> Self {
        let peer = RemotePeer::start().await;
        let client = peer.allowed_client();
        Self::with_client(peer, client).await
    }

    async fn with_client(peer: RemotePeer, client: OutboundClient) -> Self {
        let provider = Provider::start(None, fast_config(), |b| b.outbound(Arc::new(client))).await;
        Self {
            peer,
            provider,
            key: new_key(),
        }
    }

    fn actor(&self) -> String {
        format!("bob@{}", self.peer.authority())
    }

    /// Publish bob's `dk_1` (or not), cacheable for `ttl` seconds.
    fn serve(&self, with_key: bool, ttl: i64) {
        let keys: Vec<_> = if with_key {
            vec![("dk_1", self.key.verifying_key())]
        } else {
            vec![("dk_2", new_key().verifying_key())]
        };
        let until = rfc3339(self.provider.now() + ttl);
        self.peer.set(
            &keys_path("bob"),
            Reply::json(200, &keys_doc(&self.actor(), &keys, &until)),
        );
    }

    fn fail(&self) {
        self.peer.set(&keys_path("bob"), Reply::new(500, ""));
    }

    async fn connect(&self) -> Client {
        self.provider.client("10.0.0.1").await
    }

    async fn bob(&self) -> Client {
        let mut c = self.connect().await;
        c.authenticate(&self.actor(), "dk_1", &self.key, self.provider.now())
            .await;
        c
    }

    async fn answer(&self, c: &mut Client) {
        c.answer_challenge(
            "providera.com",
            &self.actor(),
            "dk_1",
            &self.key,
            self.provider.now(),
        )
        .await;
    }
}

/// Still open: a ping is answered.
async fn assert_open(c: &mut Client) {
    let id = c.command("ping", json!({})).await;
    let pong = c.event().await;
    assert_eq!(
        (&pong["type"], pong["correlationId"].as_str()),
        (&json!("pong"), Some(id.as_str()))
    );
}

/// Long enough for several lease ticks (50 ms) and a fetch.
const SETTLE: Duration = Duration::from_millis(400);

#[tokio::test]
async fn a_remote_actor_authenticates_with_its_providers_key() {
    let r = Remote::start().await;
    r.serve(true, 600);
    let mut c = r.bob().await;
    assert_open(&mut c).await;
    assert_eq!(r.peer.hits(&keys_path("bob")), 1);
}

#[tokio::test]
async fn keys_that_cannot_be_fetched_fail_the_handshake_as_unavailable() {
    let r = Remote::start().await;
    r.fail();
    let mut c = r.connect().await;
    r.answer(&mut c).await;
    let (code, events) = c.closed().await;
    assert_eq!(code, 4001);
    assert_eq!(events[0]["data"]["code"], "service_unavailable");
    assert_eq!(events[0]["data"]["status"], 503);
    assert!(events[0]["data"]["details"]["retryAfter"].is_u64());
}

#[tokio::test]
async fn a_provider_our_outbound_rules_forbid_is_refused() {
    let peer = RemotePeer::start().await;
    let client = peer.strict_client();
    let r = Remote::with_client(peer, client).await;
    r.serve(true, 600);
    let mut c = r.connect().await;
    r.answer(&mut c).await;
    let (code, events) = c.closed().await;
    assert_eq!(code, 4001);
    assert_eq!(events[0]["data"]["code"], "unauthorized");
    assert_eq!(r.peer.total_hits(), 0);
}

#[tokio::test]
async fn federation_policy_refuses_before_fetching_and_closes_live_connections() {
    let r = Remote::start().await;
    r.serve(true, 600);
    let mut live = r.bob().await;

    let policy = r.provider.state.federation.policy();
    policy.install(denying(&r.peer.authority()));
    assert_eq!(live.closed().await.0, 4001);

    let mut c = r.connect().await;
    r.answer(&mut c).await;
    let (code, events) = c.closed().await;
    assert_eq!(code, 4001);
    assert_eq!(events[0]["data"]["code"], "forbidden");
    assert_eq!(
        r.peer.hits(&keys_path("bob")),
        1,
        "no fetch for a denied provider"
    );
}

#[tokio::test]
async fn a_key_dropped_by_its_provider_closes_4003() {
    let r = Remote::start().await;
    r.serve(true, 30);
    let mut c = r.bob().await;
    r.serve(false, 30);
    // Re-confirming starts at most halfway to `cache_until`.
    r.provider.advance(16);
    assert_eq!(c.closed().await.0, 4003);
}

#[tokio::test]
async fn an_unreachable_provider_keeps_the_connection_until_cache_until_then_4001() {
    let r = Remote::start().await;
    r.serve(true, 30);
    let mut c = r.bob().await;
    r.fail();
    r.provider.advance(20);
    tokio::time::sleep(SETTLE).await;
    assert_open(&mut c).await;
    assert!(r.peer.hits(&keys_path("bob")) >= 2, "it tried");
    r.provider.advance(10);
    assert_eq!(c.closed().await.0, 4001);
}

#[tokio::test]
async fn a_refreshed_document_extends_the_connection() {
    let r = Remote::start().await;
    r.serve(true, 30);
    let mut c = r.bob().await;
    r.serve(true, 600);
    r.provider.advance(20);
    tokio::time::sleep(SETTLE).await;
    r.provider.advance(20);
    tokio::time::sleep(SETTLE).await;
    assert_open(&mut c).await;
}

#[tokio::test]
async fn before_the_policy_loads_remote_actors_are_refused_as_unavailable() {
    let peer = RemotePeer::start().await;
    let mut config = peer.config(vec![peer.authority(), peer.ip_authority()]);
    config.policy = Arc::new(FederationPolicy::unloaded());
    let client = OutboundClient::new(&config).unwrap();
    let r = Remote::with_client(peer, client).await;
    r.serve(true, 600);
    let mut c = r.connect().await;
    r.answer(&mut c).await;
    let (code, events) = c.closed().await;
    assert_eq!(code, 4001);
    assert_eq!(events[0]["data"]["code"], "service_unavailable");
    assert_eq!(r.peer.total_hits(), 0);
    // Loaded: the actor gets in.
    r.provider
        .state
        .federation
        .policy()
        .install(Snapshot::default());
    let mut c = r.bob().await;
    assert_open(&mut c).await;
}
