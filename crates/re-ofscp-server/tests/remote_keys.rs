//! Remote key resolution (spec §4.6, §8.1, lost-conn/ofscp#19 and #20,
//! docs/decisions/0006) against a local https peer, on an injected clock.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::harness::{SIGNED_AT, SettableClock, new_key};
use common::remote_peer::{DISCOVERY_PATH, RemotePeer, Reply, discovery_doc, keys_doc, keys_path};
use ed25519_dalek::VerifyingKey;
use re_ofscp_server::outbound::OutboundClient;
use re_ofscp_server::remote_keys::RemoteKeys;
use re_ofscp_server::signing::{KeyError, KeyResolver, Requester, Resolved, Signer};
use re_ofscp_server::timefmt::rfc3339;
use re_ofscp_types::Actor;
use serde_json::json;

struct Setup {
    peer: RemotePeer,
    keys: Arc<RemoteKeys>,
    clock: Arc<SettableClock>,
}

impl Setup {
    async fn new() -> Self {
        let peer = RemotePeer::start().await;
        let client = Arc::new(peer.allowed_client());
        Self::with_client(peer, client)
    }

    fn with_client(peer: RemotePeer, client: Arc<OutboundClient>) -> Self {
        let clock = SettableClock::at(SIGNED_AT);
        let keys = Arc::new(RemoteKeys::new(client, clock.clone()));
        Self { peer, keys, clock }
    }

    fn actor_id(&self, handle: &str) -> String {
        format!("{handle}@{}", self.peer.authority())
    }

    fn actor(&self, handle: &str) -> Signer {
        Signer::Actor(Actor::parse_canonical(&self.actor_id(handle)).unwrap())
    }

    fn provider(&self) -> Signer {
        Signer::Provider(self.peer.authority())
    }

    /// Unix seconds now, on the test clock.
    fn now(&self) -> i64 {
        use re_ofscp_server::signing::Clock as _;
        self.clock.now().unix_timestamp()
    }

    fn advance(&self, secs: i64) {
        self.clock
            .set(time::OffsetDateTime::from_unix_timestamp(self.now() + secs).unwrap());
    }

    /// Serve `handle`'s keys, cacheable for `ttl` seconds from now.
    fn serve_keys(&self, handle: &str, keys: &[(&str, VerifyingKey)], ttl: i64) {
        let doc = keys_doc(&self.actor_id(handle), keys, &rfc3339(self.now() + ttl));
        self.peer.set(&keys_path(handle), Reply::json(200, &doc));
    }

    fn hits(&self, handle: &str) -> usize {
        self.peer.hits(&keys_path(handle))
    }

    async fn resolve(
        &self,
        signer: &Signer,
        key_id: &str,
        fresh: bool,
    ) -> Result<Resolved, KeyError> {
        self.resolve_as(&client(), signer, key_id, fresh).await
    }

    /// Resolve on behalf of `requester`.
    async fn resolve_as(
        &self,
        requester: &Requester,
        signer: &Signer,
        key_id: &str,
        fresh: bool,
    ) -> Result<Resolved, KeyError> {
        self.keys.resolve(signer, key_id, fresh, requester).await
    }
}

/// The client most tests make their lookups for.
fn client() -> Requester {
    Requester::new("203.0.113.7")
}

/// The `n`th of many distinct clients.
fn nth_client(n: u32) -> Requester {
    Requester::new(format!("198.51.100.{n}"))
}

fn unavailable(r: Result<Resolved, KeyError>) -> u64 {
    match r {
        Err(KeyError::Unavailable { retry_after, .. }) => retry_after,
        other => panic!("expected 503, got {other:?}"),
    }
}

fn fetched(key: Option<VerifyingKey>) -> Result<Resolved, KeyError> {
    Ok(Resolved::authoritative(key))
}

fn cached(key: Option<VerifyingKey>) -> Result<Resolved, KeyError> {
    Ok(Resolved::cached(key))
}

#[tokio::test]
async fn a_valid_list_is_used() {
    let s = Setup::new().await;
    let k = new_key().verifying_key();
    s.serve_keys("alice", &[("dk_1", k)], 600);
    let alice = s.actor("alice");
    assert_eq!(s.resolve(&alice, "dk_1", false).await, fetched(Some(k)));
    // From cache now, and a key that is not in the list is a cached miss.
    assert_eq!(s.resolve(&alice, "dk_1", false).await, cached(Some(k)));
    assert_eq!(s.resolve(&alice, "dk_2", false).await, cached(None));
    assert_eq!(s.hits("alice"), 1);
}

#[tokio::test]
async fn an_empty_list_and_a_404_mean_no_key() {
    let s = Setup::new().await;
    s.serve_keys("alice", &[], 600);
    assert_eq!(
        s.resolve(&s.actor("alice"), "dk_1", false).await,
        fetched(None)
    );
    // Nothing served for bob: the peer answers 404.
    assert_eq!(
        s.resolve(&s.actor("bob"), "dk_1", false).await,
        fetched(None)
    );
    // Both are cached (a miss still re-fetches, on the fresh path).
    assert_eq!(
        s.resolve(&s.actor("alice"), "dk_1", false).await,
        cached(None)
    );
    assert_eq!(
        s.resolve(&s.actor("bob"), "dk_1", false).await,
        cached(None)
    );
    assert_eq!(s.hits("alice") + s.hits("bob"), 2);
}

#[tokio::test]
async fn every_other_answer_is_a_fetch_failure() {
    let s = Setup::new().await;
    let k = new_key().verifying_key();
    let other_actor = keys_doc(
        "bob@remote.example",
        &[("dk_1", k)],
        &rfc3339(s.now() + 600),
    );
    let other_domain = keys_doc(
        "alice@other.example",
        &[("dk_1", k)],
        &rfc3339(s.now() + 600),
    );
    let mut duplicate = keys_doc(
        &s.actor_id("alice"),
        &[("dk_1", k)],
        &rfc3339(s.now() + 600),
    );
    let entry = duplicate["keys"][0].clone();
    duplicate["keys"].as_array_mut().unwrap().push(entry);
    for (what, reply) in [
        ("500", Reply::new(500, "boom")),
        ("503", Reply::new(503, "")),
        ("429", Reply::new(429, "").header("retry-after", "1")),
        ("403", Reply::new(403, "")),
        ("410", Reply::new(410, "")),
        (
            "302",
            Reply::new(302, "").header("location", "https://elsewhere.example/"),
        ),
        ("invalid body", Reply::new(200, "not json")),
        (
            "schema",
            Reply::json(200, &json!({ "actor": s.actor_id("alice") })),
        ),
        ("actor mismatch", Reply::json(200, &other_actor)),
        ("domain mismatch", Reply::json(200, &other_domain)),
        ("duplicate key_id", Reply::json(200, &duplicate)),
    ] {
        s.peer.set(&keys_path("alice"), reply);
        // Failures are never cached, so each lookup fetches. (Not `fresh`:
        // a failed re-fetch answers with the re-fetch interval instead.)
        s.advance(61);
        assert_eq!(
            unavailable(s.resolve(&s.actor("alice"), "dk_1", false).await),
            5,
            "{what}"
        );
    }
}

#[tokio::test]
async fn discovery_supplies_provider_keys() {
    let s = Setup::new().await;
    let k = new_key().verifying_key();
    let authority = s.peer.authority().to_string();
    s.peer.set(
        DISCOVERY_PATH,
        Reply::json(200, &discovery_doc(&authority, &[("pk_1", k)]))
            .header("cache-control", "max-age=120"),
    );
    let provider = s.provider();
    assert_eq!(s.resolve(&provider, "pk_1", false).await, fetched(Some(k)));
    s.advance(119);
    assert_eq!(s.resolve(&provider, "pk_1", false).await, cached(Some(k)));
    s.advance(1);
    assert_eq!(
        s.resolve(&provider, "pk_1", false).await,
        fetched(Some(k)),
        "max-age passed"
    );
    assert_eq!(s.peer.hits(DISCOVERY_PATH), 2);
}

#[tokio::test]
async fn discovery_failures() {
    let s = Setup::new().await;
    let k = new_key().verifying_key();
    let provider = s.provider();
    for (what, reply) in [
        // §8.1: for discovery even a 404 is a fetch failure.
        ("404", Reply::new(404, "")),
        (
            "domain mismatch",
            Reply::json(200, &discovery_doc("other.example", &[("pk_1", k)])),
        ),
        (
            "no port",
            Reply::json(200, &discovery_doc("localhost", &[("pk_1", k)])),
        ),
        ("500", Reply::new(500, "")),
    ] {
        s.peer.set(DISCOVERY_PATH, reply);
        s.advance(61);
        assert_eq!(
            unavailable(s.resolve(&provider, "pk_1", false).await),
            5,
            "{what}"
        );
    }
}

#[tokio::test]
async fn discovery_no_store_is_not_cached() {
    let s = Setup::new().await;
    let k = new_key().verifying_key();
    let doc = discovery_doc(&s.peer.authority().to_string(), &[("pk_1", k)]);
    for header in ["no-store", "no-cache", "max-age=0"] {
        s.peer.set(
            DISCOVERY_PATH,
            Reply::json(200, &doc).header("cache-control", header),
        );
        let before = s.peer.hits(DISCOVERY_PATH);
        for _ in 0..2 {
            assert_eq!(
                s.resolve(&s.provider(), "pk_1", false).await,
                fetched(Some(k)),
                "{header}"
            );
        }
        assert_eq!(s.peer.hits(DISCOVERY_PATH), before + 2, "{header}");
    }
}

#[tokio::test]
async fn cache_until_is_honoured_and_capped_at_an_hour() {
    let s = Setup::new().await;
    let k = new_key().verifying_key();
    s.serve_keys("alice", &[("dk_1", k)], 7200);
    let alice = s.actor("alice");
    assert_eq!(s.resolve(&alice, "dk_1", false).await, fetched(Some(k)));
    s.advance(3599);
    assert_eq!(s.resolve(&alice, "dk_1", false).await, cached(Some(k)));
    s.advance(1);
    assert_eq!(
        s.resolve(&alice, "dk_1", false).await,
        fetched(Some(k)),
        "capped at 1 h"
    );
    assert_eq!(s.hits("alice"), 2);

    // A cache_until at or before now: not cached at all.
    s.serve_keys("bob", &[("dk_1", k)], 0);
    let bob = s.actor("bob");
    assert_eq!(s.resolve(&bob, "dk_1", false).await, fetched(Some(k)));
    assert_eq!(s.resolve(&bob, "dk_1", false).await, fetched(Some(k)));
    assert_eq!(s.hits("bob"), 2);
}

#[tokio::test]
async fn a_fresh_lookup_refetches_and_finds_a_new_key() {
    let s = Setup::new().await;
    let (k1, k2) = (new_key().verifying_key(), new_key().verifying_key());
    s.serve_keys("alice", &[("dk_1", k1)], 600);
    let alice = s.actor("alice");
    assert_eq!(s.resolve(&alice, "dk_1", false).await, fetched(Some(k1)));
    s.serve_keys("alice", &[("dk_1", k1), ("dk_2", k2)], 600);
    assert_eq!(s.resolve(&alice, "dk_2", false).await, cached(None));
    assert_eq!(s.resolve(&alice, "dk_2", true).await, fetched(Some(k2)));
    // The re-fetch refreshed the cache.
    assert_eq!(s.resolve(&alice, "dk_2", false).await, cached(Some(k2)));
    assert_eq!(s.hits("alice"), 2);
}

#[tokio::test]
async fn fresh_refetches_are_limited_per_source() {
    let s = Setup::new().await;
    let k = new_key().verifying_key();
    s.serve_keys("alice", &[("dk_1", k)], 600);
    let alice = s.actor("alice");
    assert_eq!(s.resolve(&alice, "dk_1", true).await, fetched(Some(k)));
    s.advance(10);
    // Throttled, but the unexpired cached key is still used.
    assert_eq!(s.resolve(&alice, "dk_1", true).await, cached(Some(k)));
    // Throttled with no cached key: 503 until the minute is up.
    assert_eq!(unavailable(s.resolve(&alice, "dk_9", true).await), 50);
    s.advance(49);
    assert_eq!(unavailable(s.resolve(&alice, "dk_9", true).await), 1);
    assert_eq!(s.hits("alice"), 1);
    s.advance(1);
    assert_eq!(s.resolve(&alice, "dk_9", true).await, fetched(None));
    assert_eq!(s.hits("alice"), 2);
    // Another actor at the same host has its own limit.
    s.serve_keys("bob", &[("dk_1", k)], 600);
    assert_eq!(
        s.resolve(&s.actor("bob"), "dk_1", true).await,
        fetched(Some(k))
    );
    // Expiry-driven fetches are not held to it.
    s.serve_keys("carol", &[("dk_1", k)], 5);
    let carol = s.actor("carol");
    assert_eq!(s.resolve(&carol, "dk_1", true).await, fetched(Some(k)));
    s.advance(6);
    assert_eq!(s.resolve(&carol, "dk_1", false).await, fetched(Some(k)));
}

#[tokio::test]
async fn a_cached_key_stands_in_for_a_failed_fetch_only_while_unexpired() {
    let s = Setup::new().await;
    let k = new_key().verifying_key();
    s.serve_keys("alice", &[("dk_1", k)], 30);
    let alice = s.actor("alice");
    assert_eq!(s.resolve(&alice, "dk_1", false).await, fetched(Some(k)));
    s.peer.set(&keys_path("alice"), Reply::new(500, ""));
    // Unexpired: the cached key is used when the re-fetch fails.
    assert_eq!(s.resolve(&alice, "dk_1", true).await, cached(Some(k)));
    // ... but not for a key id it does not hold. That failed re-fetch
    // started the re-fetch interval, so the client is told to wait it out.
    s.advance(60);
    assert_eq!(unavailable(s.resolve(&alice, "dk_2", true).await), 60);
}

#[tokio::test]
async fn an_entry_that_expires_between_lookups_is_no_fallback() {
    // lost-conn/ofscp#20: expiry is checked when the fallback is used, not
    // when the entry was first read.
    let s = Setup::new().await;
    let k = new_key().verifying_key();
    s.serve_keys("alice", &[("dk_1", k)], 30);
    let alice = s.actor("alice");
    assert_eq!(s.resolve(&alice, "dk_1", false).await, fetched(Some(k)));
    assert_eq!(s.resolve(&alice, "dk_1", false).await, cached(Some(k)));
    // The verifier's fresh call comes after the entry expired, and the
    // re-fetch fails: no stale fallback.
    s.peer.set(&keys_path("alice"), Reply::new(500, ""));
    s.advance(30);
    assert_eq!(unavailable(s.resolve(&alice, "dk_1", true).await), 60);
    // Expired and throttled: no fallback either.
    assert_eq!(unavailable(s.resolve(&alice, "dk_1", true).await), 60);
}

#[tokio::test]
async fn the_clock_moving_during_a_fetch_is_respected() {
    // The entry is unexpired when the fresh lookup starts and expires while
    // its fetch is in flight; the failed fetch must not fall back to it.
    let s = Setup::new().await;
    let k = new_key().verifying_key();
    s.serve_keys("alice", &[("dk_1", k)], 30);
    let alice = s.actor("alice");
    assert_eq!(s.resolve(&alice, "dk_1", false).await, fetched(Some(k)));
    s.peer.set(
        &keys_path("alice"),
        Reply::new(500, "").delayed(Duration::from_millis(300)),
    );
    let keys = s.keys.clone();
    let lookup = tokio::spawn({
        let alice = alice.clone();
        async move { keys.resolve(&alice, "dk_1", true, &client()).await }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    s.advance(31);
    // The failed re-fetch began 31 s ago: the next one is allowed in 29 s.
    assert_eq!(unavailable(lookup.await.unwrap()), 29);
}

#[tokio::test]
async fn fetches_to_one_host_share_a_token_bucket() {
    let s = Setup::new().await;
    // Twenty distinct actors (nothing served: 404s), each looked up for a
    // different client, use up the target's burst.
    for i in 0..20 {
        assert_eq!(
            s.resolve_as(
                &nth_client(i),
                &s.actor(&format!("user{i:02}")),
                "dk_1",
                false
            )
            .await,
            fetched(None)
        );
    }
    // The 21st waits for a token (30/min: one every 2 s).
    assert_eq!(
        unavailable(s.resolve(&s.actor("user20"), "dk_1", false).await),
        2
    );
    assert_eq!(s.peer.total_hits(), 20);
    s.advance(2);
    assert_eq!(
        s.resolve(&s.actor("user20"), "dk_1", false).await,
        fetched(None)
    );
    // Cached answers cost no token.
    assert_eq!(
        s.resolve(&s.actor("user00"), "dk_1", false).await,
        cached(None)
    );
    assert_eq!(s.peer.total_hits(), 21);
}

#[tokio::test]
async fn concurrent_lookups_share_one_fetch() {
    let s = Setup::new().await;
    let k = new_key().verifying_key();
    let doc = keys_doc(
        &s.actor_id("alice"),
        &[("dk_1", k)],
        &rfc3339(s.now() + 600),
    );
    s.peer.set(
        &keys_path("alice"),
        Reply::json(200, &doc).delayed(Duration::from_millis(200)),
    );
    let alice = s.actor("alice");
    let lookups: Vec<_> = (0..16)
        .map(|i| {
            let (keys, alice) = (s.keys.clone(), alice.clone());
            tokio::spawn(async move { keys.resolve(&alice, "dk_1", i % 2 == 0, &client()).await })
        })
        .collect();
    for lookup in lookups {
        assert_eq!(lookup.await.unwrap(), fetched(Some(k)));
    }
    assert_eq!(s.hits("alice"), 1);
}

#[tokio::test]
async fn a_dropped_lookup_does_not_cancel_the_shared_fetch() {
    let s = Setup::new().await;
    let k = new_key().verifying_key();
    let doc = keys_doc(
        &s.actor_id("alice"),
        &[("dk_1", k)],
        &rfc3339(s.now() + 600),
    );
    s.peer.set(
        &keys_path("alice"),
        Reply::json(200, &doc).delayed(Duration::from_millis(200)),
    );
    let alice = s.actor("alice");
    let first = tokio::spawn({
        let (keys, alice) = (s.keys.clone(), alice.clone());
        async move { keys.resolve(&alice, "dk_1", false, &client()).await }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    first.abort();
    assert_eq!(s.resolve(&alice, "dk_1", false).await, fetched(Some(k)));
    assert_eq!(s.hits("alice"), 1);
}

#[tokio::test]
async fn an_outbound_refusal_is_401() {
    // The peer is on loopback and not allowed: by name (refused after DNS)
    // and by address (refused before anything is sent).
    let peer = RemotePeer::start().await;
    let ip = peer.ip_authority();
    let client = Arc::new(peer.strict_client());
    let s = Setup::with_client(peer, client);
    s.serve_keys("alice", &[("dk_1", new_key().verifying_key())], 600);
    for signer in [
        s.actor("alice"),
        Signer::Actor(Actor::parse_canonical(&format!("alice@{ip}")).unwrap()),
        Signer::Provider(ip.clone()),
    ] {
        for fresh in [false, true] {
            assert!(
                matches!(
                    s.resolve(&signer, "dk_1", fresh).await,
                    Err(KeyError::Unresolvable(_))
                ),
                "{signer:?} fresh={fresh}"
            );
        }
    }
    assert_eq!(s.peer.total_hits(), 0);
}

/// Twenty user-key fetches (404s) at the peer, each for its own client:
/// the user-keys bucket of the peer's domain is then empty.
async fn drain_user_keys_bucket(s: &Setup) {
    for i in 0..20 {
        let actor = s.actor(&format!("drain{i:02}"));
        assert_eq!(
            s.resolve_as(&nth_client(i), &actor, "dk_1", false).await,
            fetched(None)
        );
    }
}

#[tokio::test]
async fn another_port_of_the_host_shares_its_bucket() {
    let s = Setup::new().await;
    drain_user_keys_bucket(&s).await;
    // `localhost:{other port}` is the same target: refused by the empty
    // bucket before anything is fetched (otherwise our outbound rules would
    // refuse its loopback address: 401).
    let other_port = s.peer.port.wrapping_add(1).max(1);
    let elsewhere =
        Signer::Actor(Actor::parse_canonical(&format!("xxx@localhost:{other_port}")).unwrap());
    assert_eq!(
        unavailable(
            s.resolve_as(&nth_client(99), &elsewhere, "dk_1", false)
                .await
        ),
        2
    );
    assert_eq!(s.peer.total_hits(), 20);
}

#[tokio::test]
async fn discovery_works_while_the_user_keys_bucket_is_empty() {
    let s = Setup::new().await;
    drain_user_keys_bucket(&s).await;
    assert_eq!(
        unavailable(
            s.resolve_as(&nth_client(99), &s.actor("bob"), "dk_1", false)
                .await
        ),
        2
    );
    let k = new_key().verifying_key();
    let authority = s.peer.authority().to_string();
    s.peer.set(
        DISCOVERY_PATH,
        Reply::json(200, &discovery_doc(&authority, &[("pk_1", k)])),
    );
    assert_eq!(
        s.resolve_as(&nth_client(99), &s.provider(), "pk_1", false)
            .await,
        fetched(Some(k))
    );
}

#[tokio::test]
async fn a_client_is_charged_only_for_fetches_it_causes() {
    let s = Setup::new().await;
    let k = new_key().verifying_key();
    s.serve_keys("alice", &[("dk_1", k)], 600);
    let alice = s.actor("alice");
    let me = client();
    assert_eq!(
        s.resolve_as(&me, &alice, "dk_1", false).await,
        fetched(Some(k))
    );
    // Cache hits are free.
    for _ in 0..20 {
        assert_eq!(
            s.resolve_as(&me, &alice, "dk_1", false).await,
            cached(Some(k))
        );
    }
    // Nine more fetches spend the burst of ten ...
    for i in 0..9 {
        let actor = s.actor(&format!("user{i}"));
        assert_eq!(
            s.resolve_as(&me, &actor, "dk_1", false).await,
            fetched(None)
        );
    }
    // ... after which this client's next fetch is refused, but its cache
    // hits still work, and so do other clients' fetches.
    assert_eq!(
        unavailable(s.resolve_as(&me, &s.actor("user9"), "dk_1", false).await),
        2
    );
    assert_eq!(
        s.resolve_as(&me, &alice, "dk_1", false).await,
        cached(Some(k))
    );
    // A re-fetch would be charged too: the unexpired cached key stands in.
    assert_eq!(
        s.resolve_as(&me, &alice, "dk_1", true).await,
        cached(Some(k))
    );
    assert_eq!(
        s.resolve_as(&nth_client(1), &s.actor("user9"), "dk_1", false)
            .await,
        fetched(None)
    );
    assert_eq!(s.peer.total_hits(), 11);
}

#[tokio::test]
async fn joining_a_fetch_under_way_is_free() {
    let s = Setup::new().await;
    let broke = nth_client(1);
    for i in 0..10 {
        let actor = s.actor(&format!("user{i}"));
        assert_eq!(
            s.resolve_as(&broke, &actor, "dk_1", false).await,
            fetched(None)
        );
    }
    let k = new_key().verifying_key();
    let doc = keys_doc(&s.actor_id("slow"), &[("dk_1", k)], &rfc3339(s.now() + 600));
    s.peer.set(
        &keys_path("slow"),
        Reply::json(200, &doc).delayed(Duration::from_millis(300)),
    );
    let slow = s.actor("slow");
    let first = tokio::spawn({
        let (keys, slow) = (s.keys.clone(), slow.clone());
        async move { keys.resolve(&slow, "dk_1", false, &nth_client(2)).await }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    // Out of budget, but it only waits for the fetch another client started.
    assert_eq!(
        s.resolve_as(&broke, &slow, "dk_1", false).await,
        fetched(Some(k))
    );
    assert_eq!(first.await.unwrap(), fetched(Some(k)));
    assert_eq!(s.hits("slow"), 1);
}
