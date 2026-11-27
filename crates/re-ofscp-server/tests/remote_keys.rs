//! Remote key resolution (spec §4.6, §8.1, lost-conn/ofscp#19 and #20,
//! docs/decisions/0006) against a local https peer, on an injected clock.
//! The fetch budgets are in `remote_keys_budgets.rs`.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::harness::new_key;
use common::key_setup::{Setup, cached, client, fetched, unavailable};
use common::remote_peer::{RemotePeer, Reply, keys_doc, keys_path};
use re_ofscp_server::signing::{KeyError, KeyResolver, Lifetime};
use re_ofscp_server::timefmt::rfc3339;
use re_ofscp_types::Actor;
use serde_json::json;

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
    let lifetime = Lifetime::Until(s.now() + 600);
    let lookups: Vec<_> = (0..16)
        .map(|i| {
            let (keys, alice) = (s.keys.clone(), alice.clone());
            tokio::spawn(async move { keys.resolve(&alice, "dk_1", i % 2 == 0, &client()).await })
        })
        .collect();
    for lookup in lookups {
        let expected = fetched(Some(k)).map(|r| r.lasting(lifetime));
        assert_eq!(lookup.await.unwrap(), expected);
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
    // The peer is on loopback and not allowed: by name (`localhost` is not
    // under a known public suffix, so refused before any lookup) and by
    // address (refused before anything is sent).
    let peer = RemotePeer::start().await;
    let ip = peer.ip_authority();
    let client = Arc::new(peer.strict_client());
    let s = Setup::with_client(peer, client);
    s.serve_keys("alice", &[("dk_1", new_key().verifying_key())], 600);
    for signer in [
        s.actor("alice"),
        Actor::parse_canonical(&format!("alice@{ip}")).unwrap(),
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
