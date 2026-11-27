//! The remote key resolver's fetch budgets (docs/decisions/0006) against a
//! local https peer, on an injected clock: per target (known and
//! first-time apart) and per client.

mod common;

use std::time::Duration;

use common::harness::new_key;
use common::key_setup::{Setup, cached, client, fetched, nth_client, unavailable};
use common::remote_peer::{Reply, keys_doc, keys_path};
use re_ofscp_server::signing::{KeyResolver, Lifetime, Requester};
use re_ofscp_server::timefmt::rfc3339;
use re_ofscp_types::Actor;

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
    let elsewhere = Actor::parse_canonical(&format!("xxx@localhost:{other_port}")).unwrap();
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
        6
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
    // Resolved directly, so with the lifetime of the document it fetched.
    let until = Lifetime::Until(s.now() + 600);
    assert_eq!(
        first.await.unwrap(),
        fetched(Some(k)).map(|r| r.lasting(until))
    );
    assert_eq!(s.hits("slow"), 1);
}

/// Each `(client, signer)` looks `signer` up for `key_id`; the answers do
/// not matter.
async fn spam(s: &Setup, lookups: Vec<(Requester, Actor)>, key_id: &str, fresh: bool) {
    for (spammer, signer) in lookups {
        let _ = s.resolve_as(&spammer, &signer, key_id, fresh).await;
    }
}

#[tokio::test]
async fn known_users_keep_working_while_first_time_lookups_are_spammed() {
    let s = Setup::new().await;
    let (k1, k2) = (new_key().verifying_key(), new_key().verifying_key());
    s.serve_keys("alice", &[("dk_1", k1)], 120);
    let alice = s.actor("alice");
    // A fetch that found keys: alice is now a known source.
    assert_eq!(s.resolve(&alice, "dk_1", false).await, fetched(Some(k1)));
    // For three simulated minutes, eight clients each look up a random
    // handle (404s, so first-time lookups) every two seconds: more than the
    // first-time bucket refills, so it stays empty.
    let mut n = 0;
    let mut spam_round = || -> Vec<_> {
        (0..8)
            .map(|c| {
                n += 1;
                (nth_client(100 + c), s.actor(&format!("r{n:04}")))
            })
            .collect()
    };
    for _ in 0..90 {
        spam(&s, spam_round(), "dk_1", false).await;
        s.advance(2);
    }
    spam(&s, spam_round(), "dk_1", false).await;
    assert_eq!(
        unavailable(
            s.resolve_as(&nth_client(1), &s.actor("newcomer"), "dk_1", false)
                .await
        ),
        2,
        "the first-time bucket is empty"
    );
    // alice rotates her key. A re-fetch on a key miss is charged as
    // first-time, whoever is named (anyone can name a bogus key id), so
    // while the spam lasts it waits for that bucket: the cost of keeping
    // the known bucket out of the spammers' reach.
    s.serve_keys("alice", &[("dk_1", k1), ("dk_2", k2)], 600);
    assert_eq!(
        unavailable(s.resolve_as(&nth_client(2), &alice, "dk_2", true).await),
        2
    );
    // Her cached keys have expired meanwhile: the expiry re-fetch of a
    // known source is charged to the known bucket and goes through,
    // bringing the new key.
    assert_eq!(
        s.resolve_as(&nth_client(3), &alice, "dk_2", false).await,
        fetched(Some(k2))
    );
    assert_eq!(s.hits("alice"), 2);
}

/// Known users whose cached keys expire while spammers keep naming them
/// with bogus key ids (each lookup then a `fresh` re-fetch, which handles
/// being public anyone can cause) are still re-fetched on expiry.
#[tokio::test]
async fn bogus_key_id_refetches_of_known_users_cannot_drain_the_known_bucket() {
    const USERS: u32 = 40;
    let s = Setup::new().await;
    let k = new_key().verifying_key();
    let handle = |i: u32| format!("user{i:02}");
    let expiry = s.now() + 400;
    for i in 0..USERS {
        s.serve_keys(&handle(i), &[("dk_1", k)], expiry - s.now());
        assert_eq!(
            s.resolve_as(&nth_client(i), &s.actor(&handle(i)), "dk_1", false)
                .await,
            fetched(Some(k))
        );
        s.advance(2);
    }
    // Six clients each name a known user with a bogus key id every two
    // seconds: up to one re-fetch per user per minute, 40 a minute, more
    // than a bucket refills (30). Were they charged to the known bucket,
    // it would stay empty.
    let mut next = 0;
    let mut spam_round = || -> Vec<_> {
        (0..6)
            .map(|c| {
                next += 1;
                (nth_client(100 + c), s.actor(&handle(next % USERS)))
            })
            .collect()
    };
    while s.now() < expiry {
        spam(&s, spam_round(), "dk_bogus", true).await;
        s.advance(2);
    }
    // The cached keys have expired. While the spam goes on, every known
    // user's expiry re-fetch (one every two seconds, within the known
    // bucket's refill) still goes through. Each user's document is renewed
    // just before its lookup, so no spammer's re-fetch has cached it: the
    // lookup is a fetch, charged to the known bucket.
    for i in 0..USERS {
        spam(&s, spam_round(), "dk_bogus", true).await;
        s.serve_keys(&handle(i), &[("dk_1", k)], 600);
        assert_eq!(
            s.resolve_as(&nth_client(200 + i), &s.actor(&handle(i)), "dk_1", false)
                .await,
            fetched(Some(k)),
            "{}",
            handle(i)
        );
        s.advance(2);
    }
}
