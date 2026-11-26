//! How long a remote key may be relied on, and re-confirming it for a live
//! WebSocket connection (spec §7.1, lost-conn/ofscp#20), against a local
//! https peer.

mod common;

use common::harness::new_key;
use common::key_setup::{Setup, fetched};
use common::remote_peer::{Reply, keys_path};
use re_ofscp_server::signing::{Lifetime, Reconfirmed};

#[tokio::test]
async fn answers_carry_the_cache_lifetime_or_none() {
    let s = Setup::new().await;
    let k = new_key().verifying_key();
    let alice = s.actor("alice");
    s.serve_keys("alice", &[("dk_1", k)], 600);
    let until = Lifetime::Until(s.now() + 600);
    assert_eq!(
        s.resolve_with_lifetime(&alice, "dk_1", false).await,
        fetched(Some(k)).map(|r| r.lasting(until))
    );
    // A `cache_until` already past: usable once, not cacheable.
    let bob = s.actor("bob");
    s.serve_keys("bob", &[("dk_1", k)], -5);
    assert_eq!(
        s.resolve_with_lifetime(&bob, "dk_1", false).await,
        fetched(Some(k)).map(|r| r.lasting(Lifetime::Uncached))
    );
}

#[tokio::test]
async fn a_refreshed_document_extends_the_key() {
    let s = Setup::new().await;
    let k = new_key().verifying_key();
    let alice = s.actor("alice");
    s.serve_keys("alice", &[("dk_1", k)], 600);
    s.resolve(&alice, "dk_1", false).await.unwrap();
    let held = Lifetime::Until(s.now() + 600);
    s.advance(570);
    s.serve_keys("alice", &[("dk_1", k)], 600);
    let extended = Lifetime::Until(s.now() + 600);
    assert_eq!(
        s.reconfirm(&alice, "dk_1", &k, held).await,
        Reconfirmed::Present(extended)
    );
    assert_eq!(s.hits("alice"), 2);
    // Another connection holding the old expiry is answered from the
    // refreshed cache, with no fetch.
    assert_eq!(
        s.reconfirm(&alice, "dk_1", &k, held).await,
        Reconfirmed::Present(extended)
    );
    assert_eq!(s.hits("alice"), 2);
}

#[tokio::test]
async fn a_completed_fetch_without_the_key_is_gone() {
    let s = Setup::new().await;
    let k = new_key().verifying_key();
    let alice = s.actor("alice");
    s.serve_keys("alice", &[("dk_1", k)], 600);
    s.resolve(&alice, "dk_1", false).await.unwrap();
    let held = Lifetime::Until(s.now() + 600);

    // Dropped from the document.
    s.serve_keys("alice", &[("dk_2", k)], 600);
    assert_eq!(
        s.reconfirm(&alice, "dk_1", &k, held).await,
        Reconfirmed::Gone
    );
    // The id now names another key.
    let other = new_key().verifying_key();
    s.serve_keys("alice", &[("dk_1", other)], 600);
    assert_eq!(
        s.reconfirm(&alice, "dk_1", &k, Lifetime::Uncached).await,
        Reconfirmed::Gone
    );
    // A 404.
    s.peer.set(&keys_path("alice"), Reply::new(404, ""));
    assert_eq!(
        s.reconfirm(&alice, "dk_1", &k, Lifetime::Uncached).await,
        Reconfirmed::Gone
    );
}

#[tokio::test]
async fn a_failed_fetch_leaves_the_key_unconfirmed() {
    let s = Setup::new().await;
    let k = new_key().verifying_key();
    let alice = s.actor("alice");
    s.serve_keys("alice", &[("dk_1", k)], 600);
    s.resolve(&alice, "dk_1", false).await.unwrap();
    let held = Lifetime::Until(s.now() + 600);
    s.peer.set(&keys_path("alice"), Reply::new(500, ""));
    assert!(matches!(
        s.reconfirm(&alice, "dk_1", &k, held).await,
        Reconfirmed::Unconfirmed(_)
    ));
    // Not a miss: re-confirming again at once still fetches (no miss
    // re-fetch interval), and succeeds once the peer recovers.
    s.serve_keys("alice", &[("dk_1", k)], 600);
    assert_eq!(
        s.reconfirm(&alice, "dk_1", &k, held).await,
        Reconfirmed::Present(Lifetime::Until(s.now() + 600))
    );
    assert_eq!(s.hits("alice"), 3);
}
