//! The resolver's handling of outbound refusals, which a local test peer
//! cannot produce for a host it has also answered for, and of refusals
//! decided before any fetch starts. Fetch outcomes against a real peer are
//! covered in `tests/remote_keys.rs`.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use ed25519_dalek::SigningKey;
use re_ofscp_types::{Actor, Authority};
use time::OffsetDateTime;

use super::*;
use crate::outbound::OutboundConfig;
use crate::remote_keys::document::KeySet;

struct TestClock(AtomicI64);

impl Clock for TestClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(self.0.load(Ordering::SeqCst)).unwrap()
    }
}

const T: i64 = 1_800_000_000;

fn resolver() -> (RemoteKeys, Arc<TestClock>) {
    let clock = Arc::new(TestClock(AtomicI64::new(T)));
    let client = Arc::new(OutboundClient::new(&OutboundConfig::new(Vec::new())).unwrap());
    (RemoteKeys::new(client, clock.clone()), clock)
}

/// `alice@127.0.0.1`: an IP-literal host our outbound rules refuse.
fn loopback_alice() -> Signer {
    Signer::Actor(Actor::new("alice", Authority::parse_canonical("127.0.0.1").unwrap()).unwrap())
}

fn client() -> Requester {
    Requester::new("203.0.113.7")
}

fn cache(keys: &RemoteKeys, signer: &Signer, key: ed25519_dalek::VerifyingKey, expires: i64) {
    let set: KeySet = [("dk_1".to_owned(), key)].into_iter().collect();
    keys.inner
        .tables()
        .store(&Source::of(signer), Arc::new(set), Some(expires), T);
}

#[tokio::test]
async fn a_refusal_without_a_cached_key_is_unresolvable() {
    let (keys, _) = resolver();
    for fresh in [false, true] {
        assert!(matches!(
            keys.resolve(&loopback_alice(), "dk_1", fresh, &client())
                .await,
            Err(KeyError::Unresolvable(_))
        ));
    }
}

#[tokio::test]
async fn a_refused_fetch_still_uses_an_unexpired_cached_key() {
    // lost-conn/ofscp#20: the refusal only replaces a fetch.
    let (keys, clock) = resolver();
    let key = SigningKey::from_bytes(&[7; 32]).verifying_key();
    let alice = loopback_alice();
    cache(&keys, &alice, key, T + 30);
    assert_eq!(
        keys.resolve(&alice, "dk_1", true, &client()).await,
        Ok(Resolved::cached(Some(key)))
    );
    // A key id the entry does not hold: 401.
    assert!(matches!(
        keys.resolve(&alice, "dk_2", true, &client()).await,
        Err(KeyError::Unresolvable(_))
    ));
    // Expired: never a fallback.
    clock.0.store(T + 30, Ordering::SeqCst);
    assert!(matches!(
        keys.resolve(&alice, "dk_1", true, &client()).await,
        Err(KeyError::Unresolvable(_))
    ));
}

#[tokio::test]
async fn a_refusal_after_lookup_falls_back_the_same_way() {
    // A name that resolved to a refused address comes back from the fetch
    // as `Refused`; `settle` treats it like the IP-literal case.
    let (keys, clock) = resolver();
    let key = SigningKey::from_bytes(&[9; 32]).verifying_key();
    let signer = Signer::Provider(Authority::parse_canonical("internal.example").unwrap());
    let source = Source::of(&signer);
    cache(&keys, &signer, key, T + 30);
    let refused = || Fetched::Refused("internal.example resolves to 10.0.0.1".to_owned());
    assert_eq!(
        keys.inner.settle(&source, "dk_1", refused(), false),
        Ok(Resolved::cached(Some(key)))
    );
    clock.0.store(T + 31, Ordering::SeqCst);
    assert!(matches!(
        keys.inner.settle(&source, "dk_1", refused(), false),
        Err(KeyError::Unresolvable(_))
    ));
}

fn remote(id: &str) -> Signer {
    Signer::Actor(Actor::parse_canonical(id).unwrap())
}

fn retry_after(r: Result<Resolved, KeyError>) -> u64 {
    match r {
        Err(KeyError::Unavailable { retry_after, .. }) => retry_after,
        other => panic!("expected 503, got {other:?}"),
    }
}

#[tokio::test]
async fn ports_and_subdomains_of_a_target_share_its_bucket() {
    // Nothing here starts a fetch: the bucket is drained up front, so every
    // lookup below is refused before one would.
    let (keys, _) = resolver();
    let drain = Source::of(&remote("xxx@victim.example"));
    for i in 0..DOMAIN_BURST {
        let c = Requester::new(format!("drain{i}"));
        keys.inner.budgets.charge(&drain, &c, T).unwrap();
    }
    for (i, id) in [
        "xxx@victim.example:8443",
        "xxx@victim.example:1",
        "yyy@a.victim.example",
        "zzz@17.b.victim.example:65535",
    ]
    .into_iter()
    .enumerate()
    {
        let c = Requester::new(format!("client{i}"));
        assert_eq!(
            retry_after(keys.resolve(&remote(id), "dk_1", false, &c).await),
            2,
            "{id}"
        );
    }
    assert!(keys.inner.tables().flights.is_empty());
}

#[tokio::test]
async fn a_capacity_refusal_charges_no_budget() {
    let (keys, _) = resolver();
    let alice = remote("alice@remote.example");
    let source = Source::of(&alice);
    {
        let mut tables = keys.inner.tables();
        for i in 0..MAX_ENTRIES {
            let (_tx, answer) = watch::channel(None);
            let other =
                Source::Provider(Authority::parse_canonical(&format!("p{i}.example")).unwrap());
            tables.flights.insert(
                other,
                Flight {
                    answer,
                    refetch: false,
                },
            );
        }
    }
    // Lookups refused for capacity, then for the re-fetch interval: neither
    // may take a token from the target's or the client's bucket.
    for _ in 0..DOMAIN_BURST + CLIENT_BURST {
        assert_eq!(
            retry_after(keys.resolve(&alice, "dk_1", false, &client()).await),
            1
        );
    }
    keys.inner.tables().note_refetch(&source, T);
    keys.inner.tables().flights.clear();
    for _ in 0..DOMAIN_BURST + CLIENT_BURST {
        assert_eq!(
            retry_after(keys.resolve(&alice, "dk_1", true, &client()).await),
            60
        );
    }
    assert!(keys.inner.tables().flights.is_empty());
    // Both buckets are still full.
    for i in 0..DOMAIN_BURST {
        let c = Requester::new(format!("c{i}"));
        keys.inner.budgets.charge(&source, &c, T).unwrap();
    }
    for i in 0..CLIENT_BURST {
        let elsewhere = Source::of(&remote(&format!("uuu@t{i}.example")));
        keys.inner.budgets.charge(&elsewhere, &client(), T).unwrap();
    }
}

#[tokio::test]
async fn a_client_over_budget_gets_503_or_an_unexpired_cached_key() {
    let (keys, _) = resolver();
    let alice = remote("alice@remote.example");
    let key = SigningKey::from_bytes(&[3; 32]).verifying_key();
    cache(&keys, &alice, key, T + 30);
    // The client spends its budget elsewhere.
    for i in 0..CLIENT_BURST {
        let elsewhere = Source::of(&remote(&format!("uuu@t{i}.example")));
        keys.inner.budgets.charge(&elsewhere, &client(), T).unwrap();
    }
    // A cache hit costs nothing, so it still works.
    assert_eq!(
        keys.resolve(&alice, "dk_1", false, &client()).await,
        Ok(Resolved::cached(Some(key)))
    );
    // A re-fetch would need the budget: the unexpired cached key stands in,
    // and without one it is 503 until a token is back.
    assert_eq!(
        keys.resolve(&alice, "dk_1", true, &client()).await,
        Ok(Resolved::cached(Some(key)))
    );
    assert_eq!(
        retry_after(keys.resolve(&alice, "dk_2", true, &client()).await),
        2
    );
    // Another client is not affected.
    assert!(keys.inner.budgets.would_allow(
        &Source::of(&alice),
        &Requester::new("198.51.100.1"),
        T
    ));
    assert!(keys.inner.tables().flights.is_empty());
}

#[test]
fn a_failed_refetch_answers_with_the_refetch_interval() {
    let (keys, clock) = resolver();
    let signer = remote("alice@remote.example");
    let source = Source::of(&signer);
    let failed = || Fetched::Failed("remote.example answered 500".to_owned());
    keys.inner.tables().note_refetch(&source, T);
    clock.0.store(T + 10, Ordering::SeqCst);
    let retry = |refetch| retry_after(keys.inner.settle(&source, "dk_1", failed(), refetch));
    assert_eq!(retry(true), 50, "the next re-fetch is allowed in 50 s");
    assert_eq!(
        retry(false),
        FAILURE_RETRY_SECS,
        "a plain fetch can be retried soon"
    );
    clock.0.store(T + 58, Ordering::SeqCst);
    assert_eq!(
        retry(true),
        FAILURE_RETRY_SECS,
        "never below the failure delay"
    );
}
