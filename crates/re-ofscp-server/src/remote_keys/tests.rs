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
use crate::federation::FederationPolicy;
use crate::outbound::OutboundConfig;
use crate::remote_keys::budget::Standing::FirstTime;
use crate::remote_keys::document::KeySet;

struct TestClock(AtomicI64);

impl Clock for TestClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(self.0.load(Ordering::SeqCst)).unwrap()
    }
}

const T: i64 = 1_800_000_000;

fn resolver() -> (RemoteKeys, Arc<TestClock>) {
    resolver_allowing(Vec::new())
}

/// A resolver whose outbound client allows `allow_hosts`.
fn resolver_allowing(allow_hosts: Vec<Authority>) -> (RemoteKeys, Arc<TestClock>) {
    let clock = Arc::new(TestClock(AtomicI64::new(T)));
    let client = Arc::new(
        OutboundClient::new(&OutboundConfig::new(
            allow_hosts,
            Arc::new(FederationPolicy::open()),
        ))
        .unwrap(),
    );
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
    let drain = Source::of(&remote("xxx@victim.example.com"));
    for i in 0..DOMAIN_BURST {
        let c = Requester::new(format!("drain{i}"));
        keys.inner.budgets.charge(&drain, FirstTime, &c, T).unwrap();
    }
    for (i, id) in [
        "xxx@victim.example.com:8443",
        "xxx@victim.example.com:1",
        "yyy@a.victim.example.com",
        "zzz@17.b.victim.example.com:65535",
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
    let alice = remote("alice@remote.example.com");
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
        keys.inner
            .budgets
            .charge(&source, FirstTime, &c, T)
            .unwrap();
    }
    for i in 0..CLIENT_BURST {
        let elsewhere = Source::of(&remote(&format!("uuu@t{i}.example")));
        keys.inner
            .budgets
            .charge(&elsewhere, FirstTime, &client(), T)
            .unwrap();
    }
}

#[tokio::test]
async fn a_client_over_budget_gets_503_or_an_unexpired_cached_key() {
    let (keys, _) = resolver();
    let alice = remote("alice@remote.example.com");
    let key = SigningKey::from_bytes(&[3; 32]).verifying_key();
    cache(&keys, &alice, key, T + 30);
    // The client spends its budget elsewhere.
    for i in 0..CLIENT_BURST {
        let elsewhere = Source::of(&remote(&format!("uuu@t{i}.example")));
        keys.inner
            .budgets
            .charge(&elsewhere, FirstTime, &client(), T)
            .unwrap();
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
        6
    );
    // Another client is not affected.
    assert!(keys.inner.budgets.would_allow(
        &Source::of(&alice),
        FirstTime,
        &Requester::new("198.51.100.1"),
        T
    ));
    assert!(keys.inner.tables().flights.is_empty());
}

#[test]
fn a_failed_refetch_answers_with_the_refetch_interval() {
    let (keys, clock) = resolver();
    let signer = remote("alice@remote.example.com");
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

/// Spend `requester`'s whole client budget on another target
/// (`example.net`, which no test here looks up).
fn spend_client(keys: &RemoteKeys, requester: &Requester) {
    for i in 0..CLIENT_BURST {
        let elsewhere = Source::of(&remote(&format!("uuu{i}@example.net")));
        keys.inner
            .budgets
            .charge(&elsewhere, FirstTime, requester, T)
            .unwrap();
    }
}

#[tokio::test]
async fn hosts_under_an_unknown_suffix_are_refused_at_no_cost() {
    let (keys, _) = resolver();
    // Each `n{i}.zzqq` would be a target group of its own: refused (401)
    // before any budget, so these lookups cannot drain or fill anything.
    for i in 0..DOMAIN_BURST + CLIENT_BURST {
        for signer in [
            remote(&format!("xxx@n{i}.zzqq")),
            Signer::Provider(Authority::parse_canonical(&format!("n{i}.zzqq:8443")).unwrap()),
        ] {
            for fresh in [false, true] {
                assert!(
                    matches!(
                        keys.resolve(&signer, "dk_1", fresh, &client()).await,
                        Err(KeyError::Unresolvable(_))
                    ),
                    "{signer:?}"
                );
            }
        }
    }
    assert!(keys.inner.tables().flights.is_empty());
    assert_eq!(
        keys.inner
            .tables()
            .refetch_wait(&Source::of(&remote("xxx@n0.zzqq")), T),
        None
    );
    // The client's budget is whole.
    spend_client(&keys, &client());
    // Still subject to #20: an unexpired cached key is used.
    let key = SigningKey::from_bytes(&[5; 32]).verifying_key();
    let odd = remote("xxx@n0.zzqq");
    cache(&keys, &odd, key, T + 30);
    assert_eq!(
        keys.resolve(&odd, "dk_1", true, &client()).await,
        Ok(Resolved::cached(Some(key)))
    );
}

#[tokio::test]
async fn operator_allowed_names_are_exempt_from_the_suffix_rule() {
    // `peer.test:8443` is allowed, so `peer.test` on any port passes the
    // suffix rule and reaches the budgets: spent here, so the answer is a
    // 503 rather than the 401 of a refusal, and nothing is fetched.
    let allowed = Authority::parse_canonical("peer.test:8443").unwrap();
    let (keys, _) = resolver_allowing(vec![allowed]);
    let me = client();
    spend_client(&keys, &me);
    for id in ["alice@peer.test:8443", "alice@peer.test:9000"] {
        assert_eq!(
            retry_after(keys.resolve(&remote(id), "dk_1", false, &me).await),
            6,
            "{id}"
        );
    }
    assert!(matches!(
        keys.resolve(&remote("alice@other.test"), "dk_1", false, &me)
            .await,
        Err(KeyError::Unresolvable(_))
    ));
    assert!(keys.inner.tables().flights.is_empty());
}

#[tokio::test]
async fn a_busy_target_costs_no_budget_and_no_refetch_interval() {
    let (keys, _) = resolver();
    let alice = remote("alice@remote.example.com");
    let source = Source::of(&alice);
    let key = SigningKey::from_bytes(&[4; 32]).verifying_key();
    cache(&keys, &alice, key, T + 30);
    // Every slot of the target group is taken (by other subdomains).
    let cap = OutboundConfig::new(Vec::new(), Arc::new(FederationPolicy::open()))
        .max_in_flight_per_target;
    let held: Vec<_> = (0..cap)
        .map(|i| {
            let host = Authority::parse_canonical(&format!("h{i}.example.com")).unwrap();
            keys.inner.client.reserve(&host, "/").unwrap()
        })
        .collect();
    // A fresh lookup: 503 with the failure delay (or the cached key), and
    // repeated as often as the budgets' bursts, charged nothing.
    for _ in 0..DOMAIN_BURST + CLIENT_BURST {
        assert_eq!(
            retry_after(keys.resolve(&alice, "dk_2", true, &client()).await),
            FAILURE_RETRY_SECS
        );
    }
    assert_eq!(
        keys.resolve(&alice, "dk_1", true, &client()).await,
        Ok(Resolved::cached(Some(key)))
    );
    assert!(keys.inner.tables().flights.is_empty());
    assert_eq!(
        keys.inner.tables().refetch_wait(&source, T),
        None,
        "no re-fetch interval started"
    );
    spend_client(&keys, &client());
    for i in 0..DOMAIN_BURST {
        let c = Requester::new(format!("c{i}"));
        keys.inner
            .budgets
            .charge(&source, FirstTime, &c, T)
            .unwrap();
    }
    drop(held);
    // Freed: the target can be reserved again.
    assert!(
        keys.inner
            .client
            .reserve(source.host(), &source.path())
            .is_ok()
    );
}

#[tokio::test]
async fn a_budget_refusal_after_reserving_releases_the_in_flight_slot() {
    let (keys, _) = resolver();
    let drain = Source::of(&remote("xxx@remote.example.com"));
    for i in 0..DOMAIN_BURST {
        let c = Requester::new(format!("drain{i}"));
        keys.inner.budgets.charge(&drain, FirstTime, &c, T).unwrap();
    }
    // Each lookup reserves one of the target's in-flight slots, then is
    // refused by the empty bucket. More lookups than there are slots: had
    // a refusal kept its slot, the later ones would be refused as busy
    // (`Retry-After: 5`) instead.
    let cap = OutboundConfig::new(Vec::new(), Arc::new(FederationPolicy::open()))
        .max_in_flight_per_target;
    for i in 0..2 * cap {
        let c = Requester::new(format!("client{i}"));
        let signer = remote(&format!("u{i:04}@remote.example.com"));
        assert_eq!(
            retry_after(keys.resolve(&signer, "dk_1", false, &c).await),
            2
        );
    }
    assert!(keys.inner.tables().flights.is_empty());
    // Every slot is free.
    let held: Vec<_> = (0..cap)
        .map(|i| {
            let host = Authority::parse_canonical(&format!("h{i}.remote.example.com")).unwrap();
            keys.inner.client.reserve(&host, "/").unwrap()
        })
        .collect();
    assert_eq!(held.len(), cap);
}

/// A document holding `key` as `dk_1`.
fn one_key(key: ed25519_dalek::VerifyingKey) -> Arc<KeySet> {
    Arc::new([("dk_1".to_owned(), key)].into_iter().collect())
}

/// Every one of `victims` is served `key` from cache, with no fetch.
async fn all_cached(keys: &RemoteKeys, victims: &[Signer], key: ed25519_dalek::VerifyingKey) {
    for victim in victims {
        assert_eq!(
            keys.resolve(victim, "dk_1", false, &client()).await,
            Ok(Resolved::cached(Some(key)))
        );
    }
    assert!(keys.inner.tables().flights.is_empty());
}

#[tokio::test]
async fn a_flood_of_another_domains_documents_leaves_a_peers_cache_intact() {
    // An attacker's providers serve keys for any handle, so it can have us
    // cache as many documents as it likes, all newer than the peer's: twice
    // the table's worth in one domain, then more spread over several.
    let (keys, _) = resolver();
    let key = SigningKey::from_bytes(&[5; 32]).verifying_key();
    let evil_key = SigningKey::from_bytes(&[6; 32]).verifying_key();
    let victims: Vec<_> = (0..50)
        .map(|i| remote(&format!("user{i}@victim.example")))
        .collect();
    for victim in &victims {
        cache(&keys, victim, key, T + 3600);
    }
    {
        let mut tables = keys.inner.tables();
        for i in 0..2 * state::MAX_CACHED {
            let source = Source::of(&remote(&format!("rrr{i}@evil.example")));
            tables.store(&source, one_key(evil_key), Some(T + 3600), T + 1);
        }
        for d in 0..5 {
            for i in 0..1_000 {
                let source = Source::of(&remote(&format!("rrr{i}@evil{d}.example")));
                tables.store(&source, one_key(evil_key), Some(T + 3600), T + 2);
            }
        }
    }
    all_cached(&keys, &victims, key).await;
}

#[tokio::test]
async fn a_flood_of_negatives_leaves_a_peers_cached_documents_intact() {
    // A peer with more users than any per-group cap ever was, all cached;
    // then an attacker names thousands of handles at the same domain that
    // do not exist, each answered by a cacheable 404 or empty list.
    let (keys, _) = resolver();
    let key = SigningKey::from_bytes(&[5; 32]).verifying_key();
    let victims: Vec<_> = (0..1_000)
        .map(|i| remote(&format!("user{i}@victim.example")))
        .collect();
    for victim in &victims {
        cache(&keys, victim, key, T + 3600);
    }
    {
        let mut tables = keys.inner.tables();
        for i in 0..5 * state::MAX_NEGATIVE {
            let source = Source::of(&remote(&format!("ghost{i}@victim.example")));
            tables.store(&source, Arc::new(KeySet::new()), Some(T + 3600), T + 1);
        }
    }
    all_cached(&keys, &victims, key).await;
}

/// The resolver judges the provider before its cache: an unloaded policy
/// is a temporary refusal and a denial is final, cached key or not
/// (§4.6 "No fetch is allowed", §8 *Authorization*).
#[tokio::test]
async fn the_policy_is_decided_before_the_cache_is_consulted() {
    use re_ofscp_types::federation::{FederationMode, RuleList, RuleScope};

    use crate::federation::{Rule, Snapshot};

    let policy = Arc::new(FederationPolicy::unloaded());
    let clock = Arc::new(TestClock(AtomicI64::new(T)));
    let outbound = OutboundClient::new(&OutboundConfig::new(Vec::new(), policy.clone())).unwrap();
    let keys = RemoteKeys::new(Arc::new(outbound), clock);
    let bob = remote("bob@chat.evil.example");
    cache(
        &keys,
        &bob,
        SigningKey::from_bytes(&[11; 32]).verifying_key(),
        T + 600,
    );

    let r = keys.resolve(&bob, "dk_1", false, &client()).await;
    assert_eq!(retry_after(r), crate::federation::UNKNOWN_RETRY_SECS);

    let mut deny = Snapshot {
        mode: FederationMode::Denylist,
        ..Snapshot::default()
    };
    deny.deny.insert(Rule {
        id: "r1".to_owned(),
        list: RuleList::Deny,
        scope: RuleScope::Domain,
        value: "evil.example".to_owned(),
        note: String::new(),
        created_by: "test".to_owned(),
        created_at: 0,
    });
    policy.install(deny);
    let r = keys.resolve(&bob, "dk_1", false, &client()).await;
    assert!(matches!(r, Err(KeyError::Denied(_))), "{r:?}");

    policy.install(Snapshot::default());
    assert!(keys.resolve(&bob, "dk_1", false, &client()).await.is_ok());
}
