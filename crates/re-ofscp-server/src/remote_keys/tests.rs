//! The resolver's handling of outbound refusals, which a local test peer
//! cannot produce for a host it has also answered for. Fetch outcomes
//! against a real peer are covered in `tests/remote_keys.rs`.

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
            keys.resolve(&loopback_alice(), "dk_1", fresh).await,
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
        keys.resolve(&alice, "dk_1", true).await,
        Ok(Resolved::cached(Some(key)))
    );
    // A key id the entry does not hold: 401.
    assert!(matches!(
        keys.resolve(&alice, "dk_2", true).await,
        Err(KeyError::Unresolvable(_))
    ));
    // Expired: never a fallback.
    clock.0.store(T + 30, Ordering::SeqCst);
    assert!(matches!(
        keys.resolve(&alice, "dk_1", true).await,
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
        keys.inner.settle(&source, "dk_1", refused()),
        Ok(Resolved::cached(Some(key)))
    );
    clock.0.store(T + 31, Ordering::SeqCst);
    assert!(matches!(
        keys.inner.settle(&source, "dk_1", refused()),
        Err(KeyError::Unresolvable(_))
    ));
}
