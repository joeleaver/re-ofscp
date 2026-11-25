use super::*;
use SignerKind::{Actor, Provider};
use Surface::{SignedRequest, WsHandshake};

const T: i64 = 1_000_000;

/// `record`, ignoring the expiry it reports.
fn rec(s: &ReplayStore, surface: Surface, u: &NonceUse<'_>, now: i64) -> Result<(), ReplayError> {
    s.record(surface, u, now).map(|_| ())
}
const SKEW: i64 = 300;
const HOME: &str = "home.example";

/// Only the pool bounds apply (each pool holds `capacity`).
fn limits(capacity: usize) -> ReplayLimits {
    ReplayLimits {
        local_total: capacity,
        remote_total: capacity,
        per_signer: usize::MAX,
        per_remote_domain: usize::MAX,
    }
}

/// A store whose warm-up is over for every timestamp acceptable at `T`
/// (from `T - SKEW` on).
fn warm(capacity: usize) -> ReplayStore {
    warm_with(limits(capacity))
}

fn warm_with(l: ReplayLimits) -> ReplayStore {
    ReplayStore::new(l, SKEW, T - 2 * SKEW - 1, HOME)
}

fn alice(nonce: &str, signed_at: i64) -> NonceUse<'_> {
    NonceUse {
        kind: Actor,
        signer: "alice@home.example",
        domain: HOME,
        key_id: "k",
        nonce,
        signed_at,
    }
}

fn remote<'a>(signer: &'a str, domain: &'a str, nonce: &'a str) -> NonceUse<'a> {
    NonceUse {
        kind: Actor,
        signer,
        domain,
        key_id: signer,
        nonce,
        signed_at: T,
    }
}

#[test]
fn check_does_not_record() {
    let s = warm(10);
    assert_eq!(s.check(SignedRequest, &alice("n", T), T), Ok(()));
    assert_eq!(s.check(SignedRequest, &alice("n", T), T), Ok(()));
    assert!(s.is_empty(T));
}

#[test]
fn record_then_replay_is_refused() {
    let s = warm(10);
    assert_eq!(rec(&s, SignedRequest, &alice("n", T), T), Ok(()));
    assert_eq!(
        s.check(SignedRequest, &alice("n", T), T),
        Err(ReplayError::Replayed)
    );
    assert_eq!(
        rec(&s, SignedRequest, &alice("n", T), T),
        Err(ReplayError::Replayed)
    );
}

#[test]
fn surfaces_share_one_store() {
    let s = warm(10);
    assert_eq!(rec(&s, WsHandshake, &alice("n", T), T), Ok(()));
    assert_eq!(
        s.check(SignedRequest, &alice("n", T), T),
        Err(ReplayError::Replayed)
    );
}

#[test]
fn signer_kinds_and_key_ids_do_not_collide() {
    let s = warm(10);
    assert_eq!(rec(&s, SignedRequest, &alice("n", T), T), Ok(()));
    let mut p = alice("n", T);
    p.kind = Provider;
    assert_eq!(rec(&s, SignedRequest, &p, T), Ok(()));
    let mut k2 = alice("n", T);
    k2.key_id = "k2";
    assert_eq!(rec(&s, SignedRequest, &k2, T), Ok(()));
}

/// The nonce must outlive every moment its timestamp is accepted, which is
/// while `now <= signed_at + skew` (§4.5 step 3 and 4).
#[test]
fn nonce_lives_exactly_as_long_as_its_timestamp_is_acceptable() {
    for signed_at in [T - SKEW, T, T + SKEW] {
        let s = warm(10);
        let u = alice("n", signed_at);
        let now = T;
        rec(&s, SignedRequest, &u, now).unwrap();
        let last_ok = signed_at + SKEW;
        assert_eq!(
            s.check(SignedRequest, &u, last_ok),
            Err(ReplayError::Replayed),
            "signed_at={signed_at}: still replayable at {last_ok}"
        );
        // One second later the entry is gone, and so is the timestamp's
        // acceptability: the store refuses it as expired.
        assert!(s.is_empty(last_ok + 1));
        assert_eq!(
            s.check(SignedRequest, &u, last_ok + 1),
            Err(ReplayError::Expired)
        );
    }
}

#[test]
fn full_store_fails_closed_without_evicting() {
    let s = warm(2);
    rec(&s, SignedRequest, &alice("a", T), T).unwrap();
    rec(&s, SignedRequest, &alice("b", T + 10), T + 10).unwrap();
    // `a` expires at T + 301.
    assert_eq!(
        rec(&s, SignedRequest, &alice("c", T + 100), T + 100),
        Err(ReplayError::Full { retry_after: 201 })
    );
    // Nothing was evicted.
    assert_eq!(
        s.check(SignedRequest, &alice("a", T), T + 100),
        Err(ReplayError::Replayed)
    );
    assert_eq!(
        s.check(SignedRequest, &alice("b", T + 10), T + 100),
        Err(ReplayError::Replayed)
    );
    // Once `a` expires there is room again.
    assert_eq!(
        rec(&s, SignedRequest, &alice("c", T + 100), T + SKEW + 1),
        Ok(())
    );
}

#[test]
fn expiry_order_is_by_timestamp_not_arrival() {
    // A later-arriving nonce with an earlier timestamp expires first and
    // frees room first.
    let s = warm(2);
    rec(&s, SignedRequest, &alice("late", T + 200), T).unwrap();
    rec(&s, SignedRequest, &alice("early", T - 200), T).unwrap();
    assert_eq!(s.len(T + 101), 1, "early (T-200) expired at T+101");
    assert_eq!(
        s.check(SignedRequest, &alice("late", T + 200), T + 101),
        Err(ReplayError::Replayed)
    );
}

#[test]
fn one_signer_cannot_take_the_whole_store() {
    let s = warm_with(ReplayLimits {
        per_signer: 2,
        ..limits(100)
    });
    rec(&s, SignedRequest, &alice("a", T), T).unwrap();
    rec(&s, SignedRequest, &alice("b", T + 5), T).unwrap();
    let limited = Err(ReplayError::RateLimited { retry_after: 301 });
    assert_eq!(s.check(SignedRequest, &alice("c", T), T), limited);
    assert_eq!(rec(&s, SignedRequest, &alice("c", T), T), limited);
    // Someone else is unaffected.
    let mut bob = alice("c", T);
    bob.signer = "bob@home.example";
    assert_eq!(rec(&s, SignedRequest, &bob, T), Ok(()));
}

#[test]
fn one_remote_domain_cannot_take_the_whole_store() {
    let s = warm_with(ReplayLimits {
        per_remote_domain: 2,
        ..limits(100)
    });
    // A hostile provider minting fresh actors still shares one domain quota.
    rec(
        &s,
        SignedRequest,
        &remote("u1@evil.example", "evil.example", "1"),
        T,
    )
    .unwrap();
    rec(
        &s,
        SignedRequest,
        &remote("u2@evil.example", "evil.example", "2"),
        T,
    )
    .unwrap();
    assert!(matches!(
        rec(
            &s,
            SignedRequest,
            &remote("u3@evil.example", "evil.example", "3"),
            T
        ),
        Err(ReplayError::RateLimited { .. })
    ));
    // Other remote domains and local users are unaffected.
    assert_eq!(
        rec(
            &s,
            SignedRequest,
            &remote("v@good.example", "good.example", "4"),
            T
        ),
        Ok(())
    );
    for i in 0..5 {
        let n = i.to_string();
        let mut u = alice(&n, T);
        let signer = format!("user{i}@home.example");
        u.signer = &signer;
        assert_eq!(rec(&s, SignedRequest, &u, T), Ok(()), "local user {i}");
    }
}

#[test]
fn quotas_free_up_as_entries_expire() {
    let s = warm_with(ReplayLimits {
        per_signer: 1,
        ..limits(100)
    });
    rec(&s, SignedRequest, &alice("a", T), T).unwrap();
    assert!(rec(&s, SignedRequest, &alice("b", T), T).is_err());
    assert_eq!(
        rec(&s, SignedRequest, &alice("b", T + SKEW + 1), T + SKEW + 1),
        Ok(())
    );
}

#[test]
fn warm_up_refuses_through_start_plus_skew_inclusive() {
    // Began during second T. The previous process may have run in second T
    // too, accepting timestamps that floor to T + 300.
    let s = ReplayStore::new(limits(10), SKEW, T, HOME);
    let warming = |r| Err(ReplayError::WarmingUp { retry_after: r });
    assert_eq!(s.check(SignedRequest, &alice("n", T), T), warming(301));
    assert_eq!(rec(&s, SignedRequest, &alice("n", T), T), warming(301));
    assert_eq!(
        s.check(SignedRequest, &alice("n", T + SKEW), T),
        warming(301)
    );
    // Retry-After counts down and never reaches zero.
    assert_eq!(
        s.check(SignedRequest, &alice("n", T + 10), T + SKEW),
        warming(1)
    );
    assert_eq!(
        s.check(SignedRequest, &alice("n", T + 10), T + 999),
        warming(1)
    );
    // From T + 301 on, signatures are accepted.
    assert_eq!(
        rec(&s, SignedRequest, &alice("n", T + SKEW + 1), T + SKEW + 1),
        Ok(())
    );
}

#[test]
fn ws_handshake_is_exempt_from_warm_up() {
    let s = ReplayStore::new(limits(10), SKEW, T, HOME);
    assert_eq!(s.check(WsHandshake, &alice("n", T), T), Ok(()));
    assert_eq!(rec(&s, WsHandshake, &alice("n", T), T), Ok(()));
    assert_eq!(
        rec(&s, WsHandshake, &alice("n", T), T),
        Err(ReplayError::Replayed)
    );
}

#[test]
fn concurrent_records_have_exactly_one_winner() {
    let s = std::sync::Arc::new(warm(100));
    let wins: usize = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..16)
            .map(|_| {
                let s = s.clone();
                scope.spawn(move || usize::from(rec(&s, SignedRequest, &alice("n", T), T).is_ok()))
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).sum()
    });
    assert_eq!(wins, 1);
}

#[test]
fn subdomains_and_ports_of_one_domain_share_a_quota() {
    let s = warm_with(ReplayLimits {
        per_remote_domain: 2,
        ..limits(100)
    });
    rec(
        &s,
        SignedRequest,
        &remote("u@a.evil.com", "a.evil.com", "1"),
        T,
    )
    .unwrap();
    rec(
        &s,
        SignedRequest,
        &remote("u@b.evil.com:8443", "b.evil.com:8443", "2"),
        T,
    )
    .unwrap();
    assert!(matches!(
        rec(
            &s,
            SignedRequest,
            &remote("u@evil.com:8444", "evil.com:8444", "3"),
            T
        ),
        Err(ReplayError::RateLimited { .. })
    ));
}

#[test]
fn private_section_subdomains_share_their_icann_domains_quota() {
    // `*.workers.dev` names are free, so they are one group, `workers.dev`
    // (docs/decisions/0001), not one group each.
    let s = warm_with(ReplayLimits {
        per_remote_domain: 2,
        ..limits(100)
    });
    rec(
        &s,
        SignedRequest,
        &remote("u@s1.workers.dev", "s1.workers.dev", "1"),
        T,
    )
    .unwrap();
    rec(
        &s,
        SignedRequest,
        &remote("u@s2.workers.dev", "s2.workers.dev", "2"),
        T,
    )
    .unwrap();
    let third = remote("u@s3.workers.dev:8443", "s3.workers.dev:8443", "3");
    assert!(matches!(
        rec(&s, SignedRequest, &third, T),
        Err(ReplayError::RateLimited { .. })
    ));
    assert!(matches!(
        s.check(SignedRequest, &third, T),
        Err(ReplayError::RateLimited { .. })
    ));
    // Another ICANN domain's free subdomains have their own quota.
    rec(
        &s,
        SignedRequest,
        &remote("u@s1.vercel.app", "s1.vercel.app", "4"),
        T,
    )
    .unwrap();
}

#[test]
fn a_full_remote_pool_does_not_touch_local_users() {
    let s = warm_with(ReplayLimits {
        local_total: 10,
        remote_total: 2,
        per_signer: usize::MAX,
        per_remote_domain: usize::MAX,
    });
    rec(&s, SignedRequest, &remote("u@one.com", "one.com", "1"), T).unwrap();
    rec(&s, SignedRequest, &remote("u@two.com", "two.com", "2"), T).unwrap();
    assert_eq!(
        rec(
            &s,
            SignedRequest,
            &remote("u@three.com", "three.com", "3"),
            T
        ),
        Err(ReplayError::Full { retry_after: 301 })
    );
    assert_eq!(rec(&s, SignedRequest, &alice("local", T), T), Ok(()));
}

#[test]
fn a_full_local_pool_does_not_touch_remote_users() {
    let s = warm_with(ReplayLimits {
        local_total: 1,
        remote_total: 10,
        per_signer: usize::MAX,
        per_remote_domain: usize::MAX,
    });
    rec(&s, SignedRequest, &alice("a", T), T).unwrap();
    assert!(matches!(
        rec(&s, SignedRequest, &alice("b", T), T),
        Err(ReplayError::Full { .. })
    ));
    assert_eq!(
        rec(&s, SignedRequest, &remote("u@one.com", "one.com", "1"), T),
        Ok(())
    );
}

#[test]
fn retry_after_on_a_domain_quota_waits_for_the_domain() {
    // The domain is at its cap; this signer holds nothing yet. Retry-After
    // must come from the domain's earliest expiry, not the signer's.
    let s = warm_with(ReplayLimits {
        per_signer: 10,
        per_remote_domain: 2,
        ..limits(100)
    });
    let mut a = remote("a@evil.com", "evil.com", "1");
    a.signed_at = T - 200; // expires at T + 101
    rec(&s, SignedRequest, &a, T).unwrap();
    rec(&s, SignedRequest, &remote("b@evil.com", "evil.com", "2"), T).unwrap();
    assert_eq!(
        rec(&s, SignedRequest, &remote("c@evil.com", "evil.com", "3"), T),
        Err(ReplayError::RateLimited { retry_after: 101 })
    );
    // And at that moment there is room again.
    assert_eq!(
        rec(
            &s,
            SignedRequest,
            &remote("c@evil.com", "evil.com", "3"),
            T + 101
        ),
        Ok(())
    );
}

/// The reviewer's interleaving: copy 2 read the clock at S+300 and waited for
/// the lock while an unrelated request at S+301 swept copy 1's entry away.
/// Copy 2 must not be accepted.
#[test]
fn a_stale_reading_cannot_resurrect_a_swept_nonce() {
    let s = warm(10);
    rec(&s, SignedRequest, &alice("dup", T), T).unwrap();
    rec(&s, SignedRequest, &alice("other", T + 300), T + SKEW + 1).unwrap();
    assert_eq!(
        rec(&s, SignedRequest, &alice("dup", T), T + SKEW),
        Err(ReplayError::Expired)
    );
    assert_eq!(
        s.check(SignedRequest, &alice("dup", T), T + SKEW),
        Err(ReplayError::Expired)
    );
}

#[test]
fn a_wall_clock_stepped_back_does_not_reopen_nonces() {
    let s = warm(10);
    rec(&s, SignedRequest, &alice("n", T), T).unwrap();
    // Time passes beyond the nonce's life; something sweeps.
    assert!(s.is_empty(T + SKEW + 1));
    // NTP steps the clock back into the nonce's window.
    assert_eq!(
        rec(&s, SignedRequest, &alice("n", T), T + 10),
        Err(ReplayError::Expired)
    );
}

#[test]
fn record_reports_expiry_and_restore_round_trips() {
    let s = warm(10);
    let recorded = s.record(SignedRequest, &alice("n", T), T).unwrap();
    assert_eq!(recorded.expires, T + SKEW + 1);
    assert_eq!(recorded.clock, T);
    let expires = recorded.expires;

    // A fresh store (a restarted process) restores what the ledger held.
    let fresh = ReplayStore::new(limits(10), SKEW, T + 5, HOME);
    assert!(fresh.warming_up());
    let stored = vec![
        StoredNonce::from_use(&alice("n", T), expires),
        // Already expired by `now`: skipped.
        StoredNonce::from_use(&alice("old", T - 400), T - 99),
    ];
    assert_eq!(fresh.restore(stored, T + 5), 1);
    fresh.end_warm_up();
    assert!(!fresh.warming_up());
    // The restored nonce is still refused; a new one is accepted at once.
    assert_eq!(
        fresh.check(SignedRequest, &alice("n", T), T + 5),
        Err(ReplayError::Replayed)
    );
    assert_eq!(
        rec(&fresh, SignedRequest, &alice("new", T + 5), T + 5),
        Ok(())
    );
}
