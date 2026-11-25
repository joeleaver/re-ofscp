//! The fetch budgets of the remote key resolver (docs/decisions/0006).
//!
//! Every fetch it makes is charged to two token buckets at once, or to
//! none:
//!
//! * **the target**, by registrable domain (port and subdomains ignored, so
//!   `x@victim.example:1..65535` or `x@{n}.victim.example` behind wildcard
//!   DNS all share one bucket). Each target has four buckets: user keys and
//!   provider discovery apart, so requests naming random handles cannot
//!   stop us from verifying the provider itself; and each of those split
//!   into **known**, for expiry-driven fetches of known sources (the last
//!   completed fetch found keys), and **first-time**, for everything else,
//!   including every re-fetch on a key miss. Requests naming random
//!   handles or subdomains, or real users with bogus key ids, are all
//!   first-time, so they cannot spend the budget that keeps a peer's
//!   existing users working; an expiry fetch happens at most once per
//!   cache lifetime per source, however often it is named;
//! * **the client** whose request caused it, at a rate well below each
//!   target bucket's, so one anonymous client cannot keep any of a peer's
//!   buckets empty and lock that peer's real users out.
//!
//! Only a fetch that is actually about to start is charged: cache hits,
//! lookups that join a fetch already under way, and lookups refused for any
//! other reason cost nothing.

use super::fetch::Source;
use super::state::MAX_ENTRIES;
use crate::ratelimit::{Limited, RateLimiter};
use crate::registrable::registrable_group;
use crate::signing::Requester;

/// Fetches to one target, in each of its buckets (user keys or discovery,
/// known or first-time): at most this many at once ...
pub const DOMAIN_BURST: u32 = 20;
/// ... refilled at this rate.
pub const DOMAIN_PER_MINUTE: u32 = 30;
/// Fetches charged to one client (address, or IPv6 /64): at most this
/// many at once ...
pub const CLIENT_BURST: u32 = 10;
/// ... refilled at this rate: a third of a target bucket's, so a single
/// client can never keep one empty.
pub const CLIENT_PER_MINUTE: u32 = 10;

/// Which of a target's buckets a fetch is charged to; each standing has
/// its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// An expiry-driven fetch (not a re-fetch on a key miss) of a source
    /// whose last completed fetch found keys.
    Known,
    /// Any other fetch: a source never fetched, or last found an empty
    /// list or a `404`, and every re-fetch on a key miss.
    FirstTime,
}

/// A fetch the budgets do not allow now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverBudget {
    /// Seconds until every budget involved has a token again.
    pub retry_after: u64,
    /// Which budget ran out (for the log).
    pub why: &'static str,
}

/// The resolver's token buckets.
#[derive(Debug)]
pub struct Budgets {
    user_known: RateLimiter,
    user_first_time: RateLimiter,
    provider_known: RateLimiter,
    provider_first_time: RateLimiter,
    clients: RateLimiter,
}

impl Default for Budgets {
    fn default() -> Self {
        let target = || RateLimiter::new(DOMAIN_BURST, DOMAIN_PER_MINUTE, MAX_ENTRIES);
        Self {
            user_known: target(),
            user_first_time: target(),
            provider_known: target(),
            provider_first_time: target(),
            clients: RateLimiter::new(CLIENT_BURST, CLIENT_PER_MINUTE, MAX_ENTRIES),
        }
    }
}

impl Budgets {
    /// Charge a fetch of `source` (of `standing`) for `requester` at `now`:
    /// one token from the target's bucket and one from the client's, or
    /// none at all when either is empty. Callers serialize calls (the
    /// resolver holds its tables' lock), so nothing can take the tokens
    /// between the check and the charge.
    pub fn charge(
        &self,
        source: &Source,
        standing: Standing,
        requester: &Requester,
        now: i64,
    ) -> Result<(), OverBudget> {
        let target = target_group(source);
        let targets = self.targets(source, standing);
        let target_check = targets.peek(&target, now);
        let client_check = self.clients.peek(requester.as_str(), now);
        let over = |l: Limited, why| OverBudget {
            retry_after: l.retry_after,
            why,
        };
        match (target_check, client_check) {
            (Ok(()), Ok(())) => {}
            (Err(t), Err(c)) => {
                return Err(over(
                    Limited {
                        retry_after: t.retry_after.max(c.retry_after),
                    },
                    "key fetch budget spent (target and client)",
                ));
            }
            (Err(t), Ok(())) => return Err(over(t, "key fetch budget spent (target)")),
            (Ok(()), Err(c)) => return Err(over(c, "key fetch budget spent (client)")),
        }
        targets
            .check(&target, now)
            .map_err(|l| over(l, "key fetch budget spent (target)"))?;
        self.clients
            .check(requester.as_str(), now)
            .map_err(|l| over(l, "key fetch budget spent (client)"))
    }

    fn targets(&self, source: &Source, standing: Standing) -> &RateLimiter {
        match (source, standing) {
            (Source::User(_), Standing::Known) => &self.user_known,
            (Source::User(_), Standing::FirstTime) => &self.user_first_time,
            (Source::Provider(_), Standing::Known) => &self.provider_known,
            (Source::Provider(_), Standing::FirstTime) => &self.provider_first_time,
        }
    }

    /// Whether a fetch of `source` (of `standing`) for `requester` could be
    /// charged at `now`, without charging it.
    #[cfg(test)]
    pub fn would_allow(
        &self,
        source: &Source,
        standing: Standing,
        requester: &Requester,
        now: i64,
    ) -> bool {
        self.targets(source, standing)
            .peek(&target_group(source), now)
            .is_ok()
            && self.clients.peek(requester.as_str(), now).is_ok()
    }
}

/// The bucket a fetch of `source` is charged to: the registrable domain of
/// its host, port dropped.
pub fn target_group(source: &Source) -> String {
    registrable_group(source.host().as_str())
}

#[cfg(test)]
mod tests {
    use re_ofscp_types::{Actor, Authority};

    use super::Standing::{FirstTime, Known};
    use super::*;

    const T: i64 = 1_800_000_000;

    fn user(id: &str) -> Source {
        Source::User(Actor::parse_canonical(id).unwrap())
    }

    fn provider(authority: &str) -> Source {
        Source::Provider(Authority::parse_canonical(authority).unwrap())
    }

    #[test]
    fn ports_and_subdomains_share_a_target_group() {
        let group = target_group(&user("xxx@victim.example"));
        assert_eq!(group, "victim.example");
        for other in [
            user("xxx@victim.example:1"),
            user("yyy@victim.example:65535"),
            user("xxx@a.victim.example"),
            user("xxx@123.b.victim.example:8443"),
            provider("victim.example:8443"),
            provider("www.victim.example"),
        ] {
            assert_eq!(target_group(&other), group, "{other:?}");
        }
        assert_ne!(target_group(&user("xxx@other.example")), group);
    }

    #[test]
    fn a_target_bucket_is_shared_by_ports_and_subdomains() {
        let b = Budgets::default();
        for i in 0..DOMAIN_BURST {
            // A fresh client each time: only the target bucket drains.
            let client = Requester::new(format!("client{i}"));
            let source = user(&format!("user{i}@s{i}.victim.example:{}", 1000 + i));
            b.charge(&source, FirstTime, &client, T).unwrap();
        }
        let next = Requester::new("another");
        let refused = b
            .charge(&user("zzz@victim.example:9"), FirstTime, &next, T)
            .unwrap_err();
        assert_eq!(refused.retry_after, 2);
        assert!(
            b.charge(&user("zzz@other.example"), FirstTime, &next, T)
                .is_ok()
        );
    }

    #[test]
    fn user_keys_discovery_known_and_first_time_have_separate_buckets() {
        let b = Budgets::default();
        for i in 0..DOMAIN_BURST {
            let client = Requester::new(format!("client{i}"));
            b.charge(
                &user(&format!("user{i}@victim.example")),
                FirstTime,
                &client,
                T,
            )
            .unwrap();
        }
        let client = Requester::new("another");
        let next = user("vvv@victim.example");
        assert!(b.charge(&next, FirstTime, &client, T).is_err());
        assert!(b.charge(&next, Known, &client, T).is_ok());
        let victim = provider("victim.example");
        assert!(b.charge(&victim, FirstTime, &client, T).is_ok());
        assert!(b.charge(&victim, Known, &client, T).is_ok());
    }

    #[test]
    fn a_client_bucket_spans_targets_and_refusals_charge_nothing() {
        let b = Budgets::default();
        let client = Requester::new("203.0.113.7");
        for i in 0..CLIENT_BURST {
            b.charge(&user(&format!("uuu@t{i}.example")), FirstTime, &client, T)
                .unwrap();
        }
        let source = user("uuu@fresh.example");
        let refused = b.charge(&source, FirstTime, &client, T).unwrap_err();
        // 10 per minute: one token every 6 s.
        assert_eq!(refused.retry_after, 6);
        assert_eq!(refused.why, "key fetch budget spent (client)");
        // The refused charge took nothing from the target's bucket.
        for i in 0..DOMAIN_BURST {
            let other = Requester::new(format!("other{i}"));
            b.charge(&source, FirstTime, &other, T).unwrap();
        }
        assert!(!b.would_allow(&source, FirstTime, &client, T + 5));
        assert!(b.would_allow(&source, FirstTime, &client, T + 6));
    }

    #[test]
    fn over_both_budgets_the_longer_wait_is_given() {
        let b = Budgets::default();
        let source = user("uuu@victim.example");
        let drain_target = |at: i64| {
            for i in 0..DOMAIN_BURST {
                let other = Requester::new(format!("other{at}-{i}"));
                b.charge(&source, FirstTime, &other, at).unwrap();
            }
        };
        let drain_client = |client: &Requester, at: i64| {
            for i in 0..CLIENT_BURST {
                let elsewhere = user(&format!("uuu@t{i}.example"));
                b.charge(&elsewhere, FirstTime, client, at).unwrap();
            }
        };
        // The client's wait (6 s) is the longer: both drained just now.
        let slow = Requester::new("203.0.113.7");
        drain_client(&slow, T);
        drain_target(T);
        let refused = b.charge(&source, FirstTime, &slow, T).unwrap_err();
        assert_eq!(refused.why, "key fetch budget spent (target and client)");
        assert_eq!(refused.retry_after, 6);
        // The target's wait (2 s) is the longer: this client drained its
        // bucket 5 s ago, so its next token is 1 s away.
        let b = Budgets::default();
        let nearly = Requester::new("203.0.113.8");
        for i in 0..CLIENT_BURST {
            let elsewhere = user(&format!("uuu@t{i}.example"));
            b.charge(&elsewhere, FirstTime, &nearly, T - 5).unwrap();
        }
        for i in 0..DOMAIN_BURST {
            let other = Requester::new(format!("other{i}"));
            b.charge(&source, FirstTime, &other, T).unwrap();
        }
        let refused = b.charge(&source, FirstTime, &nearly, T).unwrap_err();
        assert_eq!(refused.why, "key fetch budget spent (target and client)");
        assert_eq!(refused.retry_after, 2);
    }

    #[test]
    fn first_time_spam_never_starves_known_sources() {
        let b = Budgets::default();
        let alice = user("alice@victim.example");
        let spam = |n: u64| user(&format!("r{n:05}@victim.example"));
        let mut n = 0;
        // One client spamming first-time lookups, once a second for five
        // minutes, cannot even keep the first-time bucket empty: it gets
        // its own 10 per minute, the bucket refills at 30.
        let spammer = Requester::new("203.0.113.66");
        for t in T..T + 300 {
            n += 1;
            let _ = b.charge(&spam(n), FirstTime, &spammer, t);
            let other = Requester::new(format!("198.51.100.{}", t % 200));
            assert!(
                b.would_allow(&spam(n + 1), FirstTime, &other, t),
                "first-time bucket emptied by one client at +{}s",
                t - T
            );
        }
        // Many clients together can empty the first-time bucket, but a
        // known source's expiry re-fetch is charged to the known bucket
        // and still goes through, every minute.
        let start = T + 300;
        for t in start..start + 300 {
            for c in 0..8 {
                n += 1;
                let spammer = Requester::new(format!("2001:db8:{c}::/64"));
                let _ = b.charge(&spam(n), FirstTime, &spammer, t);
            }
            if (t - start) % 60 == 59 {
                let fresh = Requester::new(format!("192.0.2.{}", t % 200));
                assert!(
                    !b.would_allow(&spam(n + 1), FirstTime, &fresh, t),
                    "eight spammers keep the first-time bucket empty"
                );
                b.charge(&alice, Known, &fresh, t).unwrap();
            }
        }
    }
}
