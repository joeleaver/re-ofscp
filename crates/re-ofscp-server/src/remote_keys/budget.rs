//! The fetch budgets of the remote key resolver (docs/decisions/0006).
//!
//! Every fetch it makes is charged to several token buckets at once, or to
//! none:
//!
//! * **the target**, by registrable domain (port and subdomains ignored, so
//!   `x@victim.example:1..65535` or `x@{n}.victim.example` behind wildcard
//!   DNS all share one bucket). Each target has two buckets: **known**,
//!   for expiry-driven fetches of known sources (the last
//!   completed fetch found keys), and **first-time**, for everything else,
//!   including every re-fetch on a key miss. Requests naming random
//!   handles or subdomains, or real users with bogus key ids, are all
//!   first-time, so they cannot spend the budget that keeps a peer's
//!   existing users working; an expiry fetch happens at most once per
//!   cache lifetime per source, however often it is named;
//! * **the client** whose request caused it, at a rate well below each
//!   target bucket's, so one anonymous client cannot keep any of a peer's
//!   buckets empty and lock that peer's real users out;
//! * for an IPv6 client, also **its network** (the /48 its /64 sits in),
//!   so a subscriber holding a /48, and so 65 536 /64s each a client of
//!   its own, still gets only a bounded share.
//!
//! All of these are charged together, or none is. Only a fetch that is
//! actually about to start is charged: cache hits, lookups that join a
//! fetch already under way, and lookups refused for any other reason cost
//! nothing.

use super::fetch::Source;
use super::state::MAX_ENTRIES;
use crate::ratelimit::RateLimiter;
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
/// Fetches charged to one IPv6 /48, all its /64s together: at most this
/// many at once (five clients' worth) ...
pub const NETWORK_BURST: u32 = 5 * CLIENT_BURST;
/// ... refilled at this rate (five clients' worth).
pub const NETWORK_PER_MINUTE: u32 = 5 * CLIENT_PER_MINUTE;

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
    /// Which budgets ran out (for the log).
    pub why: &'static str,
}

/// The kinds of bucket a fetch is charged to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Target,
    Client,
    Network,
}

/// The log message for a refusal by the buckets of the kinds in `spent`
/// (each at most once, in [`Kind`] order).
fn spent_why(spent: &[Kind]) -> &'static str {
    use Kind::{Client, Network, Target};
    match spent {
        [Target] => "key fetch budget spent (target)",
        [Client] => "key fetch budget spent (client)",
        [Network] => "key fetch budget spent (client network)",
        [Target, Client] => "key fetch budget spent (target and client)",
        [Target, Network] => "key fetch budget spent (target and client network)",
        [Client, Network] => "key fetch budget spent (client and client network)",
        // All three (an empty list is never passed).
        _ => "key fetch budget spent (target, client and client network)",
    }
}

/// The resolver's token buckets.
#[derive(Debug)]
pub struct Budgets {
    known: RateLimiter,
    first_time: RateLimiter,
    clients: RateLimiter,
    networks: RateLimiter,
}

impl Default for Budgets {
    fn default() -> Self {
        let target = || RateLimiter::new(DOMAIN_BURST, DOMAIN_PER_MINUTE, MAX_ENTRIES);
        Self {
            known: target(),
            first_time: target(),
            clients: RateLimiter::new(CLIENT_BURST, CLIENT_PER_MINUTE, MAX_ENTRIES),
            networks: RateLimiter::new(NETWORK_BURST, NETWORK_PER_MINUTE, MAX_ENTRIES),
        }
    }
}

impl Budgets {
    /// Charge a fetch of `source` (of `standing`) for `requester` at `now`:
    /// one token from the target's bucket, the client's and (for an IPv6
    /// client) its network's, or none at all when any is empty. Callers
    /// serialize calls (the resolver holds its tables' lock), so nothing
    /// can take the tokens between the check and the charge.
    pub fn charge(
        &self,
        source: &Source,
        standing: Standing,
        requester: &Requester,
        now: i64,
    ) -> Result<(), OverBudget> {
        let target = target_group(source);
        let buckets = self.buckets(standing, &target, requester);
        let mut spent = Vec::new();
        let mut retry_after = 0;
        for (kind, limiter, key) in buckets.iter().flatten() {
            if let Err(l) = limiter.peek(key, now) {
                spent.push(*kind);
                retry_after = retry_after.max(l.retry_after);
            }
        }
        if !spent.is_empty() {
            return Err(OverBudget {
                retry_after,
                why: spent_why(&spent),
            });
        }
        for (kind, limiter, key) in buckets.iter().flatten() {
            limiter.check(key, now).map_err(|l| OverBudget {
                retry_after: l.retry_after,
                why: spent_why(&[*kind]),
            })?;
        }
        Ok(())
    }

    /// The buckets a fetch (of `standing`, in target group
    /// `target`) for `requester` is charged to, with their keys, in
    /// [`Kind`] order.
    fn buckets<'a>(
        &'a self,
        standing: Standing,
        target: &'a str,
        requester: &'a Requester,
    ) -> [Option<(Kind, &'a RateLimiter, &'a str)>; 3] {
        [
            Some((Kind::Target, self.targets(standing), target)),
            Some((Kind::Client, &self.clients, requester.as_str())),
            requester
                .network()
                .map(|network| (Kind::Network, &self.networks, network)),
        ]
    }

    fn targets(&self, standing: Standing) -> &RateLimiter {
        match standing {
            Standing::Known => &self.known,
            Standing::FirstTime => &self.first_time,
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
        let target = target_group(source);
        self.buckets(standing, &target, requester)
            .iter()
            .flatten()
            .all(|(_, limiter, key)| limiter.peek(key, now).is_ok())
    }
}

/// The bucket a fetch of `source` is charged to: the registrable domain of
/// its host, port dropped.
pub fn target_group(source: &Source) -> String {
    registrable_group(source.host().as_str())
}

#[cfg(test)]
mod tests {
    use re_ofscp_types::Actor;

    use super::Standing::{FirstTime, Known};
    use super::*;

    const T: i64 = 1_800_000_000;

    fn user(id: &str) -> Source {
        Source::of(&Actor::parse_canonical(id).unwrap())
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
            user("yyy@www.victim.example"),
        ] {
            assert_eq!(target_group(&other), group, "{other:?}");
        }
        assert_ne!(target_group(&user("xxx@other.example")), group);
    }

    #[test]
    fn private_section_subdomains_share_their_icann_target() {
        let b = Budgets::default();
        assert_eq!(target_group(&user("xxx@s1.workers.dev")), "workers.dev");
        for i in 0..DOMAIN_BURST {
            let client = Requester::new(format!("client{i}"));
            let source = user(&format!("user{i}@s{i}.workers.dev"));
            b.charge(&source, FirstTime, &client, T).unwrap();
        }
        let next = Requester::new("another");
        let refused = b
            .charge(&user("zzz@fresh.workers.dev"), FirstTime, &next, T)
            .unwrap_err();
        assert_eq!(refused.why, "key fetch budget spent (target)");
    }

    #[test]
    fn one_48_cycling_through_64s_is_refused_and_other_48s_are_not() {
        let b = Budgets::default();
        let in_48 = |net: u16, sub: u16| {
            Requester::within(
                format!("2001:db8:{net:x}:{sub:x}::/64"),
                Some(format!("2001:db8:{net:x}::/48")),
            )
        };
        // Each /64 spends one token (well inside its own burst of 10); the
        // /48 together has five clients' worth.
        for i in 0..NETWORK_BURST {
            let target = user(&format!("uuu@t{i}.example"));
            b.charge(&target, FirstTime, &in_48(1, i as u16), T)
                .unwrap();
        }
        let fresh = user("uuu@fresh.example");
        let next = in_48(1, 0xffff);
        let refused = b.charge(&fresh, FirstTime, &next, T).unwrap_err();
        assert_eq!(refused.why, "key fetch budget spent (client network)");
        // 50 per minute: one token every 1.2 s.
        assert_eq!(refused.retry_after, 2);
        assert!(!b.would_allow(&fresh, FirstTime, &next, T + 1));
        assert!(b.would_allow(&fresh, FirstTime, &next, T + 2));
        // The refusal charged nothing: the target and the /64 are full.
        for i in 0..DOMAIN_BURST {
            let other = Requester::new(format!("other{i}"));
            b.charge(&fresh, FirstTime, &other, T).unwrap();
        }
        let elsewhere = user("uuu@elsewhere.example");
        assert!(b.would_allow(
            &elsewhere,
            FirstTime,
            &Requester::new("2001:db8:1:ffff::/64"),
            T
        ));
        // Other /48s, and IPv4 clients, are unaffected.
        for net in [2, 3] {
            for i in 0..CLIENT_BURST {
                let target = user(&format!("vvv@n{net}-{i}.example"));
                b.charge(&target, FirstTime, &in_48(net, 1), T).unwrap();
            }
        }
        b.charge(&elsewhere, FirstTime, &Requester::new("203.0.113.7"), T)
            .unwrap();
    }

    #[test]
    fn a_client_over_both_its_own_and_its_network_budget_says_so() {
        let b = Budgets::default();
        let client = Requester::within("2001:db8:1:1::/64", Some("2001:db8:1::/48".to_owned()));
        for i in 0..CLIENT_BURST {
            b.charge(&user(&format!("uuu@t{i}.example")), FirstTime, &client, T)
                .unwrap();
        }
        for i in CLIENT_BURST..NETWORK_BURST {
            let sibling = Requester::within(
                format!("2001:db8:1:{i:x}::/64"),
                Some("2001:db8:1::/48".to_owned()),
            );
            b.charge(&user(&format!("uuu@t{i}.example")), FirstTime, &sibling, T)
                .unwrap();
        }
        let refused = b
            .charge(&user("uuu@fresh.example"), FirstTime, &client, T)
            .unwrap_err();
        assert_eq!(
            refused.why,
            "key fetch budget spent (client and client network)"
        );
        assert_eq!(refused.retry_after, 6);
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
    fn known_and_first_time_fetches_have_separate_buckets() {
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
