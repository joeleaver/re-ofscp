//! The fetch budgets of the remote key resolver (docs/decisions/0006).
//!
//! Every fetch it makes is charged to two token buckets at once, or to
//! none:
//!
//! * **the target**, by registrable domain (port and subdomains ignored, so
//!   `x@victim.example:1..65535` or `x@{n}.victim.example` behind wildcard
//!   DNS all share one bucket), with separate buckets for user keys and for
//!   provider discovery, so requests naming random handles cannot stop us
//!   from verifying the provider itself;
//! * **the client** whose request caused it, so one anonymous client cannot
//!   spend a peer's whole budget and lock that peer's real users out.
//!
//! Only a fetch that is actually about to start is charged: cache hits,
//! lookups that join a fetch already under way, and lookups refused for any
//! other reason cost nothing.

use super::fetch::Source;
use super::state::MAX_ENTRIES;
use crate::ratelimit::{Limited, RateLimiter};
use crate::registrable::registrable_group;
use crate::signing::Requester;

/// Fetches to one target (per registrable domain, user keys and discovery
/// each): at most this many at once ...
pub const DOMAIN_BURST: u32 = 20;
/// ... refilled at this rate.
pub const DOMAIN_PER_MINUTE: u32 = 30;
/// Fetches charged to one client (address, or IPv6 /64): at most this
/// many at once ...
pub const CLIENT_BURST: u32 = 10;
/// ... refilled at this rate.
pub const CLIENT_PER_MINUTE: u32 = 30;

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
    user_targets: RateLimiter,
    provider_targets: RateLimiter,
    clients: RateLimiter,
}

impl Default for Budgets {
    fn default() -> Self {
        Self {
            user_targets: RateLimiter::new(DOMAIN_BURST, DOMAIN_PER_MINUTE, MAX_ENTRIES),
            provider_targets: RateLimiter::new(DOMAIN_BURST, DOMAIN_PER_MINUTE, MAX_ENTRIES),
            clients: RateLimiter::new(CLIENT_BURST, CLIENT_PER_MINUTE, MAX_ENTRIES),
        }
    }
}

impl Budgets {
    /// Charge a fetch of `source` for `requester` at `now`: one token from
    /// the target's bucket and one from the client's, or none at all when
    /// either is empty. Callers serialize calls (the resolver holds its
    /// tables' lock), so nothing can take the tokens between the check and
    /// the charge.
    pub fn charge(
        &self,
        source: &Source,
        requester: &Requester,
        now: i64,
    ) -> Result<(), OverBudget> {
        let target = target_group(source);
        let targets = self.targets(source);
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

    fn targets(&self, source: &Source) -> &RateLimiter {
        match source {
            Source::User(_) => &self.user_targets,
            Source::Provider(_) => &self.provider_targets,
        }
    }

    /// Whether a fetch of `source` for `requester` could be charged at
    /// `now`, without charging it.
    #[cfg(test)]
    pub fn would_allow(&self, source: &Source, requester: &Requester, now: i64) -> bool {
        self.targets(source)
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
            b.charge(&source, &client, T).unwrap();
        }
        let next = Requester::new("another");
        let refused = b
            .charge(&user("zzz@victim.example:9"), &next, T)
            .unwrap_err();
        assert_eq!(refused.retry_after, 2);
        assert!(b.charge(&user("zzz@other.example"), &next, T).is_ok());
    }

    #[test]
    fn user_keys_and_discovery_have_separate_target_buckets() {
        let b = Budgets::default();
        for i in 0..DOMAIN_BURST {
            let client = Requester::new(format!("client{i}"));
            b.charge(&user(&format!("user{i}@victim.example")), &client, T)
                .unwrap();
        }
        let client = Requester::new("another");
        assert!(b.charge(&user("vvv@victim.example"), &client, T).is_err());
        assert!(b.charge(&provider("victim.example"), &client, T).is_ok());
    }

    #[test]
    fn a_client_bucket_spans_targets_and_refusals_charge_nothing() {
        let b = Budgets::default();
        let client = Requester::new("203.0.113.7");
        for i in 0..CLIENT_BURST {
            b.charge(&user(&format!("uuu@t{i}.example")), &client, T)
                .unwrap();
        }
        let source = user("uuu@fresh.example");
        let refused = b.charge(&source, &client, T).unwrap_err();
        assert_eq!(refused.retry_after, 2);
        assert_eq!(refused.why, "key fetch budget spent (client)");
        // The refused charge took nothing from the target's bucket.
        for i in 0..DOMAIN_BURST {
            let other = Requester::new(format!("other{i}"));
            b.charge(&source, &other, T).unwrap();
        }
        // Over both: the longer wait.
        let refused = b.charge(&source, &client, T).unwrap_err();
        assert_eq!(refused.retry_after, 2);
        assert!(!b.would_allow(&source, &client, T + 1));
        assert!(b.would_allow(&source, &client, T + 2));
    }
}
