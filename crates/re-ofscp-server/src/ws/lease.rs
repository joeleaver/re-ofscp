//! How long a connection may keep relying on its key, and when to
//! re-confirm it (spec §7.1 "For a connection from a remote actor",
//! lost-conn/ofscp#20).
//!
//! * A key held [`Lifetime::Until`] a cache entry's `cache_until` is
//!   re-confirmed before then: from `cache_until` minus a lead of half the
//!   remaining time, at most [`RENEW_LEAD_MAX`] seconds, and every
//!   [`RETRY_SECS`] after an unconfirmed attempt. If `cache_until` passes
//!   without a completed fetch extending it, the connection closes with
//!   `4001`, whether or not an attempt was made.
//! * A key from an answer that could not be cached ([`Lifetime::Uncached`])
//!   has no entry: it is re-confirmed every [`UNCACHED_INTERVAL`] seconds,
//!   and the first attempt that does not complete closes with `4001`.
//! * A completed fetch that no longer publishes the key closes with
//!   `4003`, at once.
//! * A key with no expiry ([`Lifetime::Unbounded`]: local accounts) is
//!   never re-confirmed here: revocation is announced and closes the
//!   connection directly.
//!
//! Times are unix seconds on the verifier's clock, the one key caches
//! expire by.

use crate::signing::{Lifetime, Reconfirmed};

/// Longest lead before `cache_until` at which re-confirming starts.
pub const RENEW_LEAD_MAX: i64 = 60;
/// Wait between attempts while the key is unconfirmed.
pub const RETRY_SECS: i64 = 10;
/// How often a key without a cache entry is re-confirmed.
pub const UNCACHED_INTERVAL: i64 = 60;

/// What to do now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Nothing.
    Idle,
    /// Start re-confirming the key held for this lifetime.
    Reconfirm(Lifetime),
    /// The key can no longer be confirmed: close with `4001`.
    Expire,
}

/// What a re-confirmation means for the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// It stays open.
    Keep,
    /// The key is gone: close with `4003`.
    Revoked,
    /// The key could not be confirmed and nothing else holds it: close
    /// with `4001`.
    Expired,
}

/// A connection's hold on its key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    held: Lifetime,
    next: i64,
    in_flight: bool,
}

impl Lease {
    /// A lease on a key verified at `now`, relied on for `held`.
    pub fn new(held: Lifetime, now: i64) -> Self {
        Self {
            held,
            next: first_attempt(held, now),
            in_flight: false,
        }
    }

    /// What the key is currently relied on for.
    pub fn held(&self) -> Lifetime {
        self.held
    }

    /// Seconds from `now` until [`Lease::poll`] may next have something to
    /// do (`0`: now), or `None` if nothing is due until a re-confirmation
    /// in flight settles, or ever.
    pub fn due_in(&self, now: i64) -> Option<i64> {
        let due = match (self.held, self.in_flight) {
            (Lifetime::Unbounded, _) | (Lifetime::Uncached, true) => return None,
            (Lifetime::Uncached, false) => self.next,
            (Lifetime::Until(t), true) => t,
            (Lifetime::Until(t), false) => self.next.min(t),
        };
        Some(due.saturating_sub(now).max(0))
    }

    /// What to do at `now`. A [`Step::Reconfirm`] must be answered with
    /// [`Lease::settle`] before another is issued.
    pub fn poll(&mut self, now: i64) -> Step {
        match self.held {
            Lifetime::Unbounded => Step::Idle,
            Lifetime::Until(t) if now >= t => Step::Expire,
            _ if self.in_flight || now < self.next => Step::Idle,
            held => {
                self.in_flight = true;
                Step::Reconfirm(held)
            }
        }
    }

    /// Take in what the re-confirmation started by the last
    /// [`Step::Reconfirm`] found, at `now`.
    pub fn settle(&mut self, found: &Reconfirmed, now: i64) -> Outcome {
        self.in_flight = false;
        match (found, self.held) {
            (Reconfirmed::Gone, _) => Outcome::Revoked,
            (Reconfirmed::Unconfirmed(_), Lifetime::Uncached) => Outcome::Expired,
            (Reconfirmed::Unconfirmed(_), _) => {
                self.next = now + RETRY_SECS;
                Outcome::Keep
            }
            // A completed fetch that does not reach past what we hold
            // (the peer kept its `cache_until`) extends nothing: retry.
            (Reconfirmed::Present(Lifetime::Until(t2)), Lifetime::Until(t)) if *t2 <= t => {
                self.next = now + RETRY_SECS;
                Outcome::Keep
            }
            (Reconfirmed::Present(lifetime), _) => {
                self.held = *lifetime;
                self.next = first_attempt(*lifetime, now);
                Outcome::Keep
            }
        }
    }
}

/// When to make the first attempt for a key relied on for `held` from
/// `now`.
fn first_attempt(held: Lifetime, now: i64) -> i64 {
    match held {
        Lifetime::Unbounded => i64::MAX,
        Lifetime::Uncached => now + UNCACHED_INTERVAL,
        Lifetime::Until(t) => {
            // Half the remaining time, rounded up, so even a key about to
            // expire gets one attempt.
            let lead = ((t - now + 1) / 2).clamp(0, RENEW_LEAD_MAX);
            (t - lead).max(now)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: i64 = 1_000_000;

    fn unconfirmed() -> Reconfirmed {
        Reconfirmed::Unconfirmed("peer down".into())
    }

    #[test]
    fn a_cached_key_is_renewed_before_it_expires() {
        let mut lease = Lease::new(Lifetime::Until(T + 3600), T);
        assert_eq!(lease.poll(T + 3539), Step::Idle);
        assert_eq!(
            lease.poll(T + 3540),
            Step::Reconfirm(Lifetime::Until(T + 3600))
        );
        assert_eq!(lease.poll(T + 3541), Step::Idle, "one attempt at a time");
        let found = Reconfirmed::Present(Lifetime::Until(T + 7200));
        assert_eq!(lease.settle(&found, T + 3541), Outcome::Keep);
        assert_eq!(lease.held(), Lifetime::Until(T + 7200));
        assert_eq!(lease.poll(T + 3600), Step::Idle, "extended");
    }

    #[test]
    fn failures_keep_it_open_until_cache_until_then_4001() {
        let mut lease = Lease::new(Lifetime::Until(T + 20), T);
        assert_eq!(lease.poll(T + 10), Step::Reconfirm(Lifetime::Until(T + 20)));
        assert_eq!(lease.settle(&unconfirmed(), T + 10), Outcome::Keep);
        assert_eq!(lease.poll(T + 19), Step::Idle);
        // An attempt still under way at expiry does not keep it open.
        assert!(matches!(lease.poll(T + 20), Step::Expire));
        let mut short = Lease::new(Lifetime::Until(T + 1), T);
        assert!(matches!(short.poll(T), Step::Reconfirm(_)));
        assert_eq!(short.poll(T + 1), Step::Expire);
    }

    #[test]
    fn a_refresh_that_does_not_extend_is_retried() {
        let mut lease = Lease::new(Lifetime::Until(T + 100), T);
        assert!(matches!(lease.poll(T + 50), Step::Reconfirm(_)));
        let same = Reconfirmed::Present(Lifetime::Until(T + 100));
        assert_eq!(lease.settle(&same, T + 50), Outcome::Keep);
        assert_eq!(lease.poll(T + 59), Step::Idle);
        assert!(matches!(lease.poll(T + 60), Step::Reconfirm(_)));
    }

    #[test]
    fn gone_is_4003_whatever_is_held() {
        for held in [Lifetime::Until(T + 100), Lifetime::Uncached] {
            let mut lease = Lease::new(held, T);
            assert!(matches!(
                lease.poll(T + 100),
                Step::Reconfirm(_) | Step::Expire
            ));
            assert_eq!(lease.settle(&Reconfirmed::Gone, T + 60), Outcome::Revoked);
        }
    }

    #[test]
    fn an_uncached_key_is_rechecked_and_closes_on_the_first_failure() {
        let mut lease = Lease::new(Lifetime::Uncached, T);
        assert_eq!(lease.poll(T + 59), Step::Idle);
        assert_eq!(lease.poll(T + 60), Step::Reconfirm(Lifetime::Uncached));
        let found = Reconfirmed::Present(Lifetime::Uncached);
        assert_eq!(lease.settle(&found, T + 60), Outcome::Keep);
        assert_eq!(lease.poll(T + 119), Step::Idle);
        assert!(matches!(lease.poll(T + 120), Step::Reconfirm(_)));
        assert_eq!(lease.settle(&unconfirmed(), T + 120), Outcome::Expired);
    }

    #[test]
    fn local_keys_are_never_reconfirmed() {
        let mut lease = Lease::new(Lifetime::Unbounded, T);
        assert_eq!(lease.poll(i64::MAX - 1), Step::Idle);
    }

    #[test]
    fn due_in_names_the_next_attempt_or_the_expiry() {
        let mut l = Lease::new(Lifetime::Until(200), 0);
        assert_eq!(l.due_in(0), Some(140), "the first attempt, 60 s ahead");
        assert_eq!(l.due_in(150), Some(0));
        assert_eq!(l.poll(150), Step::Reconfirm(Lifetime::Until(200)));
        assert_eq!(l.due_in(150), Some(50), "in flight: only the expiry");
        assert_eq!(Lease::new(Lifetime::Unbounded, 0).due_in(0), None);
        let mut u = Lease::new(Lifetime::Uncached, 0);
        assert_eq!(u.due_in(0), Some(UNCACHED_INTERVAL));
        assert!(matches!(u.poll(UNCACHED_INTERVAL), Step::Reconfirm(_)));
        assert_eq!(u.due_in(UNCACHED_INTERVAL), None);
    }
}
