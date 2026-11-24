//! Rate limiting for unauthenticated endpoints (spec §4.1.5).
//!
//! * [`RateLimiter`]: a token bucket per key (e.g. per client address):
//!   `burst` requests at once, refilled at `per_minute`.
//! * [`FailureBackoff`]: progressive lockout per key (e.g. per handle). An
//!   attempt is admitted only while the key is not locked, and counts as a
//!   failure *before* it is checked; from the `free`-th admitted attempt on,
//!   admission also sets the lock that applies should it fail (doubling per
//!   attempt, capped). So concurrent attempts cannot slip in ahead of the
//!   first recorded failure, refused attempts never extend a lock, and once
//!   a lock lapses one attempt is let through again. A success clears it.
//!
//! Both are bounded: past their capacity they drop idle entries first and,
//! if still full, refuse new keys (fail closed) rather than forget a key
//! under limit.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

/// A rate-limit refusal: retry after this many seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limited {
    /// Seconds to wait.
    pub retry_after: u64,
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    updated: i64,
}

/// A token bucket per key.
#[derive(Debug)]
pub struct RateLimiter {
    buckets: Mutex<HashMap<String, Bucket>>,
    burst: f64,
    per_sec: f64,
    capacity: usize,
}

impl RateLimiter {
    /// `burst` at once, refilled at `per_minute`, tracking at most `capacity`
    /// keys.
    pub fn new(burst: u32, per_minute: u32, capacity: usize) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            burst: f64::from(burst.max(1)),
            per_sec: f64::from(per_minute.max(1)) / 60.0,
            capacity,
        }
    }

    /// Take one token for `key` at `now` (unix seconds).
    pub fn check(&self, key: &str, now: i64) -> Result<(), Limited> {
        let mut map = self.buckets.lock().unwrap_or_else(PoisonError::into_inner);
        if !map.contains_key(key) && map.len() >= self.capacity {
            // Drop buckets that have refilled completely (idle keys).
            let (burst, per_sec) = (self.burst, self.per_sec);
            map.retain(|_, b| b.tokens + per_sec * ((now - b.updated) as f64) < burst);
            if map.len() >= self.capacity {
                return Err(Limited { retry_after: 1 });
            }
        }
        let b = map.entry(key.to_owned()).or_insert(Bucket {
            tokens: self.burst,
            updated: now,
        });
        let elapsed = (now - b.updated).max(0) as f64;
        b.tokens = (b.tokens + elapsed * self.per_sec).min(self.burst);
        b.updated = b.updated.max(now);
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            Ok(())
        } else {
            let wait = ((1.0 - b.tokens) / self.per_sec).ceil();
            Err(Limited {
                retry_after: (wait as u64).max(1),
            })
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Failures {
    count: u32,
    locked_until: i64,
}

/// Progressive lockout per key after repeated failures.
#[derive(Debug)]
pub struct FailureBackoff {
    entries: Mutex<HashMap<String, Failures>>,
    free: u32,
    base_secs: i64,
    max_secs: i64,
    capacity: usize,
}

impl FailureBackoff {
    /// Allow `free` consecutive failures; then lock for `base_secs`, doubling
    /// per further failure up to `max_secs`. Track at most `capacity` keys.
    pub fn new(free: u32, base_secs: i64, max_secs: i64, capacity: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            free,
            base_secs: base_secs.max(1),
            max_secs: max_secs.max(1),
            capacity,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Failures>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Begin an attempt for `key` at `now`: refused while the key is
    /// locked. Otherwise admitted and counted as a failure up front; from
    /// the `free`-th attempt on it also locks the key, as if it had already
    /// failed. Follow with [`FailureBackoff::succeed`] if it succeeds, or
    /// [`FailureBackoff::refund`] if it could not be decided (a server
    /// fault): neither then counts against the key.
    pub fn attempt(&self, key: &str, now: i64) -> Result<(), Limited> {
        let mut map = self.lock();
        if let Some(f) = map.get(key)
            && f.locked_until > now
        {
            return Err(Limited {
                retry_after: u64::try_from(f.locked_until - now).unwrap_or(1).max(1),
            });
        }
        if !map.contains_key(key) && map.len() >= self.capacity {
            // Forget keys that are not locked right now. If every tracked
            // key is locked, refuse untracked ones (fail closed).
            map.retain(|_, f| f.locked_until > now);
            if map.len() >= self.capacity {
                return Err(Limited { retry_after: 1 });
            }
        }
        let f = map.entry(key.to_owned()).or_insert(Failures {
            count: 0,
            locked_until: 0,
        });
        f.count = f.count.saturating_add(1);
        if f.count >= self.free.max(1) {
            let exp = (f.count - self.free.max(1)).min(30);
            let secs = self
                .base_secs
                .saturating_mul(1i64 << exp)
                .min(self.max_secs);
            f.locked_until = now + secs;
        }
        Ok(())
    }

    /// Take back an admitted attempt that was never decided (the server
    /// failed before checking it), so faults do not lock anyone out.
    pub fn refund(&self, key: &str) {
        let mut map = self.lock();
        if let Some(f) = map.get_mut(key) {
            f.count = f.count.saturating_sub(1);
            // The attempt was admitted, so any earlier lock had lapsed: the
            // only lock to undo is the one this attempt set.
            f.locked_until = 0;
            if f.count == 0 {
                map.remove(key);
            }
        }
    }

    /// Clear `key` after a success.
    pub fn succeed(&self, key: &str) {
        self.lock().remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: i64 = 1_000_000;

    #[test]
    fn bucket_allows_burst_then_refills() {
        let r = RateLimiter::new(3, 60, 100);
        for _ in 0..3 {
            assert_eq!(r.check("a", T), Ok(()));
        }
        assert_eq!(r.check("a", T), Err(Limited { retry_after: 1 }));
        assert_eq!(r.check("b", T), Ok(()), "keys are independent");
        assert_eq!(r.check("a", T + 1), Ok(()), "one token per second");
        assert!(r.check("a", T + 1).is_err());
    }

    #[test]
    fn bucket_retry_after_is_truthful() {
        let r = RateLimiter::new(1, 6, 100); // one per 10 s
        r.check("a", T).unwrap();
        assert_eq!(r.check("a", T), Err(Limited { retry_after: 10 }));
        assert!(r.check("a", T + 9).is_err());
        assert_eq!(r.check("a", T + 10), Ok(()));
    }

    #[test]
    fn bucket_capacity_fails_closed_but_drops_idle_keys() {
        let r = RateLimiter::new(1, 60, 2);
        r.check("a", T).unwrap();
        r.check("b", T).unwrap();
        assert!(r.check("c", T).is_err(), "full of busy keys");
        assert_eq!(r.check("c", T + 5), Ok(()), "idle keys dropped");
    }

    #[test]
    fn backoff_counts_attempts_up_front_and_clears_on_success() {
        let b = FailureBackoff::new(3, 60, 3600, 100);
        for _ in 0..3 {
            assert_eq!(b.attempt("alice", T), Ok(()));
        }
        // The third admitted attempt set a 60 s lock; refusals do not extend
        // it.
        for _ in 0..5 {
            assert_eq!(b.attempt("alice", T), Err(Limited { retry_after: 60 }));
        }
        assert_eq!(b.attempt("alice", T + 59), Err(Limited { retry_after: 1 }));
        // Lapsed: one attempt is let through, and sets a doubled lock.
        assert_eq!(b.attempt("alice", T + 60), Ok(()));
        assert_eq!(
            b.attempt("alice", T + 60),
            Err(Limited { retry_after: 120 })
        );
        assert_eq!(b.attempt("alice", T + 180), Ok(()));
        assert_eq!(
            b.attempt("alice", T + 180),
            Err(Limited { retry_after: 240 })
        );
        // Capped.
        let mut t = T + 180;
        for _ in 0..20 {
            t += 10_000;
            assert_eq!(b.attempt("alice", t), Ok(()));
        }
        assert_eq!(b.attempt("alice", t), Err(Limited { retry_after: 3600 }));
        // A success (here: the admitted attempt succeeded) clears it.
        b.succeed("alice");
        assert_eq!(b.attempt("alice", t), Ok(()));
        assert_eq!(b.attempt("bob", t), Ok(()), "keys are independent");
    }

    #[test]
    fn a_refunded_attempt_does_not_count() {
        let b = FailureBackoff::new(2, 60, 3600, 100);
        assert_eq!(b.attempt("alice", T), Ok(()));
        assert_eq!(b.attempt("alice", T), Ok(())); // sets the lock
        b.refund("alice"); // ... but was never decided
        assert_eq!(b.attempt("alice", T), Ok(()), "lock undone");
        assert!(b.attempt("alice", T).is_err());
        // Refunding everything forgets the key.
        let c = FailureBackoff::new(5, 60, 3600, 100);
        c.attempt("x", T).unwrap();
        c.refund("x");
        assert!(c.lock().is_empty());
    }

    #[test]
    fn concurrent_attempts_cannot_exceed_the_allowance() {
        let b = std::sync::Arc::new(FailureBackoff::new(5, 60, 3600, 100));
        let admitted: usize = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..40)
                .map(|_| {
                    let b = b.clone();
                    scope.spawn(move || usize::from(b.attempt("alice", T).is_ok()))
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).sum()
        });
        assert_eq!(admitted, 5);
    }

    #[test]
    fn backoff_capacity_fails_closed() {
        let b = FailureBackoff::new(1, 60, 3600, 2);
        b.attempt("a", T).unwrap();
        b.attempt("b", T).unwrap();
        // Full of locked keys: an untracked key is refused (retry soon).
        assert_eq!(b.attempt("c", T), Err(Limited { retry_after: 1 }));
        // Once those locks lapse they are dropped and "c" is tracked.
        assert_eq!(b.attempt("c", T + 60), Ok(()));
        assert_eq!(b.attempt("c", T + 60), Err(Limited { retry_after: 60 }));
    }
}
