//! Rate limiting for unauthenticated endpoints (spec §4.1.5).
//!
//! * [`RateLimiter`]: a token bucket per key (e.g. per client address):
//!   `burst` requests at once, refilled at `per_minute`.
//! * [`FailureBackoff`]: progressive lockout per key (e.g. per handle):
//!   each attempt counts as a failure *before* it is checked (so concurrent
//!   attempts cannot all slip in ahead of the first recorded failure); past
//!   `free` of them the key is locked for a doubling interval, capped; a
//!   success clears it.
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

    /// Begin an attempt for `key` at `now`: refused if the key is locked;
    /// otherwise counted as a failure up front, and refused if that pushes
    /// it past the allowance. Call [`FailureBackoff::succeed`] if the attempt
    /// then succeeds.
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
        if f.count > self.free {
            let exp = (f.count - self.free - 1).min(30);
            let secs = self
                .base_secs
                .saturating_mul(1i64 << exp)
                .min(self.max_secs);
            f.locked_until = now + secs;
            return Err(Limited {
                retry_after: u64::try_from(secs).unwrap_or(1).max(1),
            });
        }
        Ok(())
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
        // The fourth attempt is refused without being tried, and locks.
        assert_eq!(b.attempt("alice", T), Err(Limited { retry_after: 60 }));
        assert_eq!(b.attempt("alice", T), Err(Limited { retry_after: 60 }));
        // After the lock, each further attempt doubles it.
        assert_eq!(
            b.attempt("alice", T + 60),
            Err(Limited { retry_after: 120 })
        );
        assert_eq!(
            b.attempt("alice", T + 180),
            Err(Limited { retry_after: 240 })
        );
        for i in 0..20 {
            let _ = b.attempt("alice", T + 10_000 * (i + 1));
        }
        let later = T + 10_000 * 21;
        assert_eq!(
            b.attempt("alice", later),
            Err(Limited { retry_after: 3600 })
        );
        b.succeed("alice");
        assert_eq!(b.attempt("alice", later), Ok(()));
        assert_eq!(b.attempt("bob", later), Ok(()), "keys are independent");
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
        let b = FailureBackoff::new(0, 60, 3600, 2);
        let _ = b.attempt("a", T);
        let _ = b.attempt("b", T);
        // Full of locked keys: an untracked key is refused (retry soon).
        assert_eq!(b.attempt("c", T), Err(Limited { retry_after: 1 }));
        // Once those locks lapse they are dropped and "c" is tracked (and,
        // with no free attempts, locked by its own attempt).
        assert_eq!(b.attempt("c", T + 60), Err(Limited { retry_after: 60 }));
    }
}
