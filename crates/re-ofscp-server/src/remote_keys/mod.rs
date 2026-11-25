//! Resolving remote signers' keys (spec §4.6, §8.1; docs/decisions/0006).
//!
//! A remote actor's keys come from its provider's user keys endpoint, a
//! remote provider's from its discovery document, both fetched through the
//! SSRF-safe [`OutboundClient`]. How a fetch's outcome maps to the
//! verifier's answer follows lost-conn/ofscp#19 and #20:
//!
//! * a completed fetch (valid `200`, or a user-keys `404`) is authoritative;
//! * a fetch failure is `503` (`Retry-After: 5`, or until the next re-fetch
//!   is allowed when the failed fetch was itself a re-fetch), and an
//!   outbound refusal `401`, unless an **unexpired** cached key with that id
//!   exists, which is then used;
//! * a fetch stopped by a rate limit or budget ([`budget`]), or because the
//!   target already has its cap of requests in flight, is `503` with the
//!   `Retry-After` of that limit, again unless an unexpired cached key
//!   matches;
//! * a host under a public suffix the PSL does not know is refused like an
//!   outbound refusal (`401`), before any budget is consulted, unless the
//!   operator allowed its name in `OUTBOUND_ALLOW_HOSTS`.
//!
//! Lookups for the same source share one fetch (single flight). Fetches run
//! in their own task, so a lookup that gives up (its request was dropped)
//! does not cancel the fetch others are waiting for.

pub mod budget;
pub mod document;
pub mod fetch;
mod state;

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tokio::sync::watch;

use self::budget::{Budgets, Standing};
use self::fetch::{Fetched, Source};
use self::state::{Flight, MAX_ENTRIES, Tables};
use crate::outbound::{OutboundClient, OutboundError, Reservation};
use crate::registrable::has_unknown_suffix;
use crate::signing::{Clock, KeyError, KeyFuture, KeyResolver, Requester, Resolved, Signer};

pub use self::budget::{CLIENT_BURST, CLIENT_PER_MINUTE, DOMAIN_BURST, DOMAIN_PER_MINUTE};
pub use self::state::REFETCH_INTERVAL_SECS;

/// `Retry-After` after a fetch failure with no cached key to fall back on.
pub const FAILURE_RETRY_SECS: u64 = 5;

/// Remote key resolution. Use as `ProviderKeys`' remote resolver.
pub struct RemoteKeys {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for RemoteKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteKeys").finish_non_exhaustive()
    }
}

struct Inner {
    client: Arc<OutboundClient>,
    clock: Arc<dyn Clock>,
    tables: Mutex<Tables>,
    /// Every fetch is charged to its target and to the client that caused
    /// it, so requests naming random handles or key ids at one domain
    /// cannot make us hammer it, nor one client spend its whole budget.
    budgets: Budgets,
}

/// What to do for a lookup, decided under the lock.
enum Plan {
    Answer(Result<Resolved, KeyError>),
    Wait(Flight),
}

impl RemoteKeys {
    /// Resolve through `client`, timing caches and limits on `clock`.
    pub fn new(client: Arc<OutboundClient>, clock: Arc<dyn Clock>) -> Self {
        Self {
            inner: Arc::new(Inner {
                client,
                clock,
                tables: Mutex::new(Tables::default()),
                budgets: Budgets::default(),
            }),
        }
    }
}

impl KeyResolver for RemoteKeys {
    fn resolve<'a>(
        &'a self,
        signer: &'a Signer,
        key_id: &'a str,
        fresh: bool,
        requester: &'a Requester,
    ) -> KeyFuture<'a> {
        Box::pin(async move {
            let source = Source::of(signer);
            match self.inner.plan(&source, key_id, fresh, requester) {
                Plan::Answer(answer) => answer,
                Plan::Wait(flight) => {
                    let refetch = flight.refetch;
                    let fetched = wait(flight).await;
                    self.inner.settle(&source, key_id, fetched, refetch)
                }
            }
        })
    }
}

impl Inner {
    fn now(&self) -> i64 {
        self.clock.now().unix_timestamp()
    }

    fn tables(&self) -> MutexGuard<'_, Tables> {
        self.tables.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn plan(
        self: &Arc<Self>,
        source: &Source,
        key_id: &str,
        fresh: bool,
        requester: &Requester,
    ) -> Plan {
        let now = self.now();
        let mut tables = self.tables();
        if !fresh && let Some(keys) = tables.live(source, now) {
            return Plan::Answer(Ok(Resolved::cached(keys.get(key_id).copied())));
        }
        // Join a fetch already under way: its answer is as fresh as ours,
        // and joining it costs no budget.
        if let Some(flight) = tables.flights.get(source) {
            return Plan::Wait(flight.clone());
        }
        // A target refused without any lookup (an IP-literal host) costs no
        // fetch and no budget.
        if let Err(e) = self.client.target(source.host(), &source.path()) {
            let why = match e {
                OutboundError::Refused(why) => why,
                other => other.to_string(),
            };
            return Plan::Answer(fallback(&tables, source, key_id, now, || {
                KeyError::Unresolvable(why)
            }));
        }
        // Under a suffix the PSL does not know, every name would be its own
        // target group (and fill the budgets' tables): refused like an
        // outbound refusal, at no cost. Operator-allowed names (dev peers
        // on `localhost` or `*.test`) are exempt.
        let host = source.host();
        if has_unknown_suffix(host.as_str()) && !self.client.allows_host_name(host) {
            return Plan::Answer(fallback(&tables, source, key_id, now, || {
                KeyError::Unresolvable(format!("{host} is not under a known public suffix"))
            }));
        }
        let limited = |retry_after: u64, why: &str| {
            fallback(&tables, source, key_id, now, || KeyError::Unavailable {
                reason: format!("{why} for {}", source.host()),
                retry_after,
            })
        };
        // Every other reason to refuse comes before the budgets, so a
        // lookup refused for it is charged nothing.
        if fresh && let Some(wait) = tables.refetch_wait(source, now) {
            return Plan::Answer(limited(wait, "key re-fetch rate-limited"));
        }
        if tables.flights.len() >= MAX_ENTRIES {
            return Plan::Answer(limited(1, "too many key fetches in flight"));
        }
        // The target's in-flight slot is taken before anything is charged,
        // so a busy target costs no budget and starts no re-fetch interval.
        let reservation = match self.client.reserve(host, &source.path()) {
            Ok(reservation) => reservation,
            Err(OutboundError::Busy(_)) => {
                return Plan::Answer(limited(
                    FAILURE_RETRY_SECS,
                    "too many requests in flight to the target",
                ));
            }
            Err(e) => {
                return Plan::Answer(fallback(&tables, source, key_id, now, || {
                    KeyError::Unresolvable(e.to_string())
                }));
            }
        };
        let standing = if tables.is_known(source) {
            Standing::Known
        } else {
            Standing::FirstTime
        };
        if let Err(over) = self.budgets.charge(source, standing, requester, now) {
            return Plan::Answer(limited(over.retry_after, over.why));
        }
        if fresh {
            tables.note_refetch(source, now);
        }
        let (tx, rx) = watch::channel(None);
        let flight = Flight {
            answer: rx,
            refetch: fresh,
        };
        tables.flights.insert(source.clone(), flight.clone());
        drop(tables);
        tokio::spawn(self.clone().run_flight(source.clone(), reservation, tx));
        Plan::Wait(flight)
    }

    /// Fetch, update the cache, then wake every waiter.
    async fn run_flight(
        self: Arc<Self>,
        source: Source,
        reservation: Reservation,
        tx: watch::Sender<Option<Fetched>>,
    ) {
        // Whatever happens (even a panic), the flight is removed, so later
        // lookups are never stuck waiting on a fetch that will not answer.
        let mut guard = FlightGuard {
            inner: &self,
            source: &source,
            armed: true,
        };
        let fetched = fetch::fetch(&self.client, &source, reservation, || self.now()).await;
        {
            let mut tables = self.tables();
            tables.flights.remove(&source);
            guard.armed = false;
            if let Fetched::Keys { keys, expires } = &fetched {
                let now = self.now();
                tables.store(&source, keys.clone(), *expires, now);
                tables.note_found(&source, !keys.is_empty(), now);
            }
        }
        match &fetched {
            Fetched::Keys { .. } => {}
            Fetched::Failed(why) => {
                tracing::warn!(host = %source.host(), error = %why, "key fetch failed");
            }
            Fetched::Refused(why) => {
                tracing::info!(host = %source.host(), reason = %why, "key fetch refused");
            }
        }
        tx.send_replace(Some(fetched));
    }

    /// The answer for a lookup that waited on a fetch (`refetch`: one that
    /// was a `fresh` re-fetch). A fallback to the cache re-checks expiry
    /// now, not when the lookup began: the entry may have expired meanwhile
    /// (lost-conn/ofscp#20).
    fn settle(
        &self,
        source: &Source,
        key_id: &str,
        fetched: Fetched,
        refetch: bool,
    ) -> Result<Resolved, KeyError> {
        let now = self.now();
        let tables = self.tables();
        match fetched {
            Fetched::Keys { keys, .. } => Ok(Resolved::authoritative(keys.get(key_id).copied())),
            Fetched::Failed(reason) => {
                // A failed re-fetch started the re-fetch interval: retrying
                // sooner would only be refused by it.
                let retry_after = if refetch {
                    FAILURE_RETRY_SECS.max(tables.refetch_wait(source, now).unwrap_or(0))
                } else {
                    FAILURE_RETRY_SECS
                };
                fallback(&tables, source, key_id, now, || KeyError::Unavailable {
                    reason,
                    retry_after,
                })
            }
            Fetched::Refused(why) => {
                fallback(&tables, source, key_id, now, || KeyError::Unresolvable(why))
            }
        }
    }
}

/// An unexpired cached key standing in for a fetch that did not happen or
/// did not complete; otherwise `error`.
fn fallback(
    tables: &Tables,
    source: &Source,
    key_id: &str,
    now: i64,
    error: impl FnOnce() -> KeyError,
) -> Result<Resolved, KeyError> {
    match tables.cached_key(source, key_id, now) {
        Some(key) => Ok(Resolved::cached(Some(key))),
        None => Err(error()),
    }
}

/// The answer of `flight`.
async fn wait(flight: Flight) -> Fetched {
    let mut answer = flight.answer;
    match answer.wait_for(Option::is_some).await {
        Ok(answer) => answer
            .clone()
            .unwrap_or_else(|| Fetched::Failed("key fetch gave no answer".to_owned())),
        Err(_) => Fetched::Failed("key fetch ended without an answer".to_owned()),
    }
}

/// Removes a flight that ends without reaching its normal removal.
struct FlightGuard<'a> {
    inner: &'a Inner,
    source: &'a Source,
    armed: bool,
}

impl Drop for FlightGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.inner.tables().flights.remove(self.source);
        }
    }
}

#[cfg(test)]
mod tests;
