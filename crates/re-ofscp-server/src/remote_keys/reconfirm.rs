//! Re-confirming the key of a live WebSocket connection from a remote
//! actor (spec §7.1 "For a connection from a remote actor",
//! lost-conn/ofscp#20).
//!
//! The connection has relied on its key until some `cache_until` (or, for
//! an answer that could not be cached, only as of the fetch). Before that
//! runs out it asks again, and the answer is one of:
//!
//! * the key is still published (a completed fetch, or a cache entry a
//!   completed fetch refreshed past what the connection holds): rely on it
//!   until the new expiry;
//! * a completed fetch shows it gone (a valid keys response without it, or
//!   a `404`, or the id now naming another key): close with `4003`;
//! * nothing completed (failure, outbound refusal, a limit, or the
//!   federation policy denying the provider, which the connection's own
//!   policy watch acts on): unconfirmed;
//!   the connection lives on what it holds and closes with `4001` when
//!   that runs out.
//!
//! A re-confirmation is an expiry-driven fetch, not a key miss: it is not
//! subject to the miss re-fetch interval, and a known source's re-fetch is
//! charged to its known budget (docs/decisions/0006). Connections of the
//! same actor share one fetch (single flight), and one that finds the cache
//! already refreshed past its own expiry fetches nothing.

use std::sync::Arc;

use ed25519_dalek::VerifyingKey;

use super::fetch::{Fetched, Source};
use super::{Blocked, Inner, lifetime, policy_refusal, wait};
use crate::signing::{KeyError, Lifetime, Reconfirmed, Requester, classify};

impl Inner {
    /// Re-confirm `key` of `source` under `key_id`, held for `held`.
    pub(super) async fn reconfirm(
        self: &Arc<Self>,
        source: Source,
        key_id: &str,
        key: &VerifyingKey,
        held: Lifetime,
        requester: &Requester,
    ) -> Reconfirmed {
        // A provider the policy denies is never asked; the connection's
        // policy watch closes it with `4001` (§7.1, §8.5).
        if let Some(refusal) = policy_refusal(self.client.policy().decide(source.host()), &source) {
            return Reconfirmed::Unconfirmed(refusal.to_string());
        }
        let flight = {
            let now = self.now();
            let mut tables = self.tables();
            // A fetch completed after the one this connection holds: its
            // cache entry outlives the connection's, and answers for it.
            if let Lifetime::Until(held_until) = held
                && let Some((keys, expires)) = tables.live_entry(&source, now)
                && expires > held_until
            {
                return classify(keys.get(key_id), key, Lifetime::Until(expires));
            }
            match self.begin(&mut tables, &source, false, requester, now) {
                Ok(flight) => flight,
                Err(Blocked::Refused(why)) => return Reconfirmed::Unconfirmed(why),
                Err(Blocked::Policy(refusal)) => {
                    return Reconfirmed::Unconfirmed(refusal.to_string());
                }
                Err(Blocked::Limited { why, .. }) => {
                    return Reconfirmed::Unconfirmed(format!("{why} for {}", source.host()));
                }
            }
        };
        match wait(flight).await {
            Fetched::Keys { keys, expires } => classify(keys.get(key_id), key, lifetime(expires)),
            Fetched::Failed(why) | Fetched::Refused(why) => Reconfirmed::Unconfirmed(why),
            Fetched::Denied(who) => Reconfirmed::Unconfirmed(KeyError::Denied(who).to_string()),
        }
    }
}
