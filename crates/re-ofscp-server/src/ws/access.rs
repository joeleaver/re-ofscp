//! Keeping live connections within what their actors may still do (spec
//! §7.1 "Losing access", §4.7.1, §8; security requirement 5).
//!
//! * [`Hub::access_changed`]: re-check the subscriptions a change
//!   concerns; one no longer readable ends with an unsolicited
//!   `unsubscribed {reason: "access_revoked"}`. The subscriptions are held
//!   while they are re-checked, so nothing published meanwhile reaches a
//!   connection that turns out to have lost access. A re-check acts only
//!   on the subscription generation it checked. An authorizer that
//!   cannot answer is retried; if it still cannot, the connection closes
//!   with `1011` (fail closed), since its access can no longer be vouched
//!   for.
//! * [`Hub::recheck_forever`]: the same for every subscription,
//!   periodically, as a backstop for changes nobody reported.
//! * Key revocation (as a [`RevocationListener`]): close the connections
//!   authenticated with the key, or every key of the account, with `4003`.
//!   It bumps the *access epoch*, so a handshake that was verifying while
//!   it happened checks again once it is registered.
//!
//! The federation policy (§8.5) is not here: each remote actor's
//! connection watches it itself ([`super::conn`]).

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use super::wire::Unsubscribed;
use futures_util::StreamExt as _;
use re_ofscp_types::Actor;

use super::Hub;
use super::protocol::{self, ACCESS_REVOKED, Close, close};
use super::registry::{AccessChange, Ended, Held};
use super::seams::{SeamError, TopicAccess};
use crate::accounts::{Revocation, RevocationListener};
use crate::privacy::Liveness;

/// Re-checks run at once, per change.
const RECHECK_CONCURRENCY: usize = 16;

/// Attempts at one re-check before failing closed, and the wait before
/// each retry.
const RECHECK_BACKOFF: [Duration; 2] = [Duration::from_secs(1), Duration::from_secs(2)];

impl Hub {
    /// The access epoch: it moves whenever a local key or account
    /// revocation is applied.
    pub(super) fn access_epoch(&self) -> u64 {
        self.epoch.load(Ordering::SeqCst)
    }

    fn bump_epoch(&self) {
        self.epoch.fetch_add(1, Ordering::SeqCst);
    }

    /// Effective read access changed for what `change` names (a channel's
    /// tier or `view`, a membership or role, a group-wide setting):
    /// re-check the subscriptions it concerns, in the background.
    pub fn access_changed(self: &Arc<Self>, change: AccessChange) {
        let held = self.registry.hold_matching(&change);
        if held.is_empty() {
            return;
        }
        let hub = self.clone();
        tokio::spawn(async move { hub.recheck(held).await });
    }

    /// Re-check every subscription every `recheck_interval`, forever.
    pub async fn recheck_forever(self: Arc<Self>) {
        let period = self.config.recheck_interval;
        let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
        loop {
            tick.tick().await;
            let held = self.registry.hold_matching(&AccessChange::All);
            self.recheck(held).await;
        }
    }

    /// Re-check `held` subscriptions, releasing or ending each.
    pub(super) async fn recheck(&self, held: Vec<Held>) {
        futures_util::stream::iter(held)
            .for_each_concurrent(RECHECK_CONCURRENCY, |h| async move {
                match self.check_patiently(&h.actor, &h.topic).await {
                    Ok(TopicAccess::Readable) => {
                        self.registry.release(h.conn, &h.topic, h.generation);
                    }
                    Ok(TopicAccess::Unreadable) => self.revoke_topic(&h),
                    // A subscription dropped meanwhile needs nothing.
                    Err(_) if self.registry.end(h.conn, &h.topic, h.generation) == Ended::Missing => {}
                    Err(e) => {
                        tracing::warn!(conn = %h.conn, topic = h.topic, error = %e, "access re-check failed; closing");
                        if let Some(shared) = self.registry.shared(h.conn) {
                            shared.close(Close::new(
                                close::INTERNAL,
                                "access could not be re-checked",
                            ));
                        }
                    }
                }
            })
            .await;
    }

    /// Check access, retrying an authorizer that cannot answer.
    async fn check_patiently(&self, actor: &Actor, topic: &str) -> Result<TopicAccess, SeamError> {
        let mut result = self.seams.topics.check(actor, topic).await;
        for wait in RECHECK_BACKOFF {
            if result.is_ok() {
                break;
            }
            tokio::time::sleep(wait).await;
            result = self.seams.topics.check(actor, topic).await;
        }
        result
    }

    /// End a subscription whose access was lost, telling the client if it
    /// had been acknowledged (an unacknowledged one is refused by the
    /// `subscribe` that made it).
    fn revoke_topic(&self, h: &Held) {
        if self.registry.end(h.conn, &h.topic, h.generation) != Ended::Active {
            return;
        }
        tracing::info!(conn = %h.conn, actor = %h.actor, topic = h.topic, "subscription ended: access revoked");
        if let Some(shared) = self.registry.shared(h.conn) {
            let data = Unsubscribed {
                channels: vec![h.topic.clone()],
                reason: Some(ACCESS_REVOKED.to_owned()),
            };
            shared
                .deliver(protocol::event("unsubscribed", None, data.to_value(), self.now()).into());
        }
    }
}

/// Presence derives online/offline from live connections (§7.5).
impl Liveness for Hub {
    fn is_connected(&self, actor: &Actor) -> bool {
        self.registry.is_connected(actor)
    }
}

impl RevocationListener for Hub {
    fn revoked(&self, r: &Revocation) {
        self.bump_epoch();
        let Ok(actor) = Actor::new(&r.handle, self.local.clone()) else {
            return;
        };
        let n = self.registry.close_actor(
            &actor,
            r.key_id.as_deref(),
            Close::new(close::REVOKED, "credentials revoked"),
        );
        if n > 0 {
            tracing::info!(actor = %actor, connections = n, "closed WebSocket connections: credentials revoked");
        }
    }
}
