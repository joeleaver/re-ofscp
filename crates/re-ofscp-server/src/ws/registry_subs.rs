//! The subscription side of the [`Registry`]: holding subscriptions while
//! their access is checked, granting or ending them, client unsubscribes,
//! and fan-out of published events (see the parent module for the hold and
//! generation model).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use super::{AccessChange, ConnId, ConnShared, Ended, Held, Hold, OverCap, Registry, Sub, unindex};
use crate::ws::protocol::{Close, close};

impl Registry {
    /// Hold subscriptions of connection `id` to `topics` (distinct; adding
    /// the new ones, with `include`; an existing one keeps its filter until
    /// [`Registry::grant`] replaces it), pending their access checks: per
    /// topic, its hold, or `None` when the connection is gone. Finish with
    /// [`Registry::grant`] and [`Registry::end`].
    ///
    /// The subscription cap counts only readable channels (§7.1), so
    /// [`Registry::grant`] applies it after the checks, all or none. Only
    /// when `topics` names more channels than the whole cap is the answer
    /// known before any check (lost-conn/ofscp#29, in review): nothing is
    /// held and [`OverCap`] is returned. A list no longer than the cap is
    /// held and checked even if it is longer than the room left, since its
    /// readable channels may fit. This also bounds what one `subscribe`
    /// may hold to the cap.
    pub fn hold_new(
        &self,
        id: ConnId,
        topics: &[String],
        include: Option<Arc<HashSet<String>>>,
    ) -> Option<Result<Vec<Hold>, OverCap>> {
        let mut s = self.lock();
        let s = &mut *s;
        let conn = s.conns.get_mut(&id)?;
        if topics.len() > self.limits.max_subscriptions {
            return Some(Err(OverCap));
        }
        let mut fresh = Vec::with_capacity(topics.len());
        for topic in topics {
            match conn.subs.get_mut(topic) {
                Some(sub) => {
                    sub.holds += 1;
                    fresh.push(Hold {
                        fresh: sub.pending,
                        generation: sub.generation,
                    });
                }
                None => {
                    let generation = s.next_generation;
                    s.next_generation += 1;
                    conn.subs.insert(
                        topic.clone(),
                        Sub {
                            include: include.clone(),
                            holds: 1,
                            held: Vec::new(),
                            generation,
                            pending: true,
                        },
                    );
                    s.by_topic.entry(topic.clone()).or_default().insert(id);
                    fresh.push(Hold {
                        fresh: true,
                        generation,
                    });
                }
            }
        }
        Some(Ok(fresh))
    }

    /// Hold every subscription `change` concerns for a re-check.
    pub fn hold_matching(&self, change: &AccessChange) -> Vec<Held> {
        let mut s = self.lock();
        let s = &mut *s;
        let ids: Vec<ConnId> = match change {
            AccessChange::Actor(a) => s
                .by_actor
                .get(a)
                .map(|ids| ids.iter().copied().collect())
                .unwrap_or_default(),
            AccessChange::Topics(topics) => {
                let mut ids: Vec<ConnId> = topics
                    .iter()
                    .filter_map(|t| s.by_topic.get(t))
                    .flatten()
                    .copied()
                    .collect();
                ids.sort_unstable();
                ids.dedup();
                ids
            }
            AccessChange::All => s.conns.keys().copied().collect(),
        };
        let mut held = Vec::new();
        for id in ids {
            let Some(conn) = s.conns.get_mut(&id) else {
                continue;
            };
            let Some(actor) = conn.actor.clone() else {
                continue;
            };
            for (topic, sub) in &mut conn.subs {
                if let AccessChange::Topics(topics) = change
                    && !topics.contains(topic)
                {
                    continue;
                }
                sub.holds += 1;
                held.push(Held {
                    conn: id,
                    actor: actor.clone(),
                    topic: topic.clone(),
                    generation: sub.generation,
                });
            }
        }
        held
    }

    /// One access check of `topic` (of `generation`) on connection `id`
    /// passed: release its hold, delivering what was kept once no check is
    /// left.
    pub fn release(&self, id: ConnId, topic: &str, generation: u64) {
        let mut s = self.lock();
        let Some(conn) = s.conns.get_mut(&id) else {
            return;
        };
        if let Some(sub) = conn.subs.get_mut(topic)
            && sub.generation == generation
        {
            Self::release_sub(&conn.shared, sub);
        }
    }

    fn release_sub(shared: &ConnShared, sub: &mut Sub) {
        sub.holds = sub.holds.saturating_sub(1);
        if sub.holds == 0 {
            for text in sub.held.drain(..) {
                shared.deliver(text);
            }
        }
    }

    /// A `subscribe` on connection `id` granted `topics` (each with the
    /// generation it held): of those that still exist, under the lock,
    /// deliver what `announce` makes of them (the `subscribed` ack and any
    /// replay), then release their holds. So a subscription ended while
    /// it was checked is never acknowledged, and nothing published on a
    /// granted one reaches the client before its ack. Returns the topics
    /// acknowledged.
    ///
    /// All or none against the subscription cap (§7.1 *Subscriptions*):
    /// if the connection's acknowledged subscriptions plus the new ones
    /// among `topics` would pass it, the new ones are ended, the holds on
    /// the others released, nothing is announced, and [`OverCap`] is
    /// returned. `topics` are the readable ones, so only they count.
    ///
    /// Granted, each subscription takes `include` as its filter from the
    /// ack on (what it kept while held passed its old one). Refused, an
    /// existing one keeps its old filter: the `subscribe` changed nothing.
    pub fn grant(
        &self,
        id: ConnId,
        topics: &[(String, u64)],
        include: Option<Arc<HashSet<String>>>,
        announce: impl FnOnce(&[String]) -> Vec<Arc<str>>,
    ) -> Result<Vec<String>, OverCap> {
        let mut s = self.lock();
        let s = &mut *s;
        let Some(conn) = s.conns.get_mut(&id) else {
            return Ok(Vec::new());
        };
        let live: Vec<String> = topics
            .iter()
            .filter(|(t, g)| conn.subs.get(t).is_some_and(|sub| sub.generation == *g))
            .map(|(t, _)| t.clone())
            .collect();
        let pending =
            |subs: &HashMap<String, Sub>, t: &String| subs.get(t).is_some_and(|s| s.pending);
        let new = live.iter().filter(|t| pending(&conn.subs, t)).count();
        let acked = conn.subs.values().filter(|sub| !sub.pending).count();
        if acked + new > self.limits.max_subscriptions {
            for topic in &live {
                if pending(&conn.subs, topic) {
                    conn.subs.remove(topic);
                    unindex(&mut s.by_topic, topic, id);
                } else if let Some(sub) = conn.subs.get_mut(topic) {
                    Self::release_sub(&conn.shared, sub);
                }
            }
            return Err(OverCap);
        }
        if live.is_empty() {
            return Ok(live);
        }
        for text in announce(&live) {
            conn.shared.deliver(text);
        }
        for topic in &live {
            if let Some(sub) = conn.subs.get_mut(topic) {
                sub.pending = false;
                sub.include.clone_from(&include);
                Self::release_sub(&conn.shared, sub);
            }
        }
        Ok(live)
    }

    /// End the subscription of connection `id` to `topic`, if it is still
    /// of `generation`, and drop what it kept.
    pub fn end(&self, id: ConnId, topic: &str, generation: u64) -> Ended {
        let mut s = self.lock();
        let Some(conn) = s.conns.get_mut(&id) else {
            return Ended::Missing;
        };
        let pending = match conn.subs.get(topic) {
            Some(sub) if sub.generation == generation => sub.pending,
            _ => return Ended::Missing,
        };
        conn.subs.remove(topic);
        unindex(&mut s.by_topic, topic, id);
        if pending {
            Ended::Pending
        } else {
            Ended::Active
        }
    }

    /// Drop the subscription of connection `id` to `topic`, and what it
    /// kept, whatever its generation (the client asked). Returns whether
    /// there was one.
    pub fn unsubscribe(&self, id: ConnId, topic: &str) -> bool {
        let mut s = self.lock();
        let Some(conn) = s.conns.get_mut(&id) else {
            return false;
        };
        if conn.subs.remove(topic).is_none() {
            return false;
        }
        unindex(&mut s.by_topic, topic, id);
        true
    }

    /// Fan out an event of type `kind` on `topic` to its subscribers whose
    /// `include` admits it.
    pub fn publish(&self, topic: &str, kind: &str, text: &Arc<str>) {
        let mut s = self.lock();
        let s = &mut *s;
        let Some(ids) = s.by_topic.get(topic) else {
            return;
        };
        for id in ids {
            let Some(conn) = s.conns.get_mut(id) else {
                continue;
            };
            let Some(sub) = conn.subs.get_mut(topic) else {
                continue;
            };
            if sub.include.as_ref().is_some_and(|inc| !inc.contains(kind)) {
                continue;
            }
            if sub.holds == 0 {
                conn.shared.deliver(text.clone());
            } else if sub.held.len() < self.limits.held_max {
                sub.held.push(text.clone());
            } else {
                conn.shared
                    .close(Close::abandon(close::TRY_AGAIN, "too many events held"));
            }
        }
    }
}
