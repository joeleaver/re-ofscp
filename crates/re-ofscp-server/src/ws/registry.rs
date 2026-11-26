//! The registry of live connections: connection caps, the subscription
//! index, fan-out, and force-closing.
//!
//! Every connection has a bounded outbound queue. Fan-out never waits: an
//! event that does not fit closes the connection with `1013` (the client
//! did not keep up; it resumes with its cursors, §7.1). Events are queued
//! under the registry lock, so every connection sees one channel's events
//! in the order they were published (§7.1 "Ordering").
//!
//! A subscription is *held* while an access check for it is under way (at
//! subscribe time, and on every re-check, §7.1 "Losing access"): events
//! published meanwhile are kept, not delivered, and are flushed in order
//! once every check passed, or dropped with the subscription if one
//! failed. So no event reaches a connection whose access is in doubt, and
//! none is lost to one whose access holds.
//!
//! Each subscription has a *generation*, fresh whenever it is created. A
//! check acts only on the generation it checked, so a slow re-check of a
//! subscription the client has since dropped and made again cannot
//! release or end the new one.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use re_ofscp_types::{Actor, Authority};
use tokio::sync::{Notify, mpsc};

use super::protocol::{Close, close};
use crate::registrable::registrable_group;

/// A connection's id, unique in this process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnId(pub u64);

impl std::fmt::Display for ConnId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ws{}", self.0)
    }
}

/// A connection's side that other tasks talk to: its outbound queue and
/// its close request.
#[derive(Debug)]
pub struct ConnShared {
    events: mpsc::Sender<Arc<str>>,
    close: Mutex<Option<Close>>,
    wake: Notify,
}

impl ConnShared {
    /// Ask the connection to close with `close`. The first request wins.
    pub fn close(&self, close: Close) {
        let mut slot = self.close.lock().unwrap_or_else(PoisonError::into_inner);
        if slot.is_none() {
            *slot = Some(close);
            drop(slot);
            // Both halves of the connection wait on this.
            self.wake.notify_waiters();
        }
    }

    /// The close requested, if any.
    pub fn closing(&self) -> Option<Close> {
        *self.close.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Resolves once a close has been requested.
    pub async fn closed(&self) -> Close {
        loop {
            // Registered before the check, so a close between the check and
            // the wait is not missed (`notify_waiters` keeps no permit).
            let notified = self.wake.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(c) = self.closing() {
                return c;
            }
            notified.await;
        }
    }

    /// Queue `text` for the client, never waiting. A full queue closes the
    /// connection (`1013`); a closed one (the connection ended) drops it.
    pub fn deliver(&self, text: Arc<str>) {
        if let Err(mpsc::error::TrySendError::Full(_)) = self.events.try_send(text) {
            self.close(Close::abandon(close::TRY_AGAIN, "client is not keeping up"));
        }
    }
}

/// A connection just admitted.
#[derive(Debug)]
pub struct Admitted {
    /// Its id.
    pub id: ConnId,
    /// Its shared side.
    pub shared: Arc<ConnShared>,
    /// Its outbound queue, for its writer.
    pub events: mpsc::Receiver<Arc<str>>,
}

/// Connection and subscription caps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Live connections in all.
    pub max_connections: usize,
    /// Live connections from one client (its rate-limit key), counted from
    /// the upgrade on, so unauthenticated sockets count too.
    pub per_client: usize,
    /// Authenticated connections of one actor.
    pub per_actor: usize,
    /// Authenticated connections of remote actors whose providers share a
    /// registrable domain (ICANN section, as the replay quotas group).
    pub per_remote_group: usize,
    /// Subscriptions on one connection. Only channels the actor can read
    /// count towards it (§7.1 *Subscriptions*), so [`Registry::grant`]
    /// applies it, after the access checks.
    pub max_subscriptions: usize,
    /// Channels one `subscribe` or `unsubscribe` may list, readable or not:
    /// a bound on the work one command causes (an access check each), not
    /// the subscription cap. Over it is `bad_request`.
    pub max_channels_per_command: usize,
    /// Events queued for one connection.
    pub outbound_queue: usize,
    /// Events kept for one held subscription.
    pub held_max: usize,
}

/// Why a connection was not admitted or authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// The provider is shutting down.
    ShuttingDown,
    /// The provider holds its cap of connections.
    Full,
    /// This client holds its cap.
    Client,
    /// This actor holds its cap.
    Actor,
    /// Remote providers under this registrable domain hold their cap.
    Group,
}

/// Whose subscriptions an access change concerns (§7.1 "Losing access").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessChange {
    /// These topics (channels): their tier, `view`, or existence changed.
    Topics(Vec<String>),
    /// This actor: a membership or role changed.
    Actor(Actor),
    /// Everything (a group-wide change, or the periodic sweep).
    All,
}

/// A subscription held for a re-check, to be released or dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    /// The connection.
    pub conn: ConnId,
    /// Its actor.
    pub actor: Actor,
    /// The topic.
    pub topic: String,
    /// The subscription's generation.
    pub generation: u64,
}

/// A subscription [`Registry::hold_new`] held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hold {
    /// It was created by this hold: not acknowledged to the client yet.
    pub fresh: bool,
    /// Its generation.
    pub generation: u64,
}

/// A `subscribe` would take its connection past
/// [`Limits::max_subscriptions`]: [`Registry::grant`] granted none of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverCap;

/// What [`Registry::end`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ended {
    /// No such subscription (of that generation): nothing changed.
    Missing,
    /// It was still waiting for its first grant, so the client never had
    /// it; the `subscribe` that made it reports it.
    Pending,
    /// An acknowledged subscription ended.
    Active,
}

#[derive(Debug)]
struct Sub {
    include: Option<Arc<HashSet<String>>>,
    holds: u32,
    held: Vec<Arc<str>>,
    generation: u64,
    /// Not acknowledged yet: its `subscribe` is still checking it.
    pending: bool,
}

#[derive(Debug)]
struct Conn {
    shared: Arc<ConnShared>,
    client: String,
    actor: Option<Actor>,
    key_id: Option<String>,
    group: Option<String>,
    subs: HashMap<String, Sub>,
}

#[derive(Debug)]
struct State {
    accepting: bool,
    next: u64,
    next_generation: u64,
    conns: HashMap<ConnId, Conn>,
    by_actor: HashMap<Actor, HashSet<ConnId>>,
    by_client: HashMap<String, usize>,
    by_group: HashMap<String, usize>,
    by_topic: HashMap<String, HashSet<ConnId>>,
}

/// The live connections of one provider.
#[derive(Debug)]
pub struct Registry {
    limits: Limits,
    local: Authority,
    state: Mutex<State>,
}

fn decrement(map: &mut HashMap<String, usize>, key: &str) {
    if let Some(n) = map.get_mut(key) {
        *n -= 1;
        if *n == 0 {
            map.remove(key);
        }
    }
}

impl Registry {
    /// An empty registry for the provider `local`.
    pub fn new(limits: Limits, local: Authority) -> Self {
        Self {
            limits,
            local,
            state: Mutex::new(State {
                accepting: true,
                next: 1,
                next_generation: 1,
                conns: HashMap::new(),
                by_actor: HashMap::new(),
                by_client: HashMap::new(),
                by_group: HashMap::new(),
                by_topic: HashMap::new(),
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The caps.
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Admit a new connection from `client` (before the upgrade), or say
    /// why not.
    pub fn admit(&self, client: &str) -> Result<Admitted, Refused> {
        let mut s = self.lock();
        if !s.accepting {
            return Err(Refused::ShuttingDown);
        }
        if s.conns.len() >= self.limits.max_connections {
            return Err(Refused::Full);
        }
        if s.by_client.get(client).copied().unwrap_or(0) >= self.limits.per_client {
            return Err(Refused::Client);
        }
        let id = ConnId(s.next);
        s.next += 1;
        let (tx, rx) = mpsc::channel(self.limits.outbound_queue.max(1));
        let shared = Arc::new(ConnShared {
            events: tx,
            close: Mutex::new(None),
            wake: Notify::new(),
        });
        *s.by_client.entry(client.to_owned()).or_default() += 1;
        s.conns.insert(
            id,
            Conn {
                shared: shared.clone(),
                client: client.to_owned(),
                actor: None,
                key_id: None,
                group: None,
                subs: HashMap::new(),
            },
        );
        Ok(Admitted {
            id,
            shared,
            events: rx,
        })
    }

    /// Record that connection `id` authenticated as `actor` with `key_id`,
    /// unless the actor or its provider's group is at its cap.
    pub fn authenticate(&self, id: ConnId, actor: &Actor, key_id: &str) -> Result<(), Refused> {
        let mut s = self.lock();
        let s = &mut *s;
        let Some(conn) = s.conns.get_mut(&id) else {
            return Err(Refused::ShuttingDown);
        };
        if s.by_actor.get(actor).map_or(0, HashSet::len) >= self.limits.per_actor {
            return Err(Refused::Actor);
        }
        let group =
            (!actor.is_local_to(&self.local)).then(|| registrable_group(actor.domain().as_str()));
        if let Some(g) = &group
            && s.by_group.get(g).copied().unwrap_or(0) >= self.limits.per_remote_group
        {
            return Err(Refused::Group);
        }
        if let Some(g) = &group {
            *s.by_group.entry(g.clone()).or_default() += 1;
        }
        s.by_actor.entry(actor.clone()).or_default().insert(id);
        conn.actor = Some(actor.clone());
        conn.key_id = Some(key_id.to_owned());
        conn.group = group;
        Ok(())
    }

    /// Forget connection `id` and everything indexed under it.
    pub fn remove(&self, id: ConnId) {
        let mut s = self.lock();
        let Some(conn) = s.conns.remove(&id) else {
            return;
        };
        decrement(&mut s.by_client, &conn.client);
        if let Some(g) = &conn.group {
            decrement(&mut s.by_group, g);
        }
        if let Some(actor) = &conn.actor
            && let Some(ids) = s.by_actor.get_mut(actor)
        {
            ids.remove(&id);
            if ids.is_empty() {
                s.by_actor.remove(actor);
            }
        }
        for topic in conn.subs.keys() {
            unindex(&mut s.by_topic, topic, id);
        }
    }

    /// Hold subscriptions of connection `id` to `topics` (adding the new
    /// ones, with `include`; an existing one keeps its filter until
    /// [`Registry::grant`] replaces it), pending their access checks: per
    /// topic, its hold, or `None` when the connection is gone. The subscription cap
    /// is not applied here, since only readable channels count towards it
    /// (§7.1): [`Registry::grant`] applies it. Until then the connection
    /// may hold up to [`Limits::max_channels_per_command`] more. Finish
    /// with [`Registry::grant`] and [`Registry::end`].
    pub fn hold_new(
        &self,
        id: ConnId,
        topics: &[String],
        include: Option<Arc<HashSet<String>>>,
    ) -> Option<Vec<Hold>> {
        let mut s = self.lock();
        let s = &mut *s;
        let conn = s.conns.get_mut(&id)?;
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
        Some(fresh)
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

    /// Whether `actor` has at least one authenticated connection.
    pub fn is_connected(&self, actor: &Actor) -> bool {
        self.lock()
            .by_actor
            .get(actor)
            .is_some_and(|ids| !ids.is_empty())
    }

    /// Queue `text` for every authenticated connection of `actor`.
    pub fn send_to_actor(&self, actor: &Actor, text: &Arc<str>) {
        let s = self.lock();
        for id in s.by_actor.get(actor).into_iter().flatten() {
            if let Some(conn) = s.conns.get(id) {
                conn.shared.deliver(text.clone());
            }
        }
    }

    /// Close the connections of `actor`: those authenticated with `key_id`,
    /// or all of them. Returns how many.
    pub fn close_actor(&self, actor: &Actor, key_id: Option<&str>, close: Close) -> usize {
        let s = self.lock();
        let mut n = 0;
        for id in s.by_actor.get(actor).into_iter().flatten() {
            let Some(conn) = s.conns.get(id) else {
                continue;
            };
            if key_id.is_none_or(|k| conn.key_id.as_deref() == Some(k)) {
                conn.shared.close(close);
                n += 1;
            }
        }
        n
    }

    /// The shared side of connection `id`, if it is live.
    pub fn shared(&self, id: ConnId) -> Option<Arc<ConnShared>> {
        self.lock().conns.get(&id).map(|c| c.shared.clone())
    }

    /// Refuse new connections from now on, and close every live one.
    pub fn close_all(&self, close: Close) {
        let mut s = self.lock();
        s.accepting = false;
        for conn in s.conns.values() {
            conn.shared.close(close);
        }
    }

    /// Live connections.
    pub fn len(&self) -> usize {
        self.lock().conns.len()
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn unindex(by_topic: &mut HashMap<String, HashSet<ConnId>>, topic: &str, id: ConnId) {
    if let Some(ids) = by_topic.get_mut(topic) {
        ids.remove(&id);
        if ids.is_empty() {
            by_topic.remove(topic);
        }
    }
}

#[cfg(test)]
#[path = "registry_tests.rs"]
mod tests;
