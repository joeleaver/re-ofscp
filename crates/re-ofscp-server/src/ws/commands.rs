//! The subscription commands of an authenticated connection (spec §7.1
//! "Channel subscriptions", "Resuming after a disconnect"), run in order on
//! the connection's command worker.
//!
//! `subscribe` holds the requested topics first ([`super::registry`]), so
//! events published while access is checked are kept, not lost and not
//! leaked. Then, per topic: the authorizer decides; a readable topic with a
//! resume cursor is replayed from the timeline. The reply is a `subscribed`
//! ack for the granted topics (with `truncated` for resumes that could not
//! be replayed), the replayed events, and then the live events kept
//! meanwhile. Topics that are not readable, or do not exist, are refused
//! together in one `not_found` error naming them, so a subscribe cannot
//! tell a private channel from a missing one. The subscription cap counts
//! only the readable channels, all or none: past it, nothing is subscribed
//! and the one answer is `subscription_limit` (§7.1 *Subscriptions*,
//! docs/decisions/0010-websocket.md).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use super::wire::{Subscribe, Subscribed, Unsubscribe, Unsubscribed};
use re_ofscp_types::Actor;
use serde_json::json;
use tokio::sync::mpsc;

use super::Hub;
use super::protocol::{self, ACCESS_REVOKED, Command, ErrorEvent as _, MAX_ID_LEN, WsError};
use super::registry::{ConnId, ConnShared, Ended};
use super::seams::TopicAccess;

/// An authenticated connection, as its commands see it.
pub struct Session {
    /// The provider's hub.
    pub hub: Arc<Hub>,
    /// The connection.
    pub id: ConnId,
    /// Its actor.
    pub actor: Actor,
    /// Its shared side.
    pub shared: Arc<ConnShared>,
}

/// Run `commands` in order until the connection ends.
pub async fn run(session: Session, mut commands: mpsc::Receiver<Command>) {
    while let Some(cmd) = commands.recv().await {
        match cmd.kind.as_str() {
            "subscribe" => session.subscribe(&cmd).await,
            "unsubscribe" => session.unsubscribe(&cmd),
            _ => {}
        }
    }
}

/// The topics of a command, deduplicated in order, or why they are not
/// acceptable. `max` bounds how many one command may list; it is not the
/// subscription cap, which counts only readable channels (applied by
/// [`super::registry::Registry::grant`]).
fn topics(channels: Vec<String>, max: usize) -> Result<Vec<String>, WsError> {
    if channels.is_empty() {
        return Err(WsError::bad_request("channels must not be empty"));
    }
    if channels.len() > max {
        return Err(WsError::bad_request(format!(
            "at most {max} channels per command"
        )));
    }
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(channels.len());
    for c in channels {
        if c.is_empty() || c.len() > MAX_ID_LEN {
            return Err(WsError::bad_request("channel ids must be 1 to 256 bytes"));
        }
        if seen.insert(c.clone()) {
            out.push(c);
        }
    }
    Ok(out)
}

/// What became of one topic of a `subscribe`.
enum Verdict {
    /// Granted, with what to replay and whether the resume was truncated.
    Granted {
        replay: Vec<String>,
        truncated: bool,
    },
    /// Not readable (or no such topic).
    Refused,
    /// The authorizer could not answer.
    Unavailable,
}

impl Session {
    fn send(&self, text: String) {
        self.shared.deliver(text.into());
    }

    fn error(&self, correlation: &str, e: &WsError) {
        self.send(e.to_event(Some(correlation), self.hub.now()));
    }

    async fn subscribe(&self, cmd: &Command) {
        let hub = &self.hub;
        let parsed = serde_json::from_value::<Subscribe>(cmd.data.clone())
            .map_err(|_| {
                WsError::bad_request(
                    "subscribe needs channels, an array of channel ids (and string cursors in since)",
                )
            })
            .and_then(|d| {
                let t = topics(d.channels, hub.registry.limits().max_channels_per_command)?;
                Ok((t, d.include, d.since.unwrap_or_default()))
            });
        let (topics, include, since) = match parsed {
            Ok(p) => p,
            Err(e) => return self.error(&cmd.id, &e),
        };
        let include = include.map(|kinds| Arc::new(kinds.into_iter().collect::<HashSet<_>>()));
        // The connection is gone.
        let Some(holds) = hub.registry.hold_new(self.id, &topics, include.clone()) else {
            return;
        };
        let mut granted = Vec::new();
        let mut truncated = HashSet::new();
        let mut replays: HashMap<String, Vec<String>> = HashMap::new();
        let mut refused = Vec::new();
        let mut revoked = Vec::new();
        let mut unavailable = Vec::new();
        for (topic, hold) in topics.iter().zip(holds) {
            let g = hold.generation;
            match self
                .decide(topic, since.get(topic).map(String::as_str))
                .await
            {
                Verdict::Granted {
                    replay,
                    truncated: cut,
                } => {
                    granted.push((topic.clone(), g));
                    if cut {
                        truncated.insert(topic.clone());
                    }
                    replays.insert(topic.clone(), replay);
                }
                // A subscription the client had and can no longer read ends
                // as access lost. Ended already by a re-check (which sent
                // its own `unsubscribed`), the command is still answered:
                // every topic gets a reply carrying its correlationId.
                Verdict::Refused => match hub.registry.end(self.id, topic, g) {
                    Ended::Active => revoked.push(topic.clone()),
                    Ended::Pending | Ended::Missing => refused.push(topic.clone()),
                },
                Verdict::Unavailable if hold.fresh => {
                    hub.registry.end(self.id, topic, g);
                    unavailable.push(topic.clone());
                }
                // The existing grant stands; the periodic re-check will
                // check it again.
                Verdict::Unavailable => hub.registry.release(self.id, topic, g),
            }
        }
        let now = hub.now();
        let granted_now = hub.registry.grant(self.id, &granted, include, |live| {
            let ack = Subscribed {
                channels: live.to_vec(),
                truncated: live
                    .iter()
                    .filter(|t| truncated.contains(*t))
                    .cloned()
                    .collect(),
            };
            let mut texts =
                vec![protocol::event("subscribed", Some(&cmd.id), ack.to_value(), now).into()];
            for topic in live {
                texts.extend(replays.remove(topic).into_iter().flatten().map(Arc::from));
            }
            texts
        });
        if !revoked.is_empty() {
            let data = Unsubscribed {
                channels: revoked,
                reason: Some(ACCESS_REVOKED.to_owned()),
            };
            self.send(protocol::event("unsubscribed", None, data.to_value(), now));
        }
        // Past the cap: nothing subscribed, and the one answer is the limit
        // (no `not_found` for the refused channels, §7.1).
        let Ok(acked) = granted_now else {
            let cap = hub.registry.limits().max_subscriptions;
            let e = WsError::subscription_limit(format!("at most {cap} channels per connection"));
            return self.error(&cmd.id, &e);
        };
        // Granted, but ended by a re-check before it could be
        // acknowledged: refused like any other unreadable channel, so the
        // command still gets its answer (an existing one was also told
        // `unsubscribed access_revoked` by the re-check).
        refused.extend(
            granted
                .into_iter()
                .map(|(t, _)| t)
                .filter(|t| !acked.contains(t)),
        );
        if !refused.is_empty() {
            let e = WsError::not_found("no such channel, or it cannot be read")
                .with_detail("channels", json!(refused));
            self.error(&cmd.id, &e);
        }
        if !unavailable.is_empty() {
            let e = WsError::service_unavailable("access could not be checked; retry shortly", 5)
                .with_detail("channels", json!(unavailable));
            self.error(&cmd.id, &e);
        }
    }

    /// Decide one topic of a `subscribe`, resuming after `cursor` if given.
    async fn decide(&self, topic: &str, cursor: Option<&str>) -> Verdict {
        let seams = &self.hub.seams;
        match seams.topics.check(&self.actor, topic).await {
            Ok(TopicAccess::Readable) => {}
            Ok(TopicAccess::Unreadable) => return Verdict::Refused,
            Err(e) => {
                tracing::warn!(conn = %self.id, topic, error = %e, "access check failed at subscribe");
                return Verdict::Unavailable;
            }
        }
        let Some(cursor) = cursor else {
            return Verdict::Granted {
                replay: Vec::new(),
                truncated: false,
            };
        };
        match seams.timeline.replay(&self.actor, topic, cursor).await {
            Ok(r) => Verdict::Granted {
                replay: r.events,
                truncated: r.truncated,
            },
            // Nothing replayed: the client backfills through REST history.
            Err(e) => {
                tracing::warn!(conn = %self.id, topic, error = %e, "timeline replay failed");
                Verdict::Granted {
                    replay: Vec::new(),
                    truncated: true,
                }
            }
        }
    }

    /// `unsubscribe`: drop the subscriptions and acknowledge with an
    /// `unsubscribed` (no `reason`: the client asked) naming every channel
    /// requested, subscribed or not, so it is idempotent.
    fn unsubscribe(&self, cmd: &Command) {
        let hub = &self.hub;
        let parsed = serde_json::from_value::<Unsubscribe>(cmd.data.clone())
            .map_err(|_| {
                WsError::bad_request("unsubscribe needs channels, an array of channel ids")
            })
            .and_then(|d| topics(d.channels, hub.registry.limits().max_channels_per_command));
        let topics = match parsed {
            Ok(t) => t,
            Err(e) => return self.error(&cmd.id, &e),
        };
        for topic in &topics {
            hub.registry.unsubscribe(self.id, topic);
        }
        let data = Unsubscribed {
            channels: topics,
            reason: None,
        };
        self.send(protocol::event(
            "unsubscribed",
            Some(&cmd.id),
            data.to_value(),
            hub.now(),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topics_are_deduplicated_and_bounded() {
        let t = topics(vec!["a".into(), "b".into(), "a".into()], 5).unwrap();
        assert_eq!(t, ["a", "b"]);
        assert_eq!(topics(vec![], 5).unwrap_err().code, "bad_request");
        assert_eq!(
            topics(vec!["a".into(); 6], 5).unwrap_err().code,
            "bad_request"
        );
        assert_eq!(
            topics(vec![String::new()], 5).unwrap_err().code,
            "bad_request"
        );
    }
}
