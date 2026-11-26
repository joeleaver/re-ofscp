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
//! tell a private channel from a missing one
//! (docs/decisions/0008-websocket.md).

use std::collections::HashSet;
use std::sync::Arc;

use re_ofscp_types::Actor;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use tokio::sync::mpsc;

use super::Hub;
use super::protocol::{self, Inbound, MAX_ID_LEN, WsError};
use super::registry::{ConnId, ConnShared};
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
pub async fn run(session: Session, mut commands: mpsc::Receiver<Inbound>) {
    while let Some(cmd) = commands.recv().await {
        match cmd.kind.as_str() {
            "subscribe" => session.subscribe(&cmd).await,
            "unsubscribe" => session.unsubscribe(&cmd),
            _ => {}
        }
    }
}

/// `subscribe` data (`ws/subscribe.json`).
#[derive(Debug, Deserialize)]
struct SubscribeData {
    channels: Vec<String>,
    #[serde(default)]
    include: Option<Vec<String>>,
    #[serde(default)]
    since: Option<Map<String, Value>>,
}

/// `unsubscribe` data (`ws/unsubscribe.json`).
#[derive(Debug, Deserialize)]
struct UnsubscribeData {
    channels: Vec<String>,
}

/// The topics of a command, deduplicated in order, or why they are not
/// acceptable.
fn topics(channels: Vec<String>, cap: usize) -> Result<Vec<String>, WsError> {
    if channels.is_empty() {
        return Err(WsError::bad_request("channels must not be empty"));
    }
    if channels.len() > cap {
        return Err(WsError::subscription_limit(format!(
            "at most {cap} channels per connection"
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

    async fn subscribe(&self, cmd: &Inbound) {
        let hub = &self.hub;
        let parsed = serde_json::from_value::<SubscribeData>(cmd.data.clone())
            .map_err(|_| WsError::bad_request("subscribe needs channels, an array of channel ids"))
            .and_then(|d| {
                let t = topics(d.channels, hub.registry.limits().max_subscriptions)?;
                Ok((t, d.include, d.since.unwrap_or_default()))
            });
        let (topics, include, since) = match parsed {
            Ok(p) => p,
            Err(e) => return self.error(&cmd.id, &e),
        };
        let include = include.map(|kinds| Arc::new(kinds.into_iter().collect::<HashSet<_>>()));
        let Some(fresh) = hub.registry.hold_new(self.id, &topics, include) else {
            let cap = hub.registry.limits().max_subscriptions;
            let e = WsError::subscription_limit(format!("at most {cap} channels per connection"));
            return self.error(&cmd.id, &e);
        };
        let mut granted = Vec::new();
        let mut truncated = Vec::new();
        let mut replays = Vec::new();
        let mut refused = Vec::new();
        let mut revoked = Vec::new();
        let mut unavailable = Vec::new();
        for (topic, is_new) in topics.iter().zip(fresh) {
            let cursor = since.get(topic).and_then(Value::as_str);
            match self.decide(topic, cursor).await {
                Verdict::Granted {
                    replay,
                    truncated: cut,
                } => {
                    granted.push(topic.clone());
                    if cut {
                        truncated.push(topic.clone());
                    }
                    replays.push(replay);
                }
                // An existing subscription the actor can no longer read
                // ends as access lost, however it was found out.
                Verdict::Refused if !is_new => {
                    hub.registry.unsubscribe(self.id, topic);
                    revoked.push(topic.clone());
                }
                Verdict::Refused => {
                    hub.registry.unsubscribe(self.id, topic);
                    refused.push(topic.clone());
                }
                Verdict::Unavailable if is_new => {
                    hub.registry.unsubscribe(self.id, topic);
                    unavailable.push(topic.clone());
                }
                // The existing grant stands; the periodic re-check will
                // check it again.
                Verdict::Unavailable => hub.registry.release(self.id, topic),
            }
        }
        let now = hub.now();
        if !granted.is_empty() {
            let mut data = json!({ "channels": granted });
            if !truncated.is_empty() {
                data["truncated"] = json!(truncated);
            }
            self.send(protocol::event("subscribed", Some(&cmd.id), data, now));
            for text in replays.into_iter().flatten() {
                self.send(text);
            }
            for topic in &granted {
                hub.registry.release(self.id, topic);
            }
        }
        if !revoked.is_empty() {
            let data = json!({ "channels": revoked, "reason": "access_revoked" });
            self.send(protocol::event("unsubscribed", None, data, now));
        }
        if !refused.is_empty() {
            let e = WsError::not_found("no such channel, or it cannot be read")
                .with_details(json!({ "channels": refused }));
            self.error(&cmd.id, &e);
        }
        if !unavailable.is_empty() {
            let e = WsError::service_unavailable("access could not be checked; retry shortly", 5)
                .with_details(json!({ "channels": unavailable, "retryAfter": 5 }));
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
    fn unsubscribe(&self, cmd: &Inbound) {
        let hub = &self.hub;
        let parsed = serde_json::from_value::<UnsubscribeData>(cmd.data.clone())
            .map_err(|_| {
                WsError::bad_request("unsubscribe needs channels, an array of channel ids")
            })
            .and_then(|d| topics(d.channels, hub.registry.limits().max_subscriptions));
        let topics = match parsed {
            Ok(t) => t,
            Err(e) => return self.error(&cmd.id, &e),
        };
        for topic in &topics {
            hub.registry.unsubscribe(self.id, topic);
        }
        let data = json!({ "channels": topics });
        self.send(protocol::event(
            "unsubscribed",
            Some(&cmd.id),
            data,
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
            "subscription_limit"
        );
        assert_eq!(
            topics(vec![String::new()], 5).unwrap_err().code,
            "bad_request"
        );
    }
}
