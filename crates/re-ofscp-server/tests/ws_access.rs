//! WebSocket subscriptions through a test authorizer and timeline (spec
//! §7.1 "Channel subscriptions", "Resuming after a disconnect", "Losing
//! access"; security requirement 5).

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::schema;
use common::ws::{Client, Provider, fast_config};
use re_ofscp_server::ws::seams::{AccessFuture, ReplayFuture};
use re_ofscp_server::ws::{
    AccessChange, Replay, SeamError, Seams, Timeline, TopicAccess, TopicAuthorizer, WsConfig,
};
use re_ofscp_types::Actor;
use serde_json::{Value, json};
use tokio::sync::watch;

/// What the test authorizer answers for a topic.
#[derive(Debug, Clone, Copy)]
enum Answer {
    Readable,
    Unreadable,
    Fail,
}

/// An authorizer the test steers: per-topic answers (unknown topics are
/// unreadable), and a pause that holds every check until lifted.
struct Topics {
    answers: Mutex<HashMap<String, Answer>>,
    paused: watch::Sender<bool>,
}

impl Topics {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            answers: Mutex::new(HashMap::new()),
            paused: watch::channel(false).0,
        })
    }

    fn set(&self, topic: &str, answer: Answer) {
        self.answers
            .lock()
            .unwrap()
            .insert(topic.to_owned(), answer);
    }

    fn pause(&self, paused: bool) {
        self.paused.send_replace(paused);
    }
}

impl TopicAuthorizer for Topics {
    fn check<'a>(&'a self, _actor: &'a Actor, topic: &'a str) -> AccessFuture<'a> {
        Box::pin(async move {
            let mut paused = self.paused.subscribe();
            let _ = paused.wait_for(|p| !*p).await;
            match self.answers.lock().unwrap().get(topic) {
                Some(Answer::Readable) => Ok(TopicAccess::Readable),
                Some(Answer::Fail) => Err(SeamError("store down".into())),
                Some(Answer::Unreadable) | None => Ok(TopicAccess::Unreadable),
            }
        })
    }
}

/// A timeline that replays fixed events per topic, and truncates the rest.
#[derive(Default)]
struct Log(HashMap<String, Vec<String>>);

impl Timeline for Log {
    fn replay<'a>(
        &'a self,
        _actor: &'a Actor,
        topic: &'a str,
        _since: &'a str,
    ) -> ReplayFuture<'a> {
        Box::pin(async move {
            Ok(match self.0.get(topic) {
                Some(events) => Replay {
                    events: events.clone(),
                    truncated: false,
                },
                None => Replay {
                    events: Vec::new(),
                    truncated: true,
                },
            })
        })
    }
}

async fn setup_with(config: WsConfig, log: Log) -> (Provider, Arc<Topics>) {
    let topics = Topics::new();
    let seams = Seams {
        topics: topics.clone(),
        timeline: Arc::new(log),
    };
    (Provider::with_alice(config, seams).await, topics)
}

async fn setup() -> (Provider, Arc<Topics>) {
    setup_with(fast_config(), Log::default()).await
}

fn assert_valid(name: &str, v: &Value) {
    common::assert_valid(&schema(&format!("ws/{name}")), v);
}

fn alice() -> Actor {
    Actor::parse_canonical("alice@providera.com").unwrap()
}

fn message(n: u32) -> Value {
    json!({ "n": n })
}

/// Expect the event `message.created` carrying `message(n)`.
async fn expect_message(c: &mut Client, n: u32) {
    let e = c.event().await;
    assert_eq!(
        (&e["type"], &e["data"]),
        (&json!("message.created"), &message(n)),
        "{e}"
    );
    assert!(e.get("correlationId").is_none());
}

const QUIET: Duration = Duration::from_millis(200);

#[tokio::test]
async fn subscribe_delivers_live_events_until_unsubscribed() {
    let (p, topics) = setup().await;
    topics.set("chn_1", Answer::Readable);
    let mut c = p.alice("10.0.0.1").await;
    let id = c
        .command("subscribe", json!({"channels": ["chn_1", "chn_secret"]}))
        .await;
    let ack = c.event().await;
    assert_valid("subscribed.json", &ack);
    assert_eq!(ack["correlationId"], id);
    assert_eq!(ack["data"], json!({"channels": ["chn_1"]}));
    // The unreadable channel is refused like a missing one.
    let e = c.event().await;
    assert_eq!(
        (e["correlationId"].as_str(), &e["data"]["code"]),
        (Some(id.as_str()), &json!("not_found"))
    );
    assert_eq!(e["data"]["details"]["channels"], json!(["chn_secret"]));

    let hub = &p.state.ws;
    hub.publish("chn_1", "message.created", message(1));
    hub.publish("chn_secret", "message.created", message(2));
    expect_message(&mut c, 1).await;
    assert!(c.silent_for(QUIET).await);

    let id = c
        .command("unsubscribe", json!({"channels": ["chn_1"]}))
        .await;
    let ack = c.event().await;
    assert_valid("unsubscribed.json", &ack);
    assert_eq!(ack["correlationId"], id);
    assert_eq!(ack["data"], json!({"channels": ["chn_1"]}));
    hub.publish("chn_1", "message.created", message(3));
    assert!(c.silent_for(QUIET).await);
}

#[tokio::test]
async fn include_filters_event_types() {
    let (p, topics) = setup().await;
    topics.set("chn_1", Answer::Readable);
    let mut c = p.alice("10.0.0.1").await;
    c.command(
        "subscribe",
        json!({"channels": ["chn_1"], "include": ["message.deleted"]}),
    )
    .await;
    assert_eq!(c.event().await["type"], "subscribed");
    let hub = &p.state.ws;
    hub.publish("chn_1", "message.created", message(1));
    hub.publish("chn_1", "message.deleted", json!({"id": "msg_1"}));
    let e = c.event().await;
    assert_eq!(e["type"], "message.deleted");
}

#[tokio::test]
async fn losing_access_ends_the_subscription_with_access_revoked() {
    let (p, topics) = setup().await;
    topics.set("chn_1", Answer::Readable);
    topics.set("chn_2", Answer::Readable);
    let mut c = p.alice("10.0.0.1").await;
    c.command("subscribe", json!({"channels": ["chn_1", "chn_2"]}))
        .await;
    assert_eq!(c.event().await["type"], "subscribed");
    topics.set("chn_1", Answer::Unreadable);
    let hub = &p.state.ws;
    hub.access_changed(AccessChange::Topics(vec!["chn_1".into()]));
    let e = c.event().await;
    assert_valid("unsubscribed.json", &e);
    assert!(e.get("correlationId").is_none(), "unsolicited");
    assert_eq!(
        e["data"],
        json!({"channels": ["chn_1"], "reason": "access_revoked"})
    );
    hub.publish("chn_1", "message.created", message(1));
    hub.publish("chn_2", "message.created", message(2));
    expect_message(&mut c, 2).await;
    assert!(c.silent_for(QUIET).await);
}

/// Events published while access is being re-checked are held: delivered
/// if it holds, never if it was lost.
#[tokio::test]
async fn events_during_a_recheck_are_held_not_leaked() {
    let (p, topics) = setup().await;
    topics.set("chn_1", Answer::Readable);
    let mut c = p.alice("10.0.0.1").await;
    c.command("subscribe", json!({"channels": ["chn_1"]})).await;
    assert_eq!(c.event().await["type"], "subscribed");
    let hub = &p.state.ws;

    topics.pause(true);
    hub.access_changed(AccessChange::Actor(alice()));
    hub.publish("chn_1", "message.created", message(1));
    assert!(c.silent_for(QUIET).await, "held while the check runs");
    topics.pause(false);
    expect_message(&mut c, 1).await;

    topics.pause(true);
    hub.access_changed(AccessChange::All);
    hub.publish("chn_1", "message.created", message(2));
    topics.set("chn_1", Answer::Unreadable);
    topics.pause(false);
    let e = c.event().await;
    assert_eq!(e["type"], "unsubscribed", "{e}");
    assert!(c.silent_for(QUIET).await, "the held event is dropped");
}

#[tokio::test]
async fn a_resume_replays_then_flushes_what_arrived_meanwhile() {
    let replayed = |n: u32| {
        json!({"id": format!("evt_r{n}"), "type": "message.created", "ts": "2026-01-01T12:00:00Z", "data": message(n)})
            .to_string()
    };
    let log = Log(HashMap::from([(
        "chn_1".to_owned(),
        vec![replayed(1), replayed(2)],
    )]));
    let (p, topics) = setup_with(fast_config(), log).await;
    topics.set("chn_1", Answer::Readable);
    topics.set("chn_2", Answer::Readable);
    let mut c = p.alice("10.0.0.1").await;
    topics.pause(true);
    let id = c
        .command(
            "subscribe",
            json!({"channels": ["chn_1", "chn_2"], "since": {"chn_1": "cur_1", "chn_2": "cur_9"}}),
        )
        .await;
    tokio::time::sleep(QUIET).await;
    p.state.ws.publish("chn_1", "message.created", message(3));
    topics.pause(false);
    let ack = c.event().await;
    assert_valid("subscribed.json", &ack);
    assert_eq!(ack["correlationId"], id);
    assert_eq!(
        ack["data"],
        json!({"channels": ["chn_1", "chn_2"], "truncated": ["chn_2"]})
    );
    for n in 1..=3 {
        expect_message(&mut c, n).await;
    }
}

#[tokio::test]
async fn an_authorizer_that_cannot_answer() {
    let (p, topics) = setup().await;
    topics.set("chn_1", Answer::Readable);
    topics.set("chn_down", Answer::Fail);
    let mut c = p.alice("10.0.0.1").await;
    // At subscribe time: refused as unavailable, retryable.
    let id = c
        .command("subscribe", json!({"channels": ["chn_1", "chn_down"]}))
        .await;
    assert_eq!(c.event().await["data"]["channels"], json!(["chn_1"]));
    let e = c.event().await;
    assert_eq!(
        (e["correlationId"].as_str(), &e["data"]["code"]),
        (Some(id.as_str()), &json!("service_unavailable"))
    );
    assert_eq!(e["data"]["details"]["channels"], json!(["chn_down"]));
    // At a re-check: retried, then the connection fails closed.
    topics.set("chn_1", Answer::Fail);
    p.state.ws.access_changed(AccessChange::All);
    p.state.ws.publish("chn_1", "message.created", message(1));
    let (code, events) = c.closed().await;
    assert_eq!(code, 1011);
    assert!(events.is_empty(), "nothing delivered: {events:?}");
}

#[tokio::test]
async fn the_subscription_cap_applies() {
    let (p, topics) = setup().await;
    let channels: Vec<String> = (0..11).map(|i| format!("chn_{i}")).collect();
    for c in &channels {
        topics.set(c, Answer::Readable);
    }
    let mut c = p.alice("10.0.0.1").await;
    c.command("subscribe", json!({"channels": channels[..10]}))
        .await;
    assert_eq!(c.event().await["type"], "subscribed");
    c.command("subscribe", json!({"channels": [channels[10]]}))
        .await;
    let e = c.event().await;
    assert_eq!(
        (&e["data"]["code"], &e["data"]["status"]),
        (&json!("subscription_limit"), &json!(409))
    );
}

/// Only readable channels count towards the cap (10 here), and a
/// `subscribe` past it subscribes none of them, answered by the one
/// `subscription_limit` error: no `subscribed`, no `not_found` (§7.1
/// *Subscriptions*).
#[tokio::test]
async fn only_readable_channels_count_towards_the_cap() {
    let (p, topics) = setup().await;
    let readable: Vec<String> = (0..12).map(|i| format!("chn_{i}")).collect();
    for c in &readable {
        topics.set(c, Answer::Readable);
    }
    let mut c = p.alice("10.0.0.1").await;
    c.command("subscribe", json!({"channels": readable[..9]}))
        .await;
    assert_eq!(c.event().await["type"], "subscribed");
    // One readable and two unreadable: the one fits.
    let id = c
        .command(
            "subscribe",
            json!({"channels": [readable[9], "chn_x", "chn_y"]}),
        )
        .await;
    let ack = c.event().await;
    assert_eq!(
        (&ack["type"], &ack["data"]["channels"]),
        (&json!("subscribed"), &json!([readable[9]]))
    );
    let e = c.event().await;
    assert_eq!(e["correlationId"], id);
    assert_eq!(e["data"]["details"]["channels"], json!(["chn_x", "chn_y"]));
    // At the cap, a channel already subscribed may be listed again.
    c.command("subscribe", json!({"channels": [readable[0]]}))
        .await;
    assert_eq!(c.event().await["data"]["channels"], json!([readable[0]]));
    // Past it, all or none: neither the readable one, nor a not_found.
    c.command("unsubscribe", json!({"channels": [readable[0]]}))
        .await;
    assert_eq!(c.event().await["type"], "unsubscribed");
    let id = c
        .command(
            "subscribe",
            json!({"channels": [readable[10], readable[11], "chn_x"]}),
        )
        .await;
    let e = c.event().await;
    assert_valid("error.json", &e);
    assert_eq!(
        (&e["correlationId"], &e["data"]["code"]),
        (&json!(id), &json!("subscription_limit"))
    );
    let ping = c.command("ping", json!({})).await;
    assert_eq!(
        c.event().await["correlationId"],
        ping,
        "nothing else was sent"
    );
    // Nothing of it was kept: one of them alone still fits.
    c.command("subscribe", json!({"channels": [readable[10]]}))
        .await;
    assert_eq!(c.event().await["data"]["channels"], json!([readable[10]]));
}

#[tokio::test]
async fn the_periodic_recheck_catches_unreported_changes() {
    let mut config = fast_config();
    config.recheck_interval = Duration::from_millis(200);
    let (p, topics) = setup_with(config, Log::default()).await;
    let sweep = tokio::spawn(p.state.ws.clone().recheck_forever());
    topics.set("chn_1", Answer::Readable);
    let mut c = p.alice("10.0.0.1").await;
    c.command("subscribe", json!({"channels": ["chn_1"]})).await;
    assert_eq!(c.event().await["type"], "subscribed");
    topics.set("chn_1", Answer::Unreadable);
    let e = c.event().await;
    assert_eq!(e["data"]["reason"], "access_revoked");
    sweep.abort();
}
