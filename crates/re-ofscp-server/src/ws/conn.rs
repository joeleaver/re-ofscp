//! One WebSocket connection, from the upgrade to its close.
//!
//! A connection is two halves. The *writer* sends what is queued for the
//! client, in order, and the close frame once a close is requested
//! (flushing what was queued before it, so an `error` reaches the client
//! ahead of the close it explains). The *reader* runs the handshake and
//! then the authenticated loop: heartbeat, idle timeout, the command rate
//! limit, re-confirming a remote key ([`super::lease`]), the federation
//! policy for a remote actor (`4001` once it denies the actor's provider,
//! §7.1, §8.5), and dispatch.
//! Subscription commands run in order on a worker of their own, so a slow
//! access check never stalls the heartbeat.
//!
//! Anything that ends a connection does so by requesting a close on its
//! [`ConnShared`]; both halves stop on it.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{CloseFrame, Message, WebSocket};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt as _, StreamExt as _};
use serde_json::json;
use tokio::sync::mpsc;
use tokio::time::Instant;

use super::Hub;
use super::commands::{self, Session};
use super::handshake::Handshake;
use super::lease::{Lease, Outcome, Step};
use super::message_commands::MESSAGE_COMMANDS;
use super::protocol::{self, Close, Command, ErrorEvent as _, STANDARD_COMMANDS, WsError, close};
use super::registry::{ConnId, ConnShared};
use crate::signing::{Reconfirmed, Requester, WsVerified};

/// Longest one write to the client may take; a client that does not read
/// is closed rather than holding the connection.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Longest the writer spends flushing and closing once a close is
/// requested.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// A connection that passed the upgrade.
pub struct Accepted {
    /// The provider's hub.
    pub hub: Arc<Hub>,
    /// Its id in the registry.
    pub id: ConnId,
    /// Its shared side.
    pub shared: Arc<ConnShared>,
    /// Its outbound queue.
    pub events: mpsc::Receiver<Arc<str>>,
    /// Whom its remote key fetches are charged to.
    pub requester: Requester,
    /// The socket.
    pub socket: WebSocket,
}

/// Run a connection to its end, then forget it.
pub async fn run(conn: Accepted) {
    let Accepted {
        hub,
        id,
        shared,
        events,
        requester,
        socket,
    } = conn;
    let (sink, mut stream) = socket.split();
    let writer = tokio::spawn(write_loop(sink, shared.clone(), events));
    let handshake = Handshake {
        hub: &hub,
        id,
        shared: &shared,
        requester: &requester,
    };
    if let Some(verified) = handshake.run(&mut stream).await {
        let reader = Reader {
            hub: &hub,
            id,
            shared: &shared,
            requester: &requester,
        };
        reader.run(&mut stream, verified).await;
    }
    // Whatever ended the reader, the writer stops on a close request.
    shared.close(Close::new(close::NORMAL, "connection ended"));
    if let Err(e) = writer.await {
        tracing::error!(conn = %id, error = %e, "WebSocket writer failed");
    }
    let ended = shared.closing().unwrap_or(Close::new(close::NORMAL, ""));
    tracing::info!(conn = %id, code = ended.code, reason = ended.reason, "WebSocket closed");
    hub.registry.remove(id);
}

/// The close for a failed read: `1009` for a message over the size limit,
/// `1002` for anything else the transport rejected.
pub(super) fn read_error_close(e: axum::Error) -> Close {
    let inner = e.into_inner();
    match inner.downcast_ref::<tungstenite::Error>() {
        Some(tungstenite::Error::Capacity(_)) => Close::new(close::TOO_BIG, "message too big"),
        _ => Close::new(close::PROTOCOL, "protocol error"),
    }
}

/// Send what is queued, in order, until a close is requested; then flush
/// what was queued before it and send the close frame.
async fn write_loop(
    mut sink: SplitSink<WebSocket, Message>,
    shared: Arc<ConnShared>,
    mut events: mpsc::Receiver<Arc<str>>,
) {
    let requested = loop {
        tokio::select! {
            biased;
            c = shared.closed() => break c,
            next = events.recv() => {
                let Some(text) = next else { break shared.closed().await };
                let sent = tokio::time::timeout(WRITE_TIMEOUT, sink.send(Message::Text(text.as_ref().into()))).await;
                if !matches!(sent, Ok(Ok(()))) {
                    shared.close(Close::abandon(close::TRY_AGAIN, "client is not reading"));
                    return;
                }
            }
        }
    };
    let finish = async {
        // A slow consumer is closed without the backlog it could not keep
        // up with.
        if requested.flush {
            while let Ok(text) = events.try_recv() {
                sink.send(Message::Text(text.as_ref().into())).await?;
            }
        }
        let frame = CloseFrame {
            code: requested.code,
            reason: requested.reason.into(),
        };
        sink.send(Message::Close(Some(frame))).await
    };
    // The client may already be gone; nothing more to do either way.
    let _ = tokio::time::timeout(CLOSE_TIMEOUT, finish).await;
}

/// A command rate limit: a token bucket of `burst` refilled at `rate` per
/// second. A client that keeps sending past it, ignoring the errors, is
/// closed with `1008`.
struct Bucket {
    tokens: f64,
    burst: f64,
    rate: f64,
    at: Instant,
    overflow: u32,
}

impl Bucket {
    fn new(burst: u32, rate: u32, now: Instant) -> Self {
        Self {
            tokens: f64::from(burst),
            burst: f64::from(burst),
            rate: f64::from(rate),
            at: now,
            overflow: 0,
        }
    }

    /// Take a token at `now`; `false` if there is none.
    fn take(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.at).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
        self.at = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            self.overflow = 0;
            true
        } else {
            self.overflow += 1;
            false
        }
    }

    /// Whether the client has ignored a burst's worth of refusals.
    fn abused(&self) -> bool {
        f64::from(self.overflow) > self.burst
    }
}

/// A re-confirmation under way.
type Pending = Pin<Box<dyn Future<Output = Reconfirmed> + Send>>;

/// The authenticated half of a connection's reader.
struct Reader<'a> {
    hub: &'a Arc<Hub>,
    id: ConnId,
    shared: &'a Arc<ConnShared>,
    requester: &'a Requester,
}

impl Reader<'_> {
    async fn run(&self, stream: &mut SplitStream<WebSocket>, verified: WsVerified) {
        let hub = self.hub;
        let config = hub.config;
        let (commands_tx, commands_rx) =
            mpsc::channel::<Command>(usize::try_from(config.command_burst).unwrap_or(64).max(1));
        let worker = tokio::spawn(commands::run(
            Session {
                hub: hub.clone(),
                id: self.id,
                actor: verified.actor.clone(),
                shared: self.shared.clone(),
            },
            commands_rx,
        ));
        let mut lease = Lease::new(verified.lifetime, hub.now());
        let verified = Arc::new(verified);
        let start = Instant::now();
        let mut ping = tokio::time::interval_at(start + config.ping_interval, config.ping_interval);
        // When to poll the lease next: when it is due, but at least every
        // `lease_tick`, so a clock that jumps (or a test clock) is noticed.
        let lease_wake = |lease: &Lease| {
            lease.due_in(hub.now()).map(|secs| {
                let due = Duration::from_secs(u64::try_from(secs).unwrap_or(0));
                Instant::now() + due.min(config.lease_tick)
            })
        };
        let mut lease_at = lease_wake(&lease);
        let mut bucket = Bucket::new(config.command_burst, config.commands_per_sec, start);
        let mut last_seen = start;
        let mut pending: Option<Pending> = None;
        // A remote actor's provider, watched for a federation denial (one
        // already in force resolves at once).
        let remote =
            (!verified.actor.is_local_to(&hub.local)).then(|| verified.actor.domain().clone());
        let mut policy = hub.verifier.policy().watch();
        loop {
            tokio::select! {
                biased;
                _ = self.shared.closed() => break,
                found = async {
                    match pending.as_mut() {
                        Some(p) => p.await,
                        None => std::future::pending().await,
                    }
                } => {
                    pending = None;
                    let outcome = lease.settle(&found, hub.now());
                    lease_at = lease_wake(&lease);
                    match outcome {
                        Outcome::Keep => {}
                        Outcome::Revoked => self.close(close::REVOKED, "credentials revoked"),
                        Outcome::Expired => self.close(close::AUTH_FAILED, "key could not be re-confirmed"),
                    }
                }
                () = async {
                    match &remote {
                        Some(provider) => policy.until_denied(provider).await,
                        None => std::future::pending().await,
                    }
                } => {
                    tracing::info!(conn = %self.id, actor = %verified.actor, "federation denied; closing");
                    self.close(close::AUTH_FAILED, "federation with your provider is denied");
                }
                () = tokio::time::sleep_until(last_seen + config.idle_timeout) => {
                    self.close(close::NORMAL, "heartbeat timed out");
                }
                _ = ping.tick() => {
                    self.send(protocol::event("ping", None, json!({}), hub.now()));
                }
                () = async {
                    match lease_at {
                        Some(at) => tokio::time::sleep_until(at).await,
                        None => std::future::pending().await,
                    }
                } => match lease.poll(hub.now()) {
                    Step::Idle => lease_at = lease_wake(&lease),
                    Step::Expire => {
                        lease_at = None;
                        self.close(close::AUTH_FAILED, "key could not be re-confirmed");
                    }
                    Step::Reconfirm(held) => {
                        lease_at = lease_wake(&lease);
                        let (hub, verified, requester) = (hub.clone(), verified.clone(), self.requester.clone());
                        pending = Some(Box::pin(async move {
                            hub.verifier.reconfirm(&verified, held, &requester).await
                        }));
                    }
                },
                frame = stream.next() => {
                    last_seen = Instant::now();
                    match frame {
                        Some(Ok(Message::Text(text))) => {
                            if !bucket.take(last_seen) {
                                self.refuse_rate(&text, &bucket);
                                continue;
                            }
                            self.dispatch(text.as_str(), &commands_tx);
                        }
                        Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                        Some(Ok(Message::Binary(_))) => {
                            self.close(close::UNSUPPORTED, "binary messages are not supported");
                        }
                        Some(Ok(Message::Close(_))) | None => {
                            self.close(close::NORMAL, "client closed");
                        }
                        Some(Err(e)) => self.shared.close(read_error_close(e)),
                    }
                }
            }
        }
        worker.abort();
    }

    fn send(&self, text: String) {
        self.shared.deliver(text.into());
    }

    fn close(&self, code: u16, reason: &'static str) {
        self.shared.close(Close::new(code, reason));
    }

    fn error(&self, correlation: Option<&str>, e: &WsError) {
        self.send(e.to_event(correlation, self.hub.now()));
    }

    /// Answer a command over the rate limit, or close an abusive client.
    fn refuse_rate(&self, text: &str, bucket: &Bucket) {
        if bucket.abused() {
            self.close(close::POLICY, "command rate exceeded");
            return;
        }
        let id = protocol::parse_command(text).ok().map(|c| c.id);
        let e = WsError::too_many_requests("too many commands; slow down", 1);
        self.error(id.as_deref(), &e);
    }

    /// Handle one text message of an authenticated connection.
    fn dispatch(&self, text: &str, commands: &mpsc::Sender<Command>) {
        let cmd = match protocol::parse_command(text) {
            Ok(cmd) => cmd,
            Err(m) => {
                self.error(m.id.as_deref(), &WsError::bad_request(m.why));
                return;
            }
        };
        if cmd.lacks_object_data() {
            let e = WsError::bad_request(format!("{} needs data, an object", cmd.kind));
            self.error(Some(&cmd.id), &e);
            return;
        }
        match cmd.kind.as_str() {
            "ping" => {
                let now = self.hub.now();
                self.send(protocol::event("pong", Some(&cmd.id), json!({}), now));
            }
            "pong" => {}
            "authenticate" => {
                let e = WsError::bad_request("this connection is already authenticated");
                self.error(Some(&cmd.id), &e);
            }
            kind if kind == "subscribe"
                || kind == "unsubscribe"
                || (MESSAGE_COMMANDS.contains(&kind) && self.hub.messages().is_some()) =>
            {
                if let Err(mpsc::error::TrySendError::Full(cmd)) = commands.try_send(cmd) {
                    let e = WsError::too_many_requests("too many commands in progress", 1);
                    self.error(Some(&cmd.id), &e);
                }
            }
            kind if STANDARD_COMMANDS.contains(&kind) => {
                let e = WsError::bad_request(format!("{kind} is not supported by this provider"));
                self.error(Some(&cmd.id), &e);
            }
            // §2.3: unknown types are ignored.
            kind => tracing::debug!(conn = %self.id, kind, "ignoring unknown command type"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bucket_refills_and_flags_abuse() {
        let t = Instant::now();
        let mut b = Bucket::new(2, 1, t);
        assert!(b.take(t) && b.take(t));
        assert!(!b.take(t), "burst spent");
        assert!(b.take(t + Duration::from_secs(1)), "one token a second");
        for _ in 0..2 {
            assert!(!b.take(t + Duration::from_secs(1)));
        }
        assert!(!b.abused(), "two refusals within a burst of two");
        assert!(!b.take(t + Duration::from_secs(1)));
        assert!(b.abused());
    }
}
