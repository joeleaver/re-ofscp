//! The WebSocket transport (spec §7.1) at `/api/ws`
//! (docs/decisions/0010-websocket.md).
//!
//! * [`protocol`]: the envelope, events, errors and close codes.
//! * [`conn`]: one connection, from the `auth.challenge` to its close.
//! * [`commands`]: the commands of an authenticated connection.
//! * [`registry`]: live connections, caps, subscriptions and fan-out.
//! * [`access`]: re-checking access, revocation, federation policy.
//! * [`lease`]: re-confirming a remote actor's key.
//! * [`seams`]: what other subsystems plug in (channel access, the message
//!   timeline, federation policy).
//!
//! Other subsystems talk to connections through [`Hub`]: they publish
//! events to a topic or an actor, report access changes, and force-close.

pub mod access;
pub mod commands;
pub mod conn;
mod handshake;
pub mod lease;
pub mod protocol;
pub mod registry;
pub mod seams;
pub mod wire;

use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use axum::extract::ws::rejection::WebSocketUpgradeRejection;
use axum::extract::{State, WebSocketUpgrade};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use re_ofscp_types::{Actor, Authority};
use serde_json::Value;

use self::protocol::{Close, close};
pub use self::registry::{AccessChange, Admitted, ConnId, Limits, Refused, Registry};
pub use self::seams::{
    NoTimeline, NoTopics, Replay, SeamError, Timeline, TopicAccess, TopicAuthorizer,
};
use crate::AppState;
use crate::client::{Peer, client_keys_by};
use crate::problem::Problem;
use crate::signing::{Requester, Verifier};

/// Path of the endpoint (§7.1).
pub const PATH: &str = "/api/ws";

/// Timings and limits. The defaults follow §7.1's RECOMMENDED values where
/// it has them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WsConfig {
    /// How long a new connection has to send `authenticate` (§7.1:
    /// RECOMMENDED 10 s). The challenge expires at the same moment.
    pub auth_timeout: Duration,
    /// Longest the provider spends verifying one `authenticate` (a remote
    /// key fetch included) before failing it as unavailable.
    pub verify_timeout: Duration,
    /// How often the provider sends `ping` (§7.1: RECOMMENDED 30 s).
    pub ping_interval: Duration,
    /// How long a connection may stay silent, no `pong` or other traffic,
    /// before it is closed (§7.1: RECOMMENDED 60 s).
    pub idle_timeout: Duration,
    /// Longest a connection waits between checks of its key's lease. It
    /// wakes when the next re-confirmation or `cache_until` is due anyway;
    /// this bounds how late a jump of the clock is noticed.
    pub lease_tick: Duration,
    /// How often every subscription's access is re-checked, as a backstop
    /// to [`Hub::access_changed`].
    pub recheck_interval: Duration,
    /// Largest message accepted, in bytes, enforced by the transport as
    /// the message arrives (so it is also the most buffered for a client
    /// that has not authenticated yet). Larger closes `1009`.
    pub max_message_bytes: usize,
    /// Largest message accepted before authentication, in bytes (an
    /// `authenticate` is well under 1 KiB). Larger closes `1009`.
    pub max_preauth_bytes: usize,
    /// Commands one connection may send in a burst.
    pub command_burst: u32,
    /// Commands per second one connection may sustain.
    pub commands_per_sec: u32,
    /// How long shutdown waits for connections to close.
    pub shutdown_grace: Duration,
    /// Connection and subscription caps.
    pub limits: Limits,
}

impl Default for WsConfig {
    fn default() -> Self {
        Self {
            auth_timeout: Duration::from_secs(10),
            verify_timeout: Duration::from_secs(20),
            ping_interval: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(60),
            lease_tick: Duration::from_secs(5),
            recheck_interval: Duration::from_secs(300),
            max_message_bytes: 64 * 1024,
            max_preauth_bytes: 8 * 1024,
            command_burst: 40,
            commands_per_sec: 20,
            shutdown_grace: Duration::from_secs(5),
            limits: Limits {
                max_connections: 10_000,
                per_client: 32,
                per_actor: 16,
                per_remote_group: 1_000,
                max_subscriptions: 500,
                outbound_queue: 256,
                held_max: 1_024,
            },
        }
    }
}

/// The subsystems a [`Hub`] consults.
#[derive(Clone)]
pub struct Seams {
    /// Channel access.
    pub topics: Arc<dyn TopicAuthorizer>,
    /// Channel timelines.
    pub timeline: Arc<dyn Timeline>,
}

impl Default for Seams {
    fn default() -> Self {
        Self {
            topics: Arc::new(NoTopics),
            timeline: Arc::new(NoTimeline),
        }
    }
}

/// The WebSocket layer of one provider.
pub struct Hub {
    config: WsConfig,
    verifier: Arc<Verifier>,
    client_ip_header: Option<String>,
    local: Authority,
    registry: Registry,
    seams: Seams,
    epoch: AtomicU64,
}

impl std::fmt::Debug for Hub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hub")
            .field("local", &self.local)
            .field("connections", &self.registry.len())
            .finish_non_exhaustive()
    }
}

impl Hub {
    /// A hub for the provider `local`, verifying handshakes with
    /// `verifier` and telling clients apart by `client_ip_header`.
    pub fn new(
        config: WsConfig,
        verifier: Arc<Verifier>,
        client_ip_header: Option<String>,
        local: Authority,
        seams: Seams,
    ) -> Self {
        Self {
            registry: Registry::new(config.limits, local.clone()),
            config,
            verifier,
            client_ip_header,
            local,
            seams,
            epoch: AtomicU64::new(0),
        }
    }

    /// The configuration.
    pub fn config(&self) -> &WsConfig {
        &self.config
    }

    /// The registry of live connections.
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// Now, on the verifier's clock (unix seconds).
    pub fn now(&self) -> i64 {
        self.verifier.now()
    }

    /// Fan out an event of type `kind` with `data` to the subscribers of
    /// `topic` whose `include` admits it. No `correlationId`: no command
    /// of theirs caused it.
    pub fn publish(&self, topic: &str, kind: &str, data: Value) {
        let text: Arc<str> = protocol::event(kind, None, data, self.now()).into();
        self.registry.publish(topic, kind, &text);
    }

    /// Send an event of type `kind` with `data` to every connection of
    /// `actor` (DMs, notifications, read markers).
    pub fn send_to_actor(&self, actor: &Actor, kind: &str, data: Value) {
        let text: Arc<str> = protocol::event(kind, None, data, self.now()).into();
        self.registry.send_to_actor(actor, &text);
    }

    /// Close every connection of `actor` with `4003`: its credentials were
    /// revoked (a guest claimed or merged, §4.8; an account deleted).
    pub fn revoke_actor(&self, actor: &Actor) -> usize {
        self.registry.close_actor(
            actor,
            None,
            Close::new(close::REVOKED, "credentials revoked"),
        )
    }

    /// Stop accepting connections and close every live one with `1001`,
    /// waiting up to the shutdown grace for them to go.
    pub async fn shutdown(&self) {
        self.registry
            .close_all(Close::new(close::GOING_AWAY, "provider shutting down"));
        let deadline = tokio::time::Instant::now() + self.config.shutdown_grace;
        while !self.registry.is_empty() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let left = self.registry.len();
        if left > 0 {
            tracing::warn!(left, "WebSocket connections still open at shutdown");
        }
    }
}

/// `GET /api/ws`: upgrade to a WebSocket (§7.1). The `Origin` is not
/// checked (§3.4): the signed handshake is the access control. Connection
/// caps are applied before the upgrade, so a refused client gets a plain
/// `429` or `503` problem with `Retry-After`.
pub async fn upgrade(
    State(state): State<AppState>,
    peer: Peer,
    headers: HeaderMap,
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Response {
    let ws = match ws {
        Ok(ws) => ws,
        Err(e) => {
            return Problem::bad_request()
                .with_detail(format!("expected a WebSocket upgrade: {e}"))
                .into_response();
        }
    };
    let hub = state.ws.clone();
    let client = client_keys_by(hub.client_ip_header.as_deref(), &headers, &peer);
    let registry::Admitted { id, shared, events } = match hub.registry.admit(&client.key) {
        Ok(admitted) => admitted,
        Err(refused) => return refusal(refused).into_response(),
    };
    let requester = Requester::within(client.key, client.network);
    let limit = hub.config.max_message_bytes;
    ws.max_message_size(limit)
        .max_frame_size(limit)
        .on_failed_upgrade(move |e| tracing::info!(error = %e, "WebSocket upgrade failed"))
        .on_upgrade(move |socket| {
            conn::run(conn::Accepted {
                hub,
                id,
                shared,
                events,
                requester,
                socket,
            })
        })
}

/// The problem for a connection refused before the upgrade.
fn refusal(refused: Refused) -> Problem {
    match refused {
        Refused::ShuttingDown => {
            Problem::service_unavailable(5).with_detail("the provider is shutting down")
        }
        Refused::Full => {
            Problem::service_unavailable(5).with_detail("the provider holds its cap of connections")
        }
        _ => Problem::too_many_requests(30).with_detail("too many WebSocket connections"),
    }
}
