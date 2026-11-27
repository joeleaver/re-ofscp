//! A provider serving `/api/ws` on a real socket, and a WebSocket client
//! for it (tests/ws*.rs).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::SigningKey;
use futures_util::{SinkExt as _, StreamExt as _};
use re_ofscp_server::federation::{Rule, Snapshot};
use re_ofscp_server::replay::NoLedger;
use re_ofscp_server::signing::Clock as _;
use re_ofscp_server::signing::canonical::{sign, ws_canonical_string};
use re_ofscp_server::timefmt::rfc3339;
use re_ofscp_server::ws::{Limits, Seams, WsConfig};
use re_ofscp_server::{AppState, AppStateBuilder, Config, router};
use re_ofscp_types::Authority;
use re_ofscp_types::federation::{FederationMode, RuleList, RuleScope};
use serde_json::{Value, json};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use super::harness::{SIGNED_AT, SettableClock, alice_keys, key};

/// Timings short enough for tests. The auth timeout stays generous: a
/// test may do slow work (compiling schemas) between the challenge and its
/// answer, under a loaded parallel run.
pub fn fast_config() -> WsConfig {
    WsConfig {
        auth_timeout: Duration::from_secs(5),
        verify_timeout: Duration::from_secs(5),
        ping_interval: Duration::from_secs(30),
        idle_timeout: Duration::from_secs(30),
        lease_tick: Duration::from_millis(50),
        recheck_interval: Duration::from_secs(3600),
        max_message_bytes: 64 * 1024,
        max_preauth_bytes: 8 * 1024,
        command_burst: 40,
        commands_per_sec: 20,
        shutdown_grace: Duration::from_secs(2),
        limits: Limits {
            max_connections: 100,
            per_client: 32,
            per_actor: 16,
            per_remote_group: 100,
            max_subscriptions: 10,
            outbound_queue: 64,
            held_max: 64,
        },
    }
}

/// Serve `app` on a loopback port (with peer addresses, as `main` does).
pub async fn serve(app: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    addr
}

/// What the client read next.
#[derive(Debug, Clone, PartialEq)]
pub enum Got {
    /// A server event.
    Event(Value),
    /// The close frame: code and reason.
    Closed(u16, String),
}

/// A WebSocket client.
pub struct Client {
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    next_id: u64,
}

/// How long a test waits for the next frame.
pub const WAIT: Duration = Duration::from_secs(5);

impl Client {
    /// Connect to `/api/ws` at `addr`, as client address `ip`.
    pub async fn connect(addr: SocketAddr, ip: &str) -> Self {
        Self::try_connect(addr, ip).await.unwrap()
    }

    /// Connect, or the HTTP status the upgrade was refused with.
    pub async fn try_connect(addr: SocketAddr, ip: &str) -> Result<Self, u16> {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-test-ip", ip.parse().unwrap());
        Self::try_connect_with(addr, &headers).await
    }

    /// Connect sending `headers` on the upgrade request too (they replace
    /// any the client would set, `Host` included), or the HTTP status the
    /// upgrade was refused with.
    pub async fn try_connect_with(
        addr: SocketAddr,
        headers: &axum::http::HeaderMap,
    ) -> Result<Self, u16> {
        let mut req = format!("ws://{addr}/api/ws").into_client_request().unwrap();
        for (name, value) in headers {
            req.headers_mut().insert(name, value.clone());
        }
        match tokio_tungstenite::connect_async(req).await {
            Ok((ws, _)) => Ok(Self { ws, next_id: 1 }),
            Err(tokio_tungstenite::tungstenite::Error::Http(res)) => Err(res.status().as_u16()),
            Err(e) => panic!("connect failed: {e}"),
        }
    }

    /// The next frame, skipping server `ping` events (answered).
    pub async fn next(&mut self) -> Got {
        loop {
            match self.next_raw().await {
                Got::Event(e) if e["type"] == "ping" => self.pong(&e).await,
                got => return got,
            }
        }
    }

    /// Answer the server's `ping` event.
    pub async fn pong(&mut self, ping: &Value) {
        let id = self.fresh_id();
        let pong = json!({"id": id, "type": "pong", "correlationId": ping["id"], "data": {}});
        self.send_raw(&pong.to_string()).await;
    }

    /// The next frame, as received.
    pub async fn next_raw(&mut self) -> Got {
        loop {
            let msg = tokio::time::timeout(WAIT, self.ws.next())
                .await
                .expect("timed out waiting for a frame");
            match msg {
                Some(Ok(Message::Text(t))) => {
                    return Got::Event(serde_json::from_str(t.as_str()).unwrap());
                }
                Some(Ok(Message::Close(frame))) => {
                    let (code, reason) = frame
                        .map(|f| (u16::from(f.code), f.reason.as_str().to_owned()))
                        .unwrap_or((1005, String::new()));
                    return Got::Closed(code, reason);
                }
                Some(Ok(_)) => {}
                Some(Err(e)) => panic!("read failed: {e}"),
                None => panic!("connection ended without a close frame"),
            }
        }
    }

    /// The next event; panics on a close.
    pub async fn event(&mut self) -> Value {
        match self.next().await {
            Got::Event(e) => e,
            Got::Closed(code, reason) => panic!("closed {code} {reason}"),
        }
    }

    /// The close code, after any events (returned with it).
    pub async fn closed(&mut self) -> (u16, Vec<Value>) {
        let mut events = Vec::new();
        loop {
            match self.next().await {
                Got::Event(e) => events.push(e),
                Got::Closed(code, _) => return (code, events),
            }
        }
    }

    /// Whether nothing arrives within `wait`.
    pub async fn silent_for(&mut self, wait: Duration) -> bool {
        tokio::time::timeout(wait, self.ws.next()).await.is_err()
    }

    /// Every event that arrives until none has for `wait`.
    pub async fn events_for(&mut self, wait: Duration) -> Vec<Value> {
        let mut got = Vec::new();
        while let Ok(e) = tokio::time::timeout(wait, self.event()).await {
            got.push(e);
        }
        got
    }

    /// A fresh command id.
    pub fn fresh_id(&mut self) -> String {
        self.next_id += 1;
        format!("cli_{}", self.next_id)
    }

    /// Send a text frame as is.
    pub async fn send_raw(&mut self, text: &str) {
        self.ws.send(Message::Text(text.into())).await.unwrap();
    }

    /// Send a binary frame.
    pub async fn send_binary(&mut self, bytes: &[u8]) {
        self.ws
            .send(Message::Binary(bytes.to_vec().into()))
            .await
            .unwrap();
    }

    /// Send a command; returns its id.
    pub async fn command(&mut self, kind: &str, data: Value) -> String {
        let id = self.fresh_id();
        let cmd = json!({"id": id, "type": kind, "ts": "2026-01-01T12:00:00Z", "data": data});
        self.send_raw(&cmd.to_string()).await;
        id
    }

    /// Read the challenge and answer it as `actor` with `key` (`key_id`),
    /// signing at `now` for authority `authority`. Returns the authenticate
    /// command sent.
    pub async fn answer_challenge(
        &mut self,
        authority: &str,
        actor: &str,
        key_id: &str,
        key: &SigningKey,
        now: i64,
    ) -> Value {
        let challenge = self.event().await;
        assert_eq!(challenge["type"], "auth.challenge", "{challenge}");
        let nonce = challenge["data"]["nonce"].as_str().unwrap();
        let timestamp = rfc3339(now);
        let canonical = ws_canonical_string(authority, nonce, &timestamp)
            .expect("challenge components have no line break");
        let cmd = json!({
            "id": self.fresh_id(),
            "type": "authenticate",
            "ts": timestamp,
            "data": {
                "actor": actor,
                "keyId": key_id,
                "timestamp": timestamp,
                "signature": sign(key, &canonical),
            },
        });
        self.send_raw(&cmd.to_string()).await;
        cmd
    }

    /// [`Client::answer_challenge`] for `providera.com`, expecting
    /// `authenticated`.
    pub async fn authenticate(&mut self, actor: &str, key_id: &str, key: &SigningKey, now: i64) {
        self.answer_challenge("providera.com", actor, key_id, key, now)
            .await;
        let ok = self.event().await;
        assert_eq!(ok["type"], "authenticated", "{ok}");
        assert_eq!(ok["data"]["actor"], actor);
    }
}

/// A challenge nonce's entropy in bits, as base64url.
pub fn nonce_bits(nonce: &str) -> usize {
    URL_SAFE_NO_PAD.decode(nonce).unwrap().len() * 8
}

/// A provider for `providera.com` serving on a loopback port, past its
/// replay warm-up, with no database.
pub struct Provider {
    /// Where it listens.
    pub addr: SocketAddr,
    /// Its state.
    pub state: AppState,
    /// Its clock (starts at [`SIGNED_AT`]).
    pub clock: Arc<SettableClock>,
}

impl Provider {
    /// Start one: `build` finishes the builder (keys, seams, outbound).
    pub async fn start(
        allow_hosts: Option<String>,
        config: WsConfig,
        build: impl FnOnce(AppStateBuilder) -> AppStateBuilder,
    ) -> Self {
        Self::started_ago(301, allow_hosts, config, build).await
    }

    /// As [`Provider::start`], its replay store started `secs` before
    /// `SIGNED_AT` (under 301: still in its restart warm-up, §4.5).
    pub async fn started_ago(
        secs: i64,
        allow_hosts: Option<String>,
        config: WsConfig,
        build: impl FnOnce(AppStateBuilder) -> AppStateBuilder,
    ) -> Self {
        let cfg = Config::from_lookup(|k| match k {
            "DOMAIN" => Some("providera.com".into()),
            "PROVIDER_SIGNING_KEY" => Some(super::PROVIDER_SIGNING_KEY.into()),
            // No database: these tests never touch the account store.
            "RHYPEDB_ADDR" => Some("127.0.0.1:9".into()),
            "CLIENT_IP_HEADER" => Some("x-test-ip".into()),
            "OUTBOUND_ALLOW_HOSTS" => allow_hosts.clone(),
            _ => None,
        })
        .unwrap();
        let clock = SettableClock::at(SIGNED_AT - time::Duration::seconds(secs));
        let builder = AppState::builder(cfg)
            .ledger(Arc::new(NoLedger))
            .clock(clock.clone())
            .ws_config(config);
        let state = build(builder).build().unwrap();
        clock.set(SIGNED_AT);
        let addr = serve(router(state.clone())).await;
        Self { addr, state, clock }
    }

    /// One whose only keys are alice's (the spec vector key, `dk_abc123xyz`).
    pub async fn with_alice(config: WsConfig, seams: Seams) -> Self {
        Self::start(None, config, |b| {
            b.keys(Arc::new(alice_keys())).ws_seams(seams)
        })
        .await
    }

    /// Now on its clock (unix seconds).
    pub fn now(&self) -> i64 {
        self.clock.now().unix_timestamp()
    }

    /// Move its clock by `secs`.
    pub fn advance(&self, secs: i64) {
        self.clock
            .set(time::OffsetDateTime::from_unix_timestamp(self.now() + secs).unwrap());
    }

    /// A client connected from `ip`.
    pub async fn client(&self, ip: &str) -> Client {
        Client::connect(self.addr, ip).await
    }

    /// A client authenticated as alice.
    pub async fn alice(&self, ip: &str) -> Client {
        let mut c = self.client(ip).await;
        c.authenticate("alice@providera.com", "dk_abc123xyz", &key(), self.now())
            .await;
        c
    }
}

/// A denylist policy denying `provider`.
pub fn denying(provider: &Authority) -> Snapshot {
    let mut s = Snapshot {
        mode: FederationMode::Denylist,
        ..Snapshot::default()
    };
    s.deny.insert(Rule {
        id: "r1".to_owned(),
        list: RuleList::Deny,
        scope: RuleScope::Authority,
        value: provider.to_string(),
        note: String::new(),
        created_by: "owner".to_owned(),
        created_at: 0,
    });
    s
}
