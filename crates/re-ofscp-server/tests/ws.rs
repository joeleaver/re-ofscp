//! The WebSocket transport (spec §7.1): the handshake, heartbeat, limits,
//! dispatch and close codes, over a real socket.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::harness::{FixedClock, alice_keys, key, new_key, send};
use common::ws::{Client, Got, Provider, fast_config, nonce_bits};
use common::{schema, spec_json};
use re_ofscp_server::federation::FederationPolicy;
use re_ofscp_server::replay::{NoLedger, ReplayStore};
use re_ofscp_server::signing::{
    Lifetime, Requester, Verifier, VerifyError, WsAuthenticate, WsVerified,
};
use re_ofscp_server::timefmt::rfc3339;
use re_ofscp_server::ws::{Seams, WsConfig};
use re_ofscp_types::Actor;
use serde_json::{Value, json};

const ALICE: &str = "alice@providera.com";
const KEY_ID: &str = "dk_abc123xyz";

async fn provider() -> Provider {
    Provider::with_alice(fast_config(), Seams::default()).await
}

async fn provider_with(config: WsConfig) -> Provider {
    Provider::with_alice(config, Seams::default()).await
}

fn assert_valid(schema_name: &str, v: &Value) {
    common::assert_valid(&schema(&format!("ws/{schema_name}")), v);
}

/// The spec's vector runs through the handshake checks: its nonce,
/// timestamp and signature verify for alice, and the same use again is a
/// replay.
#[tokio::test]
async fn the_spec_vector_verifies_and_cannot_be_replayed() {
    let v = spec_json("ws-signing-vector.json");
    let sample = spec_json("ws-authenticate.sample.json");
    let at = time::OffsetDateTime::parse(
        v["challenge"]["timestamp"].as_str().unwrap(),
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    let replay = Arc::new(ReplayStore::new(
        common::harness::limits(1000),
        300,
        at.unix_timestamp() - 301,
        "providera.com",
    ));
    let verifier = Verifier::new(
        common::harness::provider_a(),
        300,
        replay,
        Arc::new(NoLedger),
        Arc::new(alice_keys()),
        Arc::new(FederationPolicy::open()),
        Arc::new(FixedClock(at)),
    );
    let d = &sample["data"];
    let auth = WsAuthenticate {
        actor: d["actor"].as_str().unwrap(),
        key_id: d["keyId"].as_str().unwrap(),
        timestamp: d["timestamp"].as_str().unwrap(),
        signature: d["signature"].as_str().unwrap(),
    };
    let nonce = v["challenge"]["challengeNonce"].as_str().unwrap();
    let requester = Requester::new("203.0.113.7");
    let pre = verifier.ws_precheck(&auth, nonce).unwrap();
    let verified = verifier.ws_complete(pre, &requester).await.unwrap();
    assert_eq!(
        verified,
        WsVerified {
            actor: common::harness::alice(),
            key_id: KEY_ID.into(),
            key: key().verifying_key(),
            lifetime: Lifetime::Unbounded,
        }
    );
    assert_eq!(
        verifier.ws_precheck(&auth, nonce).unwrap_err(),
        VerifyError::Replayed
    );
    // A different challenge does not verify the same signature.
    let pre = verifier
        .ws_precheck(&auth, "another-nonce-0123456789")
        .unwrap();
    assert_eq!(
        verifier.ws_complete(pre, &requester).await.unwrap_err(),
        VerifyError::Signature
    );
}

#[tokio::test]
async fn the_handshake_challenges_and_authenticates() {
    let p = provider().await;
    let mut c = p.client("10.0.0.1").await;
    let challenge = c.event().await;
    assert_valid("auth-challenge.json", &challenge);
    assert!(nonce_bits(challenge["data"]["nonce"].as_str().unwrap()) >= 128);
    assert_eq!(challenge["data"]["expiresAt"], rfc3339(p.now() + 5));
    assert_eq!(challenge["ts"], rfc3339(p.now()));

    let nonce = challenge["data"]["nonce"].as_str().unwrap();
    let ts = rfc3339(p.now());
    let canonical =
        re_ofscp_server::signing::canonical::ws_canonical_string("providera.com", nonce, &ts);
    let cmd = json!({"id": "cli_auth", "type": "authenticate", "ts": ts, "data": {
        "actor": ALICE, "keyId": KEY_ID, "timestamp": ts,
        "signature": re_ofscp_server::signing::canonical::sign(&key(), &canonical),
    }});
    assert_valid("authenticate.json", &cmd);
    c.send_raw(&cmd.to_string()).await;
    let ok = c.event().await;
    assert_valid("authenticated.json", &ok);
    assert_eq!(ok["correlationId"], "cli_auth");
    assert_eq!(ok["data"]["actor"], ALICE);

    // Authenticated: a second authenticate is refused, not obeyed.
    let id = c.command("authenticate", cmd["data"].clone()).await;
    let e = c.event().await;
    assert_valid("error.json", &e);
    assert_eq!(
        (e["correlationId"].as_str(), &e["data"]["code"]),
        (Some(id.as_str()), &json!("bad_request"))
    );
}

/// The expiry is the auth timeout after the challenge: on a clock that
/// does not move, `expiresAt` equals `ts` plus the timeout in whole seconds.
#[tokio::test]
async fn the_challenge_expires_with_the_auth_timeout() {
    let mut config = fast_config();
    config.auth_timeout = Duration::from_secs(2);
    let p = provider_with(config).await;
    let mut c = p.client("10.0.0.1").await;
    let challenge = c.event().await;
    assert_eq!(challenge["data"]["expiresAt"], rfc3339(p.now() + 2));
}

#[tokio::test]
async fn failed_handshakes_close_4001() {
    let p = provider().await;
    let now = p.now();

    // Wrong key.
    let mut c = p.client("10.0.0.1").await;
    c.answer_challenge("providera.com", ALICE, KEY_ID, &new_key(), now)
        .await;
    let (code, events) = c.closed().await;
    assert_eq!(code, 4001);
    assert_valid("error.json", &events[0]);
    assert_eq!(events[0]["data"]["code"], "unauthorized");
    assert_eq!(events[0]["data"]["status"], 401);

    // Signed for another provider.
    let mut c = p.client("10.0.0.1").await;
    c.answer_challenge("providerb.com", ALICE, KEY_ID, &key(), now)
        .await;
    assert_eq!(c.closed().await.0, 4001);

    // Outside the clock skew.
    let mut c = p.client("10.0.0.1").await;
    c.answer_challenge("providera.com", ALICE, KEY_ID, &key(), now - 301)
        .await;
    let (code, events) = c.closed().await;
    assert_eq!(
        (code, &events[0]["data"]["code"]),
        (4001, &json!("unauthorized"))
    );

    // A non-canonical actor.
    let mut c = p.client("10.0.0.1").await;
    c.answer_challenge("providera.com", "Alice@ProviderA.com", KEY_ID, &key(), now)
        .await;
    assert_eq!(c.closed().await.0, 4001);

    // An authenticate missing its fields.
    let mut c = p.client("10.0.0.1").await;
    c.event().await;
    c.command("authenticate", json!({"actor": ALICE})).await;
    let (code, events) = c.closed().await;
    assert_eq!(
        (code, &events[0]["data"]["code"]),
        (4001, &json!("bad_request"))
    );
}

/// An `authenticate` captured from one connection is worthless on another:
/// it signs that connection's challenge.
#[tokio::test]
async fn a_captured_authenticate_does_not_open_another_connection() {
    let p = provider().await;
    let mut first = p.client("10.0.0.1").await;
    let captured = first
        .answer_challenge("providera.com", ALICE, KEY_ID, &key(), p.now())
        .await;
    assert_eq!(first.event().await["type"], "authenticated");
    let mut second = p.client("10.0.0.2").await;
    second.event().await;
    second.send_raw(&captured.to_string()).await;
    let (code, events) = second.closed().await;
    assert_eq!(code, 4001);
    assert_eq!(events[0]["data"]["code"], "unauthorized");
}

#[tokio::test]
async fn anything_before_authenticate_closes_4001() {
    let p = provider().await;
    for frame in [
        json!({"id": "cli_1", "type": "subscribe", "data": {"channels": ["chn_1"]}}).to_string(),
        json!({"id": "cli_1", "type": "ping", "data": {}}).to_string(),
        "not json".to_owned(),
    ] {
        let mut c = p.client("10.0.0.1").await;
        c.event().await;
        c.send_raw(&frame).await;
        let (code, events) = c.closed().await;
        assert_eq!(code, 4001, "{frame}");
        assert_valid("error.json", &events[0]);
    }
}

#[tokio::test]
async fn no_authenticate_in_time_closes_4001() {
    let mut config = fast_config();
    config.auth_timeout = Duration::from_millis(300);
    let p = provider_with(config).await;
    let mut c = p.client("10.0.0.1").await;
    assert_eq!(c.event().await["type"], "auth.challenge");
    let (code, events) = c.closed().await;
    assert_eq!(code, 4001);
    assert_eq!(events[0]["data"]["code"], "unauthorized");
}

#[tokio::test]
async fn the_provider_pings_and_closes_silent_clients() {
    let mut config = fast_config();
    config.ping_interval = Duration::from_millis(200);
    config.idle_timeout = Duration::from_millis(700);
    let p = provider_with(config).await;
    let mut c = p.alice("10.0.0.1").await;
    // Answered pings keep it open past the idle timeout.
    let start = tokio::time::Instant::now();
    let mut pinged = 0;
    while start.elapsed() < Duration::from_millis(1200) {
        match c.next_raw().await {
            Got::Event(e) if e["type"] == "ping" => {
                assert_valid("ping.json", &e);
                pinged += 1;
                c.pong(&e).await;
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    assert!(pinged >= 4, "pinged {pinged} times");
    // Silence: closed 1000 once the idle timeout passes.
    let silent = tokio::time::Instant::now();
    loop {
        match c.next_raw().await {
            Got::Event(e) => assert_eq!(e["type"], "ping"),
            Got::Closed(code, _) => {
                assert_eq!(code, 1000);
                break;
            }
        }
    }
    assert!(silent.elapsed() >= Duration::from_millis(400));
}

#[tokio::test]
async fn client_pings_are_answered_with_pongs() {
    let p = provider().await;
    let mut c = p.alice("10.0.0.1").await;
    let ping = json!({"id": "cli_ping", "type": "ping", "ts": rfc3339(p.now()), "data": {}});
    assert_valid("ping.json", &ping);
    c.send_raw(&ping.to_string()).await;
    let pong = c.event().await;
    assert_valid("pong.json", &pong);
    assert_eq!(pong["type"], "pong");
    assert_eq!(pong["correlationId"], "cli_ping");
}

/// Presence (§7.5) sees the provider's own authenticated connections.
#[tokio::test]
async fn presence_derives_from_live_connections() {
    let p = provider().await;
    let alice = Actor::parse_canonical("alice@providera.com").unwrap();
    let liveness = &p.state.profiles.liveness;
    assert!(!liveness.is_connected(&alice));
    let unauthenticated = p.client("10.0.0.1").await;
    assert!(!liveness.is_connected(&alice));
    drop(unauthenticated);
    let c = p.alice("10.0.0.1").await;
    assert!(liveness.is_connected(&alice));
    drop(c);
    let gone = async {
        while liveness.is_connected(&alice) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(5), gone)
        .await
        .expect("disconnected");
}

#[tokio::test]
async fn oversized_messages_close_1009() {
    let p = provider().await;
    let mut c = p.client("10.0.0.1").await;
    c.event().await;
    c.send_raw(&"x".repeat(9 * 1024)).await;
    assert_eq!(c.closed().await.0, 1009);

    let mut c = p.alice("10.0.0.1").await;
    c.send_raw(&"x".repeat(65 * 1024)).await;
    assert_eq!(c.closed().await.0, 1009);
}

#[tokio::test]
async fn binary_messages_close_1003() {
    let p = provider().await;
    let mut c = p.alice("10.0.0.1").await;
    c.send_binary(b"\x00\x01").await;
    assert_eq!(c.closed().await.0, 1003);
}

#[tokio::test]
async fn the_command_rate_is_limited_then_enforced() {
    let mut config = fast_config();
    config.command_burst = 3;
    config.commands_per_sec = 1;
    let p = provider_with(config).await;
    let mut c = p.alice("10.0.0.1").await;
    for _ in 0..4 {
        c.command("ping", json!({})).await;
    }
    for _ in 0..3 {
        assert_eq!(c.event().await["type"], "pong");
    }
    let e = c.event().await;
    assert_valid("error.json", &e);
    assert_eq!(e["data"]["code"], "too_many_requests");
    assert_eq!(e["data"]["status"], 429);
    assert_eq!(e["data"]["details"]["retryAfter"], 1);
    // Ignoring the refusals: closed 1008.
    for _ in 0..4 {
        c.command("ping", json!({})).await;
    }
    assert_eq!(c.closed().await.0, 1008);
}

#[tokio::test]
async fn connection_caps_apply_per_client_and_per_actor() {
    let mut config = fast_config();
    config.limits.per_client = 2;
    config.limits.per_actor = 1;
    let p = provider_with(config).await;
    let _one = p.client("10.0.0.1").await;
    let _two = p.client("10.0.0.1").await;
    assert_eq!(
        Client::try_connect(p.addr, "10.0.0.1").await.err(),
        Some(429)
    );

    let _alice = p.alice("10.0.0.2").await;
    let mut again = p.client("10.0.0.3").await;
    again
        .answer_challenge("providera.com", ALICE, KEY_ID, &key(), p.now())
        .await;
    let (code, events) = again.closed().await;
    assert_eq!(code, 1013);
    assert_eq!(events[0]["data"]["code"], "too_many_requests");
}

#[tokio::test]
async fn unknown_types_are_ignored_and_unsupported_ones_refused() {
    let p = provider().await;
    let mut c = p.alice("10.0.0.1").await;
    c.command("x.future.thing", json!({"a": 1})).await;
    let id = c
        .command("message.create", json!({"channelId": "chn_1"}))
        .await;
    let e = c.event().await;
    assert_eq!(
        (e["correlationId"].as_str(), &e["data"]["code"]),
        (Some(id.as_str()), &json!("bad_request"))
    );
    // Malformed frames are answered, and the connection stays open.
    c.send_raw("{\"id\": \"cli_x\"}").await;
    let e = c.event().await;
    assert_eq!(
        (e["correlationId"].as_str(), &e["data"]["code"]),
        (Some("cli_x"), &json!("bad_request"))
    );
    c.send_raw("[]").await;
    assert_eq!(c.event().await["data"]["code"], "bad_request");
    let ping = c.command("ping", json!({})).await;
    assert_eq!(c.event().await["correlationId"], ping);
}

#[tokio::test]
async fn without_channel_topics_every_subscribe_is_not_found() {
    let p = provider().await;
    let mut c = p.alice("10.0.0.1").await;
    let id = c
        .command("subscribe", json!({"channels": ["chn_1", "chn_2"]}))
        .await;
    let e = c.event().await;
    assert_valid("error.json", &e);
    assert_eq!(e["correlationId"], id);
    assert_eq!(e["data"]["code"], "not_found");
    assert_eq!(e["data"]["details"]["channels"], json!(["chn_1", "chn_2"]));
    let id = c.command("subscribe", json!({"channels": []})).await;
    let e = c.event().await;
    assert_eq!(
        (e["correlationId"].as_str(), &e["data"]["code"]),
        (Some(id.as_str()), &json!("bad_request"))
    );
}

#[tokio::test]
async fn shutdown_closes_1001_and_refuses_new_connections() {
    let p = provider().await;
    let mut c = p.alice("10.0.0.1").await;
    let mut unauthenticated = p.client("10.0.0.2").await;
    let hub = p.state.ws.clone();
    let shutdown = tokio::spawn(async move { hub.shutdown().await });
    assert_eq!(c.closed().await.0, 1001);
    assert_eq!(unauthenticated.closed().await.0, 1001);
    shutdown.await.unwrap();
    assert!(p.state.ws.registry().is_empty());
    assert_eq!(
        Client::try_connect(p.addr, "10.0.0.3").await.err(),
        Some(503)
    );
}

#[tokio::test]
async fn a_plain_get_is_a_bad_request_problem() {
    let p = provider().await;
    let app = re_ofscp_server::router(p.state.clone());
    let req = axum::http::Request::get("/api/ws")
        .header("host", "providera.com")
        .body(axum::body::Body::empty())
        .unwrap();
    let (status, body, _, _) = send(&app, req).await;
    assert_eq!(status, 400);
    assert_eq!(body["status"], 400);
}
