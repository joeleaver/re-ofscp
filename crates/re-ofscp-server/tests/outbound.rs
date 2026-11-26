//! The SSRF-safe outbound client (spec §8 "Outbound requests",
//! docs/decisions/0006) against a local https peer.

mod common;

use std::time::Duration;

use common::remote_peer::{RemotePeer, Reply};
use re_ofscp_server::outbound::{OutboundClient, OutboundError};
use re_ofscp_types::Authority;
use serde_json::json;

fn open_policy() -> std::sync::Arc<re_ofscp_server::federation::FederationPolicy> {
    std::sync::Arc::new(re_ofscp_server::federation::FederationPolicy::open())
}

fn authority(s: &str) -> Authority {
    Authority::parse_canonical(s).unwrap()
}

#[tokio::test]
async fn an_allowed_peer_is_fetched_over_https() {
    let peer = RemotePeer::start().await;
    peer.set("/doc", Reply::json(200, &json!({ "ok": true })));
    let client = peer.allowed_client();
    for host in [peer.authority(), peer.ip_authority()] {
        let res = client.get(&host, "/doc").await.unwrap();
        assert_eq!(res.status, 200);
        assert_eq!(res.body, br#"{"ok":true}"#);
        assert_eq!(res.headers["content-type"], "application/json");
    }
    assert_eq!(peer.hits("/doc"), 2);
}

#[tokio::test]
async fn loopback_is_refused_unless_allowed() {
    let peer = RemotePeer::start().await;
    peer.set("/doc", Reply::json(200, &json!({})));
    let port = peer.port;
    let strict = peer.strict_client();
    for host in [
        // A name: refused by the resolver, after lookup.
        format!("localhost:{port}"),
        // IP literals: refused before any connection.
        format!("127.0.0.1:{port}"),
        format!("127.1.2.3:{port}"),
        // WHATWG numeric forms the URL parser turns into 127.0.0.1.
        format!("2130706433:{port}"),
        format!("0x7f.1:{port}"),
        format!("0177.0.0.1:{port}"),
    ] {
        let err = strict.get(&authority(&host), "/doc").await.unwrap_err();
        assert!(matches!(err, OutboundError::Refused(_)), "{host}: {err:?}");
    }
    // Allowing another port of the same host allows nothing here: the
    // exception is per authority.
    let other_port = OutboundClient::new(&peer.config(vec![authority("localhost:1")])).unwrap();
    let err = other_port.get(&peer.authority(), "/doc").await.unwrap_err();
    assert!(matches!(err, OutboundError::Refused(_)), "{err:?}");
    assert_eq!(peer.total_hits(), 0, "nothing reached the peer");
}

#[tokio::test]
async fn private_literals_are_refused_without_a_connection() {
    let client = OutboundClient::new(&re_ofscp_server::outbound::OutboundConfig::new(
        Vec::new(),
        open_policy(),
    ))
    .unwrap();
    for host in [
        "10.0.0.1",
        "169.254.169.254",
        "192.168.1.1:8443",
        "100.64.0.1",
        "0.0.0.0",
        "167772161", // 10.0.0.1
    ] {
        let target = client.target(&authority(host), "/x");
        assert!(matches!(target, Err(OutboundError::Refused(_))), "{host}");
    }
    assert!(client.target(&authority("8.8.8.8"), "/x").is_ok());
    assert!(client.target(&authority("remote.example"), "/x").is_ok());
    assert!(matches!(
        client.target(&authority("remote.example"), "x"),
        Err(OutboundError::Refused(_))
    ));
}

#[tokio::test]
async fn a_name_that_does_not_resolve_is_a_network_error_not_a_refusal() {
    // lost-conn/ofscp#20: NXDOMAIN, SERVFAIL or a DNS timeout is a fetch
    // failure (503), never the policy refusal (401).
    let peer = RemotePeer::start().await;
    let err = peer
        .strict_client()
        .get(&authority("no-such-host.invalid"), "/doc")
        .await
        .unwrap_err();
    assert!(matches!(err, OutboundError::Network(_)), "{err:?}");
}

#[tokio::test]
async fn redirects_are_not_followed() {
    let peer = RemotePeer::start().await;
    let target = format!("https://{}/elsewhere", peer.authority());
    for status in [301, 302, 303, 307, 308] {
        peer.set("/moved", Reply::new(status, "").header("location", &target));
        let err = peer
            .allowed_client()
            .get(&peer.authority(), "/moved")
            .await
            .unwrap_err();
        assert_eq!(err, OutboundError::Redirect(status));
    }
    assert_eq!(peer.hits("/elsewhere"), 0);
}

#[tokio::test]
async fn bodies_over_the_cap_fail() {
    let peer = RemotePeer::start().await;
    let mut config = peer.config(vec![peer.authority()]);
    config.max_body = 4096;
    let client = OutboundClient::new(&config).unwrap();
    peer.set("/exact", Reply::new(200, vec![b'a'; 4096]));
    peer.set(
        "/exact-chunked",
        Reply::new(200, vec![b'a'; 4096]).chunked(),
    );
    peer.set("/big", Reply::new(200, vec![b'a'; 4097]));
    peer.set(
        "/big-chunked",
        Reply::new(200, vec![b'a'; 10_000]).chunked(),
    );
    for path in ["/exact", "/exact-chunked"] {
        let res = client.get(&peer.authority(), path).await.unwrap();
        assert_eq!(res.body.len(), 4096, "{path}");
    }
    for path in ["/big", "/big-chunked"] {
        let err = client.get(&peer.authority(), path).await.unwrap_err();
        assert_eq!(err, OutboundError::TooLarge(4096), "{path}");
    }
}

#[tokio::test]
async fn slow_peers_time_out() {
    let peer = RemotePeer::start().await;
    let mut config = peer.config(vec![peer.authority()]);
    config.timeout = Duration::from_millis(300);
    let client = OutboundClient::new(&config).unwrap();
    peer.set(
        "/slow",
        Reply::new(200, "late").delayed(Duration::from_secs(5)),
    );
    let started = std::time::Instant::now();
    let err = client.get(&peer.authority(), "/slow").await.unwrap_err();
    assert_eq!(err, OutboundError::Timeout);
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[tokio::test]
async fn untrusted_certificates_fail() {
    // Without the test CA, only the Mozilla roots are trusted.
    let peer = RemotePeer::start().await;
    peer.set("/doc", Reply::json(200, &json!({})));
    let client = OutboundClient::new(&re_ofscp_server::outbound::OutboundConfig::new(
        vec![peer.authority()],
        open_policy(),
    ))
    .unwrap();
    let err = client.get(&peer.authority(), "/doc").await.unwrap_err();
    assert!(matches!(err, OutboundError::Network(_)), "{err:?}");
}

#[tokio::test]
async fn requests_over_the_per_target_cap_fail_at_once() {
    let peer = RemotePeer::start().await;
    peer.set(
        "/slow",
        Reply::json(200, &json!({})).delayed(Duration::from_millis(600)),
    );
    peer.set("/fast", Reply::json(200, &json!({})));
    let client = std::sync::Arc::new(peer.allowed_client());
    // Four stalled requests fill the cap for `localhost`.
    let stalled: Vec<_> = (0..4)
        .map(|_| {
            let (client, host) = (client.clone(), peer.authority());
            tokio::spawn(async move { client.get(&host, "/slow").await })
        })
        .collect();
    tokio::time::sleep(Duration::from_millis(150)).await;
    // The fifth fails without waiting, and so does another port of the
    // same host: it is the same target.
    let other_port = authority(&format!("localhost:{}", peer.port.wrapping_add(1).max(1)));
    for host in [peer.authority(), other_port] {
        let started = std::time::Instant::now();
        let err = client.get(&host, "/fast").await.unwrap_err();
        assert_eq!(err, OutboundError::Busy("localhost".to_owned()), "{host}");
        assert!(started.elapsed() < Duration::from_millis(100), "{host}");
    }
    // Another target is unaffected.
    assert_eq!(
        client
            .get(&peer.ip_authority(), "/fast")
            .await
            .unwrap()
            .status,
        200
    );
    for request in stalled {
        assert_eq!(request.await.unwrap().unwrap().status, 200);
    }
    // The slots are released once the stalled requests end.
    assert_eq!(
        client.get(&peer.authority(), "/fast").await.unwrap().status,
        200
    );
    assert_eq!(peer.hits("/fast"), 2);
}

#[test]
fn free_subdomains_of_a_private_suffix_share_one_per_target_cap() {
    // Reserving touches no network: the cap is taken before anything is
    // resolved or sent.
    let config = re_ofscp_server::outbound::OutboundConfig::new(Vec::new(), open_policy());
    let cap = config.max_in_flight_per_target;
    let client = OutboundClient::new(&config).unwrap();
    let held: Vec<_> = (0..cap)
        .map(|i| {
            client
                .reserve(&authority(&format!("s{i}.workers.dev")), "/doc")
                .unwrap()
        })
        .collect();
    let err = client
        .reserve(&authority("fresh.workers.dev:8443"), "/doc")
        .unwrap_err();
    assert_eq!(err, OutboundError::Busy("workers.dev".to_owned()));
    // Another ICANN domain's free subdomains are another target.
    assert!(client.reserve(&authority("s0.vercel.app"), "/doc").is_ok());
    drop(held);
    assert!(
        client
            .reserve(&authority("fresh.workers.dev"), "/doc")
            .is_ok()
    );
}
