//! Changes that land while a WebSocket handshake is resolving its key
//! (spec §7.1, §4.7, §8.5): the connection is never acknowledged.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use common::harness::key;
use common::ws::{Client, Provider, denying, fast_config};
use ed25519_dalek::VerifyingKey;
use re_ofscp_server::accounts::{Revocation, RevocationListener as _};
use re_ofscp_server::federation::Snapshot;
use re_ofscp_server::signing::{KeyFuture, KeyResolver, Requester, Resolved};
use re_ofscp_types::{Actor, Authority};
use tokio::sync::Notify;

/// Publishes `key` for every signer, but pauses the first lookup until
/// released. That lookup answers with the key: it read it before anything
/// changed. [`Paused::gone`] withdraws the key from later lookups.
#[derive(Debug)]
struct Paused {
    key: VerifyingKey,
    entered: Notify,
    release: Notify,
    paused: AtomicBool,
    gone: AtomicBool,
}

impl Paused {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            key: key().verifying_key(),
            entered: Notify::new(),
            release: Notify::new(),
            paused: AtomicBool::new(false),
            gone: AtomicBool::new(false),
        })
    }
}

impl KeyResolver for Paused {
    fn resolve<'a>(
        &'a self,
        _actor: &'a Actor,
        _key_id: &'a str,
        _fresh: bool,
        _requester: &'a Requester,
    ) -> KeyFuture<'a> {
        Box::pin(async move {
            if !self.paused.swap(true, Ordering::SeqCst) {
                self.entered.notify_one();
                self.release.notified().await;
                return Ok(Resolved::authoritative(Some(self.key)));
            }
            let key = (!self.gone.load(Ordering::SeqCst)).then_some(self.key);
            Ok(Resolved::authoritative(key))
        })
    }
}

/// Start a handshake as `actor` and wait until its key lookup is paused.
async fn paused_handshake(p: &Provider, keys: &Paused, actor: &str) -> Client {
    let mut c = p.client("10.0.0.1").await;
    c.answer_challenge("providera.com", actor, "dk_abc123xyz", &key(), p.now())
        .await;
    keys.entered.notified().await;
    c
}

#[tokio::test]
async fn a_key_revoked_mid_handshake_closes_4003_unacknowledged() {
    let keys = Paused::new();
    let p = Provider::start(None, fast_config(), |b| b.keys(keys.clone())).await;
    let mut c = paused_handshake(&p, &keys, "alice@providera.com").await;

    keys.gone.store(true, Ordering::SeqCst);
    p.state.ws.revoked(&Revocation {
        handle: "alice".to_owned(),
        key_id: Some("dk_abc123xyz".to_owned()),
    });
    keys.release.notify_one();

    let (code, events) = c.closed().await;
    assert_eq!(code, 4003);
    assert_eq!(events.len(), 1, "no `authenticated`: {events:?}");
    assert_eq!(events[0]["type"], "error");
    assert_eq!(events[0]["data"]["code"], "unauthorized");
}

#[tokio::test]
async fn a_federation_denial_mid_handshake_is_refused_unacknowledged() {
    let keys = Paused::new();
    let p = Provider::start(None, fast_config(), |b| b.remote_keys(keys.clone())).await;
    let policy = p.state.federation.policy();
    policy.install(Snapshot::default());
    let mut c = paused_handshake(&p, &keys, "bob@remote.example").await;

    let remote = Authority::parse_canonical("remote.example").unwrap();
    policy.install(denying(&remote));
    keys.release.notify_one();

    let (code, events) = c.closed().await;
    assert_eq!(code, 4001);
    assert_eq!(events.len(), 1, "no `authenticated`: {events:?}");
    assert_eq!(events[0]["data"]["code"], "forbidden");
    assert_eq!(events[0]["data"]["status"], 403);
}
