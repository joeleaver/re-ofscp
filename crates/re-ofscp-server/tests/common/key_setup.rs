//! The remote key resolver against a local https peer, on an injected
//! clock: shared by `tests/remote_keys.rs` and `tests/remote_keys_budgets.rs`.

use std::sync::Arc;

use ed25519_dalek::VerifyingKey;
use re_ofscp_server::outbound::OutboundClient;
use re_ofscp_server::remote_keys::RemoteKeys;
use re_ofscp_server::signing::{KeyError, KeyResolver, Requester, Resolved, Signer};
use re_ofscp_server::timefmt::rfc3339;
use re_ofscp_types::Actor;

use super::harness::{SIGNED_AT, SettableClock};
use super::remote_peer::{RemotePeer, Reply, keys_doc, keys_path};

pub struct Setup {
    pub peer: RemotePeer,
    pub keys: Arc<RemoteKeys>,
    pub clock: Arc<SettableClock>,
}

impl Setup {
    pub async fn new() -> Self {
        let peer = RemotePeer::start().await;
        let client = Arc::new(peer.allowed_client());
        Self::with_client(peer, client)
    }

    pub fn with_client(peer: RemotePeer, client: Arc<OutboundClient>) -> Self {
        let clock = SettableClock::at(SIGNED_AT);
        let keys = Arc::new(RemoteKeys::new(client, clock.clone()));
        Self { peer, keys, clock }
    }

    pub fn actor_id(&self, handle: &str) -> String {
        format!("{handle}@{}", self.peer.authority())
    }

    pub fn actor(&self, handle: &str) -> Signer {
        Signer::Actor(Actor::parse_canonical(&self.actor_id(handle)).unwrap())
    }

    pub fn provider(&self) -> Signer {
        Signer::Provider(self.peer.authority())
    }

    /// Unix seconds now, on the test clock.
    pub fn now(&self) -> i64 {
        use re_ofscp_server::signing::Clock as _;
        self.clock.now().unix_timestamp()
    }

    pub fn advance(&self, secs: i64) {
        self.clock
            .set(time::OffsetDateTime::from_unix_timestamp(self.now() + secs).unwrap());
    }

    /// Serve `handle`'s keys, cacheable for `ttl` seconds from now.
    pub fn serve_keys(&self, handle: &str, keys: &[(&str, VerifyingKey)], ttl: i64) {
        let doc = keys_doc(&self.actor_id(handle), keys, &rfc3339(self.now() + ttl));
        self.peer.set(&keys_path(handle), Reply::json(200, &doc));
    }

    pub fn hits(&self, handle: &str) -> usize {
        self.peer.hits(&keys_path(handle))
    }

    pub async fn resolve(
        &self,
        signer: &Signer,
        key_id: &str,
        fresh: bool,
    ) -> Result<Resolved, KeyError> {
        self.resolve_as(&client(), signer, key_id, fresh).await
    }

    /// Resolve on behalf of `requester`.
    pub async fn resolve_as(
        &self,
        requester: &Requester,
        signer: &Signer,
        key_id: &str,
        fresh: bool,
    ) -> Result<Resolved, KeyError> {
        self.keys.resolve(signer, key_id, fresh, requester).await
    }
}

/// The client most tests make their lookups for.
pub fn client() -> Requester {
    Requester::new("203.0.113.7")
}

/// The `n`th of many distinct clients.
pub fn nth_client(n: u32) -> Requester {
    Requester::new(format!("198.51.100.{n}"))
}

pub fn unavailable(r: Result<Resolved, KeyError>) -> u64 {
    match r {
        Err(KeyError::Unavailable { retry_after, .. }) => retry_after,
        other => panic!("expected 503, got {other:?}"),
    }
}

pub fn fetched(key: Option<VerifyingKey>) -> Result<Resolved, KeyError> {
    Ok(Resolved::authoritative(key))
}

pub fn cached(key: Option<VerifyingKey>) -> Result<Resolved, KeyError> {
    Ok(Resolved::cached(key))
}
