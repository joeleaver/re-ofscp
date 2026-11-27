//! Fetching a remote actor's keys and classifying the outcome (spec §4.6,
//! lost-conn/ofscp#19 and #20). A provider's discovery keys are never
//! fetched: no route accepts provider signatures (lost-conn/ofscp#42).

use std::sync::Arc;

use axum::http::StatusCode;
use re_ofscp_types::{Actor, Authority};

use super::document::{self, KeySet};
use crate::outbound::{OutboundClient, OutboundError, Reservation};

/// Where an actor's keys are published:
/// `https://{domain}/.well-known/ofscp/users/{handle}/keys` (§4.6).
/// Identity is the full actor, never a bare handle (security requirement 1).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Source(Actor);

impl Source {
    /// Where `actor`'s keys come from.
    pub fn of(actor: &Actor) -> Self {
        Self(actor.clone())
    }

    /// The actor whose keys these are.
    pub fn actor(&self) -> &Actor {
        &self.0
    }

    /// The host fetched.
    pub fn host(&self) -> &Authority {
        self.0.domain()
    }

    /// The path fetched. A canonical handle is `[a-z0-9_-]`, so it needs no
    /// escaping.
    pub fn path(&self) -> String {
        format!("/.well-known/ofscp/users/{}/keys", self.0.handle())
    }
}

/// What one fetch found.
#[derive(Debug, Clone)]
pub enum Fetched {
    /// A completed fetch: the actor's keys (empty for an empty list or a
    /// `404`), cacheable until `expires` (unix seconds; `None`:
    /// not cacheable).
    Keys {
        /// Usable keys by id.
        keys: Arc<KeySet>,
        /// Cache lifetime.
        expires: Option<i64>,
    },
    /// A fetch failure (network, timeout, `3xx`, unexpected status, invalid
    /// document): `503` unless an unexpired cached key matches.
    Failed(String),
    /// Our outbound rules forbid the fetch: `401` unless an unexpired cached
    /// key matches. Never cached: the next fetch re-evaluates it from fresh
    /// DNS (lost-conn/ofscp#20).
    Refused(String),
    /// The federation policy denied the provider while the fetch was being
    /// prepared (§8 *Authorization*): `403`, whatever the cache holds.
    Denied(String),
}

/// Fetch `source` through `reservation` (made by `client` for
/// `source.host()` and `source.path()`) and classify the answer. `now`
/// reads the clock once the response is in (unix seconds).
pub async fn fetch(
    client: &OutboundClient,
    source: &Source,
    reservation: Reservation,
    now: impl FnOnce() -> i64,
) -> Fetched {
    let host = source.host();
    let res = match client.get_reserved(reservation).await {
        Ok(res) => res,
        Err(OutboundError::Refused(why)) => return Fetched::Refused(why),
        Err(OutboundError::Denied(who)) => return Fetched::Denied(who),
        Err(e) => return Fetched::Failed(e.to_string()),
    };
    let now = now();
    match res.status {
        StatusCode::OK => match document::user_keys(&res.body, source.actor()) {
            Ok((keys, cache_until)) => Fetched::Keys {
                keys: Arc::new(keys),
                expires: document::user_keys_expiry(cache_until, now),
            },
            Err(e) => Fetched::Failed(e.to_string()),
        },
        // §4.6: a user-keys 404 means no key matches (401), like an empty
        // list. It has no `cache_until`, so its caching headers decide.
        StatusCode::NOT_FOUND => Fetched::Keys {
            keys: Arc::new(KeySet::new()),
            expires: document::http_expiry(&res.headers, now),
        },
        // §4.6: every other status is a fetch failure.
        status => Fetched::Failed(format!("{host} answered {status}")),
    }
}
