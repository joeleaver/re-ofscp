//! Fetching a signer's keys and classifying the outcome (spec §4.6, §8.1,
//! lost-conn/ofscp#19 and #20).

use std::sync::Arc;

use axum::http::StatusCode;
use re_ofscp_types::{Actor, Authority};

use super::document::{self, KeySet};
use crate::outbound::{OutboundClient, OutboundError, Reservation};
use crate::signing::Signer;

/// Where a signer's keys are published. Identity is the full actor or
/// authority, never a bare handle (security requirement 1).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Source {
    /// `https://{domain}/.well-known/ofscp/users/{handle}/keys` (§4.6).
    User(Actor),
    /// `https://{authority}/.well-known/ofscp-provider`, `provider.publicKeys`
    /// (§8.1).
    Provider(Authority),
}

impl Source {
    /// Where `signer`'s keys come from.
    pub fn of(signer: &Signer) -> Self {
        match signer {
            Signer::Actor(a) => Self::User(a.clone()),
            Signer::Provider(p) => Self::Provider(p.clone()),
        }
    }

    /// The host fetched.
    pub fn host(&self) -> &Authority {
        match self {
            Self::User(a) => a.domain(),
            Self::Provider(p) => p,
        }
    }

    /// The path fetched. A canonical handle is `[a-z0-9_-]`, so it needs no
    /// escaping.
    pub fn path(&self) -> String {
        match self {
            Self::User(a) => format!("/.well-known/ofscp/users/{}/keys", a.handle()),
            Self::Provider(_) => "/.well-known/ofscp-provider".to_owned(),
        }
    }
}

/// What one fetch found.
#[derive(Debug, Clone)]
pub enum Fetched {
    /// A completed fetch: the signer's keys (empty for an empty list or a
    /// user-keys `404`), cacheable until `expires` (unix seconds; `None`:
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
        Err(e) => return Fetched::Failed(e.to_string()),
    };
    let now = now();
    match (source, res.status) {
        (Source::User(actor), StatusCode::OK) => match document::user_keys(&res.body, actor) {
            Ok((keys, cache_until)) => Fetched::Keys {
                keys: Arc::new(keys),
                expires: document::user_keys_expiry(cache_until, now),
            },
            Err(e) => Fetched::Failed(e.to_string()),
        },
        // §4.6: a user-keys 404 means no key matches (401), like an empty
        // list. It has no `cache_until`, so its caching headers decide.
        (Source::User(_), StatusCode::NOT_FOUND) => Fetched::Keys {
            keys: Arc::new(KeySet::new()),
            expires: document::http_expiry(&res.headers, now),
        },
        (Source::Provider(authority), StatusCode::OK) => {
            match document::discovery(&res.body, authority) {
                Ok(keys) => Fetched::Keys {
                    keys: Arc::new(keys),
                    expires: document::http_expiry(&res.headers, now),
                },
                Err(e) => Fetched::Failed(e.to_string()),
            }
        }
        // §8.1: for discovery any non-200 answer is a fetch failure; for
        // user keys every status but 200 and 404 is (§4.6).
        (_, status) => Fetched::Failed(format!("{host} answered {status}")),
    }
}
