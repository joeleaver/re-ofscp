//! Validating fetched user keys responses and working out how long they may
//! be cached (spec §4.6, lost-conn/ofscp#19 and #20). Providers' discovery
//! keys are never fetched: no route accepts provider signatures
//! (lost-conn/ofscp#42, docs/decisions/0021).

use std::collections::HashMap;

use axum::http::{HeaderMap, header};
use ed25519_dalek::VerifyingKey;
use re_ofscp_types::Actor;
use re_ofscp_types::auth::ED25519;
use serde::Deserialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::signing::canonical::decode_public_key;

/// An actor's usable keys, by key id.
pub type KeySet = HashMap<String, VerifyingKey>;

/// Longest any document is cached: bounds how long a revoked key keeps
/// verifying here (§4.7.1).
pub const MAX_CACHE_SECS: i64 = 3600;
/// Lifetime of a response whose caching headers decide (a user-keys `404`)
/// when it has no `max-age`.
pub const DEFAULT_HTTP_CACHE_SECS: i64 = 300;

/// Why a document was not a valid keys response.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid key document: {0}")]
pub struct Invalid(pub String);

fn invalid(msg: impl Into<String>) -> Invalid {
    Invalid(msg.into())
}

/// One entry of `keys` (§4.6). The user keys schema requires every field,
/// `created_at` included (a string: `null` is invalid).
#[derive(Deserialize)]
struct RawKey {
    key_id: String,
    algorithm: String,
    public_key: String,
    created_at: String,
}

#[derive(Deserialize)]
struct RawUserKeys {
    actor: String,
    keys: Vec<RawKey>,
    cache_until: String,
}

/// A valid keys response for `requested`: its keys, and until when (unix
/// seconds) it says they may be cached.
pub fn user_keys(body: &[u8], requested: &Actor) -> Result<(KeySet, i64), Invalid> {
    let raw: RawUserKeys =
        serde_json::from_slice(body).map_err(|e| invalid(format!("keys response: {e}")))?;
    // Canonicalize, then compare to exactly what we asked for (spec §4.6,
    // lost-conn/ofscp#20): keys published for anyone else are never used.
    // A value that does not canonicalize is invalid.
    let actor = Actor::canonicalize(&raw.actor)
        .map_err(|e| invalid(format!("actor {:?}: {e}", raw.actor)))?;
    if &actor != requested {
        return Err(invalid(format!(
            "keys response is for {actor}, not {requested}"
        )));
    }
    let cache_until = OffsetDateTime::parse(&raw.cache_until, &Rfc3339)
        .map_err(|_| invalid("cache_until is not RFC 3339"))?
        .unix_timestamp();
    Ok((key_set(raw.keys)?, cache_until))
}

/// The keys of `entries`, validated as the schemas require (§4.6: a
/// response is valid only if it matches the schema): every entry has a
/// non-empty `key_id`, `algorithm` `"Ed25519"` (the schemas' only value: any
/// other is invalid, not skipped), a 32-byte base64 key and an RFC 3339
/// `created_at`. A repeated
/// `key_id` makes the whole document invalid too, since we could not tell
/// which key it means.
fn key_set(entries: Vec<RawKey>) -> Result<KeySet, Invalid> {
    let mut seen = std::collections::HashSet::new();
    let mut keys = KeySet::new();
    for entry in entries {
        if entry.key_id.is_empty() {
            return Err(invalid("empty key_id"));
        }
        if !seen.insert(entry.key_id.clone()) {
            return Err(invalid(format!("key_id {:?} appears twice", entry.key_id)));
        }
        if entry.algorithm != ED25519 {
            return Err(invalid(format!(
                "key {:?} has algorithm {:?}, not {ED25519}",
                entry.key_id, entry.algorithm
            )));
        }
        if OffsetDateTime::parse(&entry.created_at, &Rfc3339).is_err() {
            return Err(invalid(format!(
                "key {:?} created_at is not RFC 3339",
                entry.key_id
            )));
        }
        let key = decode_public_key(&entry.public_key)
            .map_err(|e| invalid(format!("key {:?}: {e}", entry.key_id)))?;
        keys.insert(entry.key_id, key);
    }
    Ok(keys)
}

/// Until when (unix seconds) a keys response may be cached: its
/// `cache_until`, capped at an hour from `now`. `None`: not at all.
pub fn user_keys_expiry(cache_until: i64, now: i64) -> Option<i64> {
    Some(cache_until.min(now + MAX_CACHE_SECS)).filter(|&t| t > now)
}

/// Until when (unix seconds) a response may be cached per its
/// `Cache-Control`: `max-age` capped at an hour, five minutes when there is
/// none. `None` (not at all) for `no-store`, `no-cache` or `max-age=0`.
pub fn http_expiry(headers: &HeaderMap, now: i64) -> Option<i64> {
    let mut max_age = None;
    for value in headers.get_all(header::CACHE_CONTROL) {
        let Ok(value) = value.to_str() else {
            // Unreadable caching headers: do not guess, do not cache.
            return None;
        };
        for directive in value.split(',') {
            let directive = directive.trim().to_ascii_lowercase();
            if directive == "no-store" || directive == "no-cache" {
                return None;
            }
            if let Some(n) = directive.strip_prefix("max-age=") {
                // An unparsable max-age is treated as stale (RFC 9111 §4.2.1).
                let secs = n.trim_matches('"').parse::<i64>().unwrap_or(0);
                max_age = Some(max_age.map_or(secs, |m: i64| m.min(secs)));
            }
        }
    }
    let secs = max_age
        .unwrap_or(DEFAULT_HTTP_CACHE_SECS)
        .min(MAX_CACHE_SECS);
    Some(now + secs).filter(|&t| t > now)
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;
    use serde_json::json;

    use super::*;

    const KEY: &str = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";

    fn alice() -> Actor {
        Actor::parse_canonical("alice@remote.example").unwrap()
    }

    fn keys_doc(actor: &str, keys: serde_json::Value) -> Vec<u8> {
        json!({ "actor": actor, "keys": keys, "cache_until": "2026-01-01T13:00:00Z" })
            .to_string()
            .into_bytes()
    }

    fn entry(id: &str) -> serde_json::Value {
        json!({ "key_id": id, "algorithm": "Ed25519", "public_key": KEY, "created_at": "2026-01-01T00:00:00Z" })
    }

    #[test]
    fn a_valid_keys_response_yields_its_keys_and_cache_until() {
        let (keys, until) = user_keys(
            &keys_doc("alice@remote.example", json!([entry("dk_1")])),
            &alice(),
        )
        .unwrap();
        assert_eq!(keys.len(), 1);
        assert!(keys.contains_key("dk_1"));
        assert_eq!(until, 1_767_272_400);
        let (empty, _) = user_keys(&keys_doc("alice@remote.example", json!([])), &alice()).unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn the_actor_is_canonicalized_then_must_match() {
        // Domain spelling is converted (§2.2); the handle never is.
        assert!(user_keys(&keys_doc("alice@Remote.Example.:443", json!([])), &alice()).is_ok());
        for other in [
            "bob@remote.example",
            "alice@other.example",
            "alice@remote.example:8443",
            "Alice@remote.example",
            "alice",
            "",
        ] {
            assert!(
                user_keys(&keys_doc(other, json!([])), &alice()).is_err(),
                "{other}"
            );
        }
    }

    #[test]
    fn malformed_entries_invalidate_the_document() {
        let bad = [
            json!([{ "key_id": "", "algorithm": "Ed25519", "public_key": KEY }]),
            json!([{ "key_id": "dk_1", "algorithm": "Ed25519", "public_key": "c2hvcnQ=" }]),
            json!([{ "key_id": "dk_1", "algorithm": "Ed25519", "public_key": "not base64!" }]),
            json!([{ "key_id": "dk_1", "algorithm": "Ed25519" }]),
            json!([{ "algorithm": "Ed25519", "public_key": KEY }]),
            json!([{ "key_id": 7, "algorithm": "Ed25519", "public_key": KEY }]),
            json!([entry("dk_1"), entry("dk_1")]),
            json!([entry("dk_1"), { "key_id": "dk_1", "algorithm": "X448", "public_key": "?" }]),
            // `created_at` is required here, and must be RFC 3339.
            json!([{ "key_id": "dk_1", "algorithm": "Ed25519", "public_key": KEY }]),
            json!([{ "key_id": "dk_1", "algorithm": "Ed25519", "public_key": KEY, "created_at": "yesterday" }]),
            json!([{ "key_id": "dk_1", "algorithm": "Ed25519", "public_key": KEY, "created_at": null }]),
            json!({}),
        ];
        for keys in bad {
            assert!(
                user_keys(&keys_doc("alice@remote.example", keys.clone()), &alice()).is_err(),
                "{keys}"
            );
        }
        assert!(user_keys(b"not json", &alice()).is_err());
        let no_until = json!({ "actor": "alice@remote.example", "keys": [] }).to_string();
        assert!(user_keys(no_until.as_bytes(), &alice()).is_err());
        let bad_until =
            json!({ "actor": "alice@remote.example", "keys": [], "cache_until": "soon" })
                .to_string();
        assert!(user_keys(bad_until.as_bytes(), &alice()).is_err());
    }

    #[test]
    fn any_other_algorithm_invalidates_the_document() {
        // The schemas allow only "Ed25519": a document with anything else
        // does not match them, so it is invalid as a whole (§4.6).
        for algorithm in ["ML-DSA-65", "ed25519", "Ed448", ""] {
            let other = json!({ "key_id": "dk_2", "algorithm": algorithm, "public_key": KEY, "created_at": "2026-01-01T00:00:00Z" });
            let keys = json!([entry("dk_1"), other]);
            assert!(
                user_keys(&keys_doc("alice@remote.example", keys), &alice()).is_err(),
                "{algorithm}"
            );
        }
    }

    #[test]
    fn user_keys_lifetime_is_cache_until_capped_at_an_hour() {
        let now = 1_000_000;
        assert_eq!(user_keys_expiry(now + 60, now), Some(now + 60));
        assert_eq!(user_keys_expiry(now + 7200, now), Some(now + 3600));
        assert_eq!(user_keys_expiry(now, now), None, "already expired");
        assert_eq!(user_keys_expiry(now - 5, now), None);
    }

    #[test]
    fn http_lifetime_follows_cache_control() {
        let now = 1_000_000;
        let with = |values: &[&str]| {
            let mut h = HeaderMap::new();
            for v in values {
                h.append(header::CACHE_CONTROL, HeaderValue::from_str(v).unwrap());
            }
            http_expiry(&h, now)
        };
        assert_eq!(with(&[]), Some(now + 300));
        assert_eq!(with(&["public"]), Some(now + 300));
        assert_eq!(with(&["public, max-age=120"]), Some(now + 120));
        assert_eq!(with(&["max-age=86400"]), Some(now + 3600));
        assert_eq!(with(&["max-age=600", "max-age=60"]), Some(now + 60));
        assert_eq!(with(&["max-age=0"]), None);
        assert_eq!(with(&["max-age=soon"]), None);
        assert_eq!(with(&["max-age=60, no-cache"]), None);
        assert_eq!(with(&["No-Store"]), None);
    }
}
