//! Parties (local and remote actors with keys) and requests against the
//! group and channel endpoints (tests/groups.rs, tests/groups_access.rs).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::SigningKey;
use re_ofscp_server::signing::{Signer, StaticKeys};
use re_ofscp_types::Actor;
use serde_json::{Value, json};

use super::accounts::{EnvOptions, NOW, env_with};
use super::harness::{SIGNED_AT, new_key, send, signed};

pub use super::accounts::Env;

/// Someone who signs requests.
pub struct Party {
    /// Canonical actor.
    pub actor: String,
    /// Signing key.
    pub key: SigningKey,
    /// Its key id.
    pub key_id: String,
}

impl Party {
    /// The parsed actor.
    pub fn id(&self) -> Actor {
        Actor::parse_canonical(&self.actor).unwrap()
    }
}

/// A remote actor `handle@domain` whose keys the provider resolves from
/// `keys` (pass it to [`env_with_remotes`]).
pub fn remote(handle: &str, domain: &str) -> Party {
    Party {
        actor: format!("{handle}@{domain}"),
        key: new_key(),
        key_id: format!("dk_{handle}_remote"),
    }
}

/// A provider whose remote-key resolver knows `remotes`.
pub async fn env_with_remotes(remotes: &[&Party]) -> Env {
    let mut keys = StaticKeys::default();
    for p in remotes {
        keys = keys.with(Signer::Actor(p.id()), &p.key_id, p.key.verifying_key());
    }
    env_with(EnvOptions {
        remote: Some(keys),
        ..Default::default()
    })
    .await
}

/// A local account `handle@providera.com` with one device key.
pub async fn local(env: &Env, handle: &str) -> Party {
    let store = &env.state.accounts.store;
    let now = SIGNED_AT.unix_timestamp();
    let user = store
        .create_user(handle, "Test User", "not-a-hash", now)
        .await
        .unwrap();
    let key = new_key();
    let dk = store
        .add_device_key(
            &user,
            &B64.encode(key.verifying_key().to_bytes()),
            "Ed25519",
            "test",
            now,
        )
        .await
        .unwrap();
    Party {
        actor: format!("{handle}@providera.com"),
        key,
        key_id: dk.key_id,
    }
}

/// A request to `path`, signed by `by` (unsigned when `None`).
pub fn request(
    by: Option<&Party>,
    method: &str,
    path: &str,
    body: Option<&Value>,
) -> Request<Body> {
    let text = body.map(Value::to_string).unwrap_or_default();
    match by {
        Some(p) => signed(&p.key, &p.actor, &p.key_id, method, path, &text, NOW),
        None => {
            let mut b = Request::builder()
                .method(method)
                .uri(path)
                .header("host", "providera.com");
            if body.is_some() {
                b = b.header("content-type", "application/json");
            }
            b.body(Body::from(text)).unwrap()
        }
    }
}

/// Send a request: status and JSON body.
pub async fn call(
    env: &Env,
    by: Option<&Party>,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let (s, j, _, _) = send(&env.app, request(by, method, path, body.as_ref())).await;
    (s, j)
}

/// Create a group as `owner` with `body`; panics unless `201`. Returns it.
pub async fn create_group(env: &Env, owner: &Party, body: Value) -> Value {
    let (s, g) = call(env, Some(owner), "POST", "/api/groups", Some(body)).await;
    assert_eq!(s, StatusCode::CREATED, "{g}");
    g
}

/// Create a channel in `group` as `by`; panics unless `201`. Returns it.
pub async fn create_channel(env: &Env, by: &Party, group: &str, body: Value) -> Value {
    let path = format!("/api/groups/{group}/channels");
    let (s, c) = call(env, Some(by), "POST", &path, Some(body)).await;
    assert_eq!(s, StatusCode::CREATED, "{c}");
    c
}

/// Make `who` a member of `group` with `role` (as §5.7 will).
pub async fn join(env: &Env, group: &str, who: &Party, role: &str) {
    let now = SIGNED_AT.unix_timestamp();
    assert!(
        env.state
            .groups
            .add_member(group, &who.id(), role, now)
            .await
            .unwrap()
    );
}

/// A group body of `tier`.
pub fn group_body(name: &str, tier: &str) -> Value {
    json!({ "name": name, "tier": tier })
}

/// The `id` field of an object.
pub fn id(v: &Value) -> String {
    v["id"].as_str().unwrap().to_owned()
}
