//! Signed calls to the profile, presence and privacy endpoints
//! (tests/profiles.rs, tests/privacy_http.rs).

use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use ed25519_dalek::SigningKey;
use re_ofscp_server::privacy::seams::RelFuture;
use re_ofscp_server::privacy::{GroupMemberships, Liveness, Viewer};
use re_ofscp_server::signing::StaticKeys;
use re_ofscp_types::Actor;
use serde_json::Value;

use super::accounts::{Env, NOW, create, login, register_key};
use super::harness::{new_key, send, signed, signed_as};

/// Someone who signs requests.
pub struct Caller {
    /// `x-ofscp-actor` or `x-ofscp-provider`.
    pub header: &'static str,
    /// The actor or provider authority.
    pub id: String,
    /// The key id.
    pub key_id: String,
    /// The key.
    pub key: SigningKey,
}

/// A local account `handle` with a registered device key.
pub async fn local(env: &Env, handle: &str) -> Caller {
    create(env, handle, "correct horse battery").await;
    // One source address per account, clear of the per-source limits.
    let n = handle
        .bytes()
        .fold(0u8, |a, b| a.wrapping_mul(31).wrapping_add(b));
    let ip = format!("10.9.{n}.{}", handle.len());
    let (status, boot, _) = login(env, handle, "correct horse battery", &ip).await;
    assert_eq!(status, StatusCode::OK, "{boot}");
    let key = new_key();
    let token = boot["bootstrap_token"].as_str().unwrap();
    let (status, created) = register_key(env, token, &key, &ip).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    Caller {
        header: "x-ofscp-actor",
        id: format!("{handle}@providera.com"),
        key_id: created["key_id"].as_str().unwrap().to_owned(),
        key,
    }
}

/// The remote user `bob@providerb.com` and the provider `providerb.com`,
/// with the keys that verify them.
pub struct Remote {
    /// bob@providerb.com.
    pub bob: Caller,
    /// providerb.com, signing as a provider (§8.1).
    pub provider: Caller,
}

impl Remote {
    /// Fresh keys for both.
    pub fn new() -> Self {
        let caller = |header, id: &str, key_id: &str| Caller {
            header,
            id: id.to_owned(),
            key_id: key_id.to_owned(),
            key: new_key(),
        };
        Self {
            bob: caller("x-ofscp-actor", "bob@providerb.com", "dk_bob"),
            provider: caller("x-ofscp-provider", "providerb.com", "psk_b"),
        }
    }

    /// A resolver that knows bob's key. The provider's is never resolved:
    /// no route accepts provider signatures (lost-conn/ofscp#42).
    pub fn keys(&self) -> StaticKeys {
        StaticKeys::default().with(
            Actor::parse_canonical(&self.bob.id).unwrap(),
            &self.bob.key_id,
            self.bob.key.verifying_key(),
        )
    }
}

/// A signed request from `caller`: status and JSON body.
pub async fn call(
    env: &Env,
    caller: &Caller,
    method: &str,
    path: &str,
    body: Option<&Value>,
) -> (StatusCode, Value) {
    let body = body.map(Value::to_string).unwrap_or_default();
    let req = if caller.header == "x-ofscp-actor" {
        signed(
            &caller.key,
            &caller.id,
            &caller.key_id,
            method,
            path,
            &body,
            NOW,
        )
    } else {
        signed_as(
            &caller.key,
            (caller.header, &caller.id),
            &caller.key_id,
            method,
            path,
            &body,
            NOW,
        )
    };
    let (status, json, _, _) = send(&env.app, req).await;
    (status, json)
}

/// Group memberships set by the test: pairs who share a group, and the
/// group URIs listed for any viewer who passes the membership policy.
#[derive(Default)]
pub struct FakeGroups {
    /// Pairs sharing a group (either order).
    pub shared: Mutex<Vec<(Actor, Actor)>>,
    /// Group URIs to list.
    pub listed: Mutex<Vec<String>>,
}

impl GroupMemberships for FakeGroups {
    fn share_a_group<'a>(&'a self, a: &'a Actor, b: &'a Actor) -> RelFuture<'a, bool> {
        let shared = self
            .shared
            .lock()
            .unwrap()
            .iter()
            .any(|(x, y)| (x == a && y == b) || (x == b && y == a));
        Box::pin(async move { Ok(shared) })
    }

    fn groups_visible_to<'a>(&'a self, _: &'a Actor, _: &'a Viewer) -> RelFuture<'a, Vec<String>> {
        let listed = self.listed.lock().unwrap().clone();
        Box::pin(async move { Ok(listed) })
    }
}

/// Liveness set by the test.
#[derive(Default)]
pub struct FakeLiveness(pub Mutex<Vec<Actor>>);

impl Liveness for FakeLiveness {
    fn is_connected(&self, actor: &Actor) -> bool {
        self.0.lock().unwrap().contains(actor)
    }
}

/// `actor` as an [`Actor`].
pub fn actor(s: &str) -> Actor {
    Actor::parse_canonical(s).unwrap()
}

/// Shared handles to the fakes, for [`super::accounts::EnvOptions`].
pub fn fakes() -> (Arc<FakeGroups>, Arc<FakeLiveness>) {
    (
        Arc::new(FakeGroups::default()),
        Arc::new(FakeLiveness::default()),
    )
}
