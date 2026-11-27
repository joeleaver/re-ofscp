//! Requests against the channel message endpoints (tests/messages*.rs):
//! a channel to post in, requests signed at the provider's current clock
//! (so tests can move it, e.g. past an edit window) with their query
//! strings signed too, and the spec schemas the responses must match.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use re_ofscp_server::signing::Clock;
use re_ofscp_server::signing::canonical::{CanonicalRequest, content_digest, sign};
use re_ofscp_server::timefmt;
use serde_json::{Value, json};

use super::groups::{Env, Party, create_channel, create_group, group_body, id};
use super::harness::{rand_u64, send};

/// A channel: its group and its own id.
#[derive(Debug, Clone)]
pub struct Chan {
    /// The group id.
    pub g: String,
    /// The channel id.
    pub c: String,
}

impl Chan {
    /// `…/messages`.
    pub fn messages(&self) -> String {
        format!("/api/groups/{}/channels/{}/messages", self.g, self.c)
    }

    /// `…/messages/{m}`.
    pub fn message(&self, m: &str) -> String {
        format!("{}/{m}", self.messages())
    }

    /// `…/messages/{m}/replies`.
    pub fn replies(&self, m: &str) -> String {
        format!("{}/replies", self.message(m))
    }

    /// `…/messages/{m}/reactions`.
    pub fn reactions(&self, m: &str) -> String {
        format!("{}/reactions", self.message(m))
    }

    /// `…/messages/{m}/reactions/{key}`.
    pub fn reaction(&self, m: &str, key: &str) -> String {
        format!("{}/{key}", self.reactions(m))
    }

    /// The channel itself, `/api/groups/{g}/channels/{c}`.
    pub fn channel(&self) -> String {
        format!("/api/groups/{}/channels/{}", self.g, self.c)
    }
}

/// A group of `tier` owned by `owner`, with `group_extra` merged into its
/// create body, and a channel in it created from `channel`.
pub async fn group_and_channel(
    env: &Env,
    owner: &Party,
    tier: &str,
    group_extra: Value,
    channel: Value,
) -> Chan {
    let mut body = group_body("g", tier);
    if let (Some(b), Some(extra)) = (body.as_object_mut(), group_extra.as_object()) {
        for (k, v) in extra {
            b.insert(k.clone(), v.clone());
        }
    }
    let g = id(&create_group(env, owner, body).await);
    let c = id(&create_channel(env, owner, &g, channel).await);
    Chan { g, c }
}

/// A public group with one public text channel, owned by `owner`.
pub async fn public_channel(env: &Env, owner: &Party) -> Chan {
    group_and_channel(
        env,
        owner,
        "public",
        json!({}),
        json!({"type": "text", "tier": "public"}),
    )
    .await
}

/// A request to `path` (query string included), signed by `by` at the
/// provider's current clock, or unsigned when `by` is `None`. `body` is
/// sent as given.
pub fn request(
    env: &Env,
    by: Option<&Party>,
    method: &str,
    path: &str,
    body: &str,
) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "providera.com")
        .header("content-type", "application/json");
    if let Some(p) = by {
        let timestamp = timefmt::rfc3339(env.clock.now().unix_timestamp());
        let digest = content_digest(body.as_bytes());
        let nonce = format!("{:016x}{:016x}", rand_u64(), rand_u64());
        let (bare, query) = match path.split_once('?') {
            Some((b, q)) => (b, Some(q)),
            None => (path, None),
        };
        let canonical = CanonicalRequest {
            authority: "providera.com",
            method,
            path: bare,
            query,
            timestamp: &timestamp,
            nonce: &nonce,
            content_digest: &digest,
        }
        .render()
        .unwrap();
        b = b
            .header("x-ofscp-actor", &p.actor)
            .header("x-ofscp-key-id", &p.key_id)
            .header("x-ofscp-timestamp", &timestamp)
            .header("x-ofscp-nonce", &nonce)
            .header("x-ofscp-content-digest", &digest)
            .header("x-ofscp-signature", sign(&p.key, &canonical));
    }
    b.body(Body::from(body.to_owned())).unwrap()
}

/// Send a request with a raw body: status and JSON body (`Null` when the
/// response has none).
pub async fn raw(
    env: &Env,
    by: Option<&Party>,
    method: &str,
    path: &str,
    body: &str,
) -> (StatusCode, Value) {
    let (s, j, _, _) = send(&env.app, request(env, by, method, path, body)).await;
    (s, j)
}

/// Send a request with an optional JSON body.
pub async fn call(
    env: &Env,
    by: Option<&Party>,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let text = body.map(|b| b.to_string()).unwrap_or_default();
    raw(env, by, method, path, &text).await
}

/// A plain-text create body.
pub fn text(t: &str) -> Value {
    json!({"content": {"mime": "text/plain", "text": t}})
}

/// A plain-text create body with `clientMessageId`.
pub fn text_with_id(t: &str, cmid: &str) -> Value {
    json!({"clientMessageId": cmid, "content": {"mime": "text/plain", "text": t}})
}

/// A plain-text reply to `parent`.
pub fn reply(t: &str, parent: &str) -> Value {
    json!({
        "content": {"mime": "text/plain", "text": t},
        "reference": {"type": "reply", "id": parent},
    })
}

/// Post `body` in `chan` as `by`; panics unless `201`. Returns the message,
/// checked against `message.json`.
pub async fn post(env: &Env, by: &Party, chan: &Chan, body: Value) -> Value {
    let (s, m) = call(env, Some(by), "POST", &chan.messages(), Some(body)).await;
    assert_eq!(s, StatusCode::CREATED, "{m}");
    super::assert_valid(&message_schema(), &m);
    m
}

/// The ids of a page's items, in order.
pub fn ids(page: &Value) -> Vec<String> {
    page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["id"].as_str().unwrap().to_owned())
        .collect()
}

/// A page's `page.nextCursor`, if any.
pub fn next_cursor(page: &Value) -> Option<String> {
    page["page"]["nextCursor"].as_str().map(str::to_owned)
}

/// `message.json`.
pub fn message_schema() -> jsonschema::Validator {
    super::schema("message.json")
}

/// `messages-page.json`.
pub fn page_schema() -> jsonschema::Validator {
    super::schema("messages-page.json")
}

/// `reaction.json`.
pub fn reaction_schema() -> jsonschema::Validator {
    super::schema("reaction.json")
}

/// `problem-details.json`.
pub fn problem_schema() -> jsonschema::Validator {
    super::schema("problem-details.json")
}

/// A paged list of `Reaction` objects: the spec has no file for it, so
/// this is its `PagedResponse` with `reaction.json` items.
pub fn reactions_page_schema() -> jsonschema::Validator {
    super::schema_value(json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": format!("{}reactions-page.test.json", super::SCHEMA_ID_BASE),
        "allOf": [
            { "$ref": "./defs/messaging.json#/$defs/PagedResponse" },
            {
                "type": "object",
                "properties": {
                    "items": { "type": "array", "items": { "$ref": "./reaction.json" } }
                }
            }
        ]
    }))
}

/// Assert a problem response of `status`, valid against the schema.
pub fn assert_problem(status: StatusCode, want: StatusCode, body: &Value) {
    assert_eq!(status, want, "{body}");
    super::assert_valid(&problem_schema(), body);
    assert_eq!(body["status"], json!(want.as_u16()), "{body}");
}
