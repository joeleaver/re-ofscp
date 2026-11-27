//! Requests against `/api/me/follows`, and follows written straight to the
//! database (tests/follows.rs, tests/follows_races.rs).

use axum::http::StatusCode;
use futures_util::stream::{self, StreamExt};
use re_ofscp_server::db::Ql;
use re_ofscp_server::follows::MAX_FOLLOWS_PER_ACTOR;
use re_ofscp_server::follows::store::{FollowStore, free_slots, slot_key};
use serde_json::{Value, json};

use super::groups::{Env, Party, call};
use super::harness::SIGNED_AT;
use super::my_groups::segment;
use super::{assert_valid, schema};

/// `POST /api/me/follows` of `channel` as `by`.
pub async fn follow(env: &Env, by: &Party, channel: &str) -> (StatusCode, Value) {
    let body = json!({ "channel": channel });
    call(env, Some(by), "POST", "/api/me/follows", Some(body)).await
}

/// `DELETE /api/me/follows/{channel}` as `by`; the status.
pub async fn unfollow(env: &Env, by: &Party, channel: &str) -> StatusCode {
    let path = format!("/api/me/follows/{}", segment(channel));
    call(env, Some(by), "DELETE", &path, None).await.0
}

/// `GET /api/me/follows` as `by`, checked against the schema; the follows.
pub async fn list(env: &Env, by: &Party) -> Vec<Value> {
    let (s, body) = call(env, Some(by), "GET", "/api/me/follows", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_valid(&schema("follows-response.json"), &body);
    body["follows"].as_array().unwrap().clone()
}

/// A remote channel URI, distinct for each `i`.
pub fn remote_channel(i: usize) -> String {
    format!("https://c.example/api/groups/g/channels/chn_{i}")
}

/// Write `n` remote follows of `who` straight to the database (the count,
/// not the channels, is what is limited), in the slots their follows leave
/// free, lowest first. Past the limit's slots it writes slots beyond it,
/// as only a damaged store would hold.
pub async fn remote_follows(env: &Env, who: &Party, n: usize) {
    let owner = who.id();
    let now = SIGNED_AT.unix_timestamp();
    let held = FollowStore::new(env.state.db.clone())
        .list(&owner, 2 * MAX_FOLLOWS_PER_ACTOR)
        .await
        .unwrap();
    let mut slots = free_slots(&held, MAX_FOLLOWS_PER_ACTOR);
    slots.extend(MAX_FOLLOWS_PER_ACTOR..MAX_FOLLOWS_PER_ACTOR + n);
    slots.truncate(n);
    stream::iter(slots.into_iter().enumerate())
        .for_each_concurrent(16, |(i, slot)| {
            let owner = owner.clone();
            async move {
                let channel = remote_channel(i);
                let q = Ql::new("Follow.create({ key: ")
                    .str(&format!("{owner} {channel}"))
                    .raw(", slot: ")
                    .str(&slot_key(&owner, slot))
                    .raw(", owner: ")
                    .str(&owner.to_string())
                    .raw(", channel: ")
                    .str(&channel)
                    .raw(", created_at: ")
                    .unix_seconds(now)
                    .raw(" })");
                env.state.db.execute(&q).await.unwrap();
            }
        })
        .await;
}
