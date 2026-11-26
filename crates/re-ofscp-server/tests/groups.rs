//! The §5.5 group and channel endpoints over a real rhypedb-server:
//! creation and defaults, validation, updates, deletion, channels, tiers.
//! Every success body is validated against the spec's JSON Schemas.
//! (The access matrix and remote actors are in tests/groups_access.rs;
//! limits, the sweeper and pending rows in tests/groups_lifecycle.rs.)

mod common;

use axum::http::StatusCode;
use common::groups::{
    Env, call, create_channel, create_group, env_with_remotes, group_body, id, join, local, remote,
};
use common::harness::send;
use common::{assert_valid, schema};
use re_ofscp_server::groups::AccessChange;
use serde_json::{Value, json};

fn valid_group(g: &Value) {
    assert_valid(&schema("group.json"), g);
}

fn valid_channel(c: &Value) {
    assert_valid(&schema("channel.json"), c);
}

async fn env() -> Env {
    env_with_remotes(&[]).await
}

#[tokio::test]
async fn a_new_group_is_private_and_invite_only_with_effective_permissions() {
    let env = env().await;
    let alice = local(&env, "alice").await;
    let g = create_group(&env, &alice, json!({"name": "Dev Guild"})).await;
    valid_group(&g);
    assert!(id(&g).starts_with("grp_"));
    assert_eq!(g["owner"], "alice@providera.com");
    assert_eq!(g["tier"], "private");
    assert_eq!(g["joinPolicy"], "invite");
    assert_eq!(g["metadata"], json!([]));
    assert_eq!(
        g["permissions"],
        json!({"post": ["admin", "member"], "moderate": ["admin"], "manage": ["admin"]})
    );
    assert_eq!(g["createdAt"], g["updatedAt"]);
    assert!(g.get("description").is_none());

    let path = format!("/api/groups/{}", id(&g));
    let (s, got) = call(&env, Some(&alice), "GET", &path, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(got, g);
}

#[tokio::test]
async fn creation_keeps_what_was_given_and_fills_only_missing_actions() {
    let env = env().await;
    let alice = local(&env, "alice").await;
    let body = json!({
        "name": "Guild",
        "description": "about",
        "tier": "public",
        "joinPolicy": "open",
        "permissions": {"post": ["member"], "pin": ["moderator"]},
        "roles": [{"name": "moderator", "color": "#123456"}],
        "metadata": [{"schema": "https://x.example/meta", "version": "1", "data": {"k": 1}}],
        "unknownField": true
    });
    let g = create_group(&env, &alice, body).await;
    valid_group(&g);
    assert_eq!(g["description"], "about");
    assert_eq!(g["tier"], "public");
    assert_eq!(g["joinPolicy"], "open");
    assert_eq!(
        g["permissions"],
        json!({"post": ["member"], "pin": ["moderator"], "moderate": ["admin"], "manage": ["admin"]})
    );
    assert_eq!(
        g["roles"],
        json!([{"name": "moderator", "color": "#123456"}])
    );
    assert_eq!(g["metadata"][0]["data"], json!({"k": 1}));
    assert!(g.get("unknownField").is_none());
}

#[tokio::test]
async fn invalid_creations_are_refused() {
    let alice_remote = remote("alice", "providerb.example");
    let env = env_with_remotes(&[&alice_remote]).await;
    let alice = local(&env, "alice").await;
    for (body, why) in [
        (json!({}), "no name"),
        (json!({"name": ""}), "empty name"),
        (json!({"name": "  "}), "blank name"),
        (
            json!({"name": "x", "description": null}),
            "null description",
        ),
        (json!({"name": "x", "tier": "secret"}), "unknown tier"),
        (
            json!({"name": "x", "joinPolicy": "maybe"}),
            "unknown join policy",
        ),
        (
            json!({"name": "x", "permissions": {"post": [""]}}),
            "empty role",
        ),
        (
            json!({"name": "x", "roles": [{"name": "a"}, {"name": "a"}]}),
            "duplicate role",
        ),
        (
            json!({"name": "x", "metadata": [{"schema": "http://x", "version": "1", "data": 1}]}),
            "http schema",
        ),
        (json!({"name": "x".repeat(101)}), "long name"),
    ] {
        let (s, p) = call(&env, Some(&alice), "POST", "/api/groups", Some(body)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{why}: {p}");
        assert_eq!(p["errorCode"], "bad_request", "{why}");
    }
    let body = group_body("x", "public");
    let (s, p) = call(&env, None, "POST", "/api/groups", Some(body.clone())).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "{p}");
    // Remote actors use groups here but do not create them (provider policy).
    let (s, p) = call(&env, Some(&alice_remote), "POST", "/api/groups", Some(body)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{p}");
    assert_eq!(p["errorCode"], "forbidden");
}

#[tokio::test]
async fn unknown_and_malformed_ids_are_not_found() {
    let env = env().await;
    let alice = local(&env, "alice").await;
    for path in [
        "/api/groups/grp_nope",
        "/api/groups/has%20space",
        &format!("/api/groups/{}", "a".repeat(129)),
        "/api/groups/grp_nope/channels",
        "/api/groups/grp_nope/channels/chn_nope",
    ] {
        let (s, p) = call(&env, Some(&alice), "GET", path, None).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{path}: {p}");
        assert_eq!(p["errorCode"], "not_found");
    }
    let (s, _) = call(
        &env,
        Some(&alice),
        "PATCH",
        "/api/groups/grp_nope",
        Some(json!({})),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = call(&env, Some(&alice), "DELETE", "/api/groups/grp_nope", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Every single-channel `404` is the same, whichever id is wrong (§11.3).
    let gid = id(&create_group(&env, &alice, group_body("G", "public")).await);
    let mut bodies = Vec::new();
    for path in [
        format!("/api/groups/{gid}/channels/chn_nope"),
        "/api/groups/grp_nope/channels/chn_nope".to_owned(),
        "/api/groups/bad%20id/channels/chn_nope".to_owned(),
        format!("/api/groups/{gid}/channels/bad%20id"),
    ] {
        let (s, p) = call(&env, Some(&alice), "GET", &path, None).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{path}");
        bodies.push(p);
    }
    assert!(bodies.windows(2).all(|w| w[0] == w[1]), "{bodies:?}");
}

#[tokio::test]
async fn patch_needs_manage_and_changes_only_what_it_names() {
    let env = env().await;
    let alice = local(&env, "alice").await;
    let adam = local(&env, "adam").await;
    let mia = local(&env, "mia").await;
    let olga = local(&env, "olga").await;
    let g = create_group(&env, &alice, json!({"name": "G", "description": "d"})).await;
    let gid = id(&g);
    join(&env, &gid, &adam, "admin").await;
    join(&env, &gid, &mia, "member").await;
    let path = format!("/api/groups/{gid}");

    for (who, want) in [
        (&mia, StatusCode::FORBIDDEN),
        (&olga, StatusCode::FORBIDDEN),
    ] {
        let (s, p) = call(&env, Some(who), "PATCH", &path, Some(json!({"name": "H"}))).await;
        assert_eq!(s, want, "{}: {p}", who.actor);
    }
    let (s, _) = call(&env, None, "PATCH", &path, Some(json!({"name": "H"}))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    env.clock
        .set(common::harness::SIGNED_AT + time::Duration::seconds(5));
    let ts = "2026-01-01T12:00:05Z";
    let patch = json!({"name": "H", "tier": "group", "joinPolicy": "request"});
    let req = common::harness::signed(
        &adam.key,
        &adam.actor,
        &adam.key_id,
        "PATCH",
        &path,
        &patch.to_string(),
        ts,
    );
    let (s, u, _, _) = send(&env.app, req).await;
    assert_eq!(s, StatusCode::OK, "{u}");
    valid_group(&u);
    assert_eq!(u["name"], "H");
    assert_eq!(u["tier"], "group");
    assert_eq!(u["joinPolicy"], "request");
    assert_eq!(u["description"], "d");
    assert_eq!(u["createdAt"], g["createdAt"]);
    assert_eq!(u["updatedAt"], ts);

    // `manage` granted to `member` only: no inheritance, so `admin` loses it.
    let perms = json!({"permissions": {"manage": ["member"]}});
    let (s, _) = call(&env, Some(&alice), "PATCH", &path, Some(perms)).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = call(
        &env,
        Some(&adam),
        "PATCH",
        &path,
        Some(json!({"name": "I"})),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, u) = call(&env, Some(&mia), "PATCH", &path, Some(json!({"name": "I"}))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(u["permissions"]["post"], json!(["admin", "member"]));

    // Invalid patches change nothing.
    for bad in [
        json!({"name": ""}),
        json!({"tier": null}),
        json!({"tier": "x"}),
    ] {
        let (s, _) = call(&env, Some(&alice), "PATCH", &path, Some(bad)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
    }
    let (_, now) = call(&env, Some(&alice), "GET", &path, None).await;
    assert_eq!(now["name"], "I");
}

#[tokio::test]
async fn concurrent_patches_both_land() {
    let env = env().await;
    let alice = local(&env, "alice").await;
    let g = create_group(&env, &alice, group_body("G", "group")).await;
    let path = format!("/api/groups/{}", id(&g));
    let a = call(
        &env,
        Some(&alice),
        "PATCH",
        &path,
        Some(json!({"name": "renamed"})),
    );
    let b = call(
        &env,
        Some(&alice),
        "PATCH",
        &path,
        Some(json!({"description": "described"})),
    );
    let ((sa, _), (sb, _)) = tokio::join!(a, b);
    assert_eq!((sa, sb), (StatusCode::OK, StatusCode::OK));
    let (_, got) = call(&env, Some(&alice), "GET", &path, None).await;
    assert_eq!(got["name"], "renamed");
    assert_eq!(got["description"], "described");
}

#[tokio::test]
async fn only_the_owner_deletes_and_everything_goes_with_the_group() {
    let env = env().await;
    let alice = local(&env, "alice").await;
    let adam = local(&env, "adam").await;
    let g = create_group(&env, &alice, group_body("G", "public")).await;
    let gid = id(&g);
    join(&env, &gid, &adam, "admin").await;
    let c = create_channel(&env, &adam, &gid, json!({"type": "text", "tier": "public"})).await;
    let mut changes = env.state.groups.subscribe_changes();
    let path = format!("/api/groups/{gid}");

    let (s, p) = call(&env, Some(&adam), "DELETE", &path, None).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{p}");
    let (s, _) = call(&env, Some(&alice), "DELETE", &path, None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(
        changes.recv().await.unwrap(),
        AccessChange::Group {
            group_id: gid.clone()
        }
    );
    let (s, _) = call(&env, None, "GET", &path, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = call(&env, Some(&alice), "DELETE", &path, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let store = &env.state.groups.store;
    assert!(store.channel(&gid, &id(&c)).await.unwrap().is_none());
    assert!(store.role_of(&gid, &adam.id()).await.unwrap().is_none());
    assert!(store.deleting(10).await.unwrap().is_empty());
}

#[tokio::test]
async fn channels_are_created_read_updated_and_deleted_by_managers() {
    let env = env().await;
    let alice = local(&env, "alice").await;
    let mia = local(&env, "mia").await;
    let g = create_group(&env, &alice, group_body("G", "public")).await;
    let gid = id(&g);
    join(&env, &gid, &mia, "member").await;
    let base = format!("/api/groups/{gid}/channels");

    let body =
        json!({"name": "general", "type": "text", "tier": "public", "topic": "t", "tags": ["a"]});
    let (s, _) = call(&env, Some(&mia), "POST", &base, Some(body.clone())).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let c = create_channel(&env, &alice, &gid, body).await;
    valid_channel(&c);
    assert!(id(&c).starts_with("chn_"));
    assert_eq!(c["groupId"], gid);
    assert_eq!(
        (c["type"].as_str(), c["tier"].as_str()),
        (Some("text"), Some("public"))
    );
    assert_eq!(c["tags"], json!(["a"]));
    let bare = create_channel(&env, &alice, &gid, json!({"type": "call"})).await;
    valid_channel(&bare);
    assert_eq!(bare["tier"], "private", "the default channel tier");
    assert!(bare.get("name").is_none());

    for bad in [
        json!({}),
        json!({"type": "video"}),
        json!({"type": "text", "permissions": {"replyOnlyTo": ["member"]}}),
    ] {
        let (s, _) = call(&env, Some(&alice), "POST", &base, Some(bad)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
    }

    let path = format!("{base}/{}", id(&c));
    let (s, got) = call(&env, None, "GET", &path, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(got, c);

    let (s, _) = call(
        &env,
        Some(&mia),
        "PATCH",
        &path,
        Some(json!({"topic": "x"})),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = call(
        &env,
        Some(&alice),
        "PATCH",
        &path,
        Some(json!({"type": "call"})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "type is immutable");
    let patch = json!({"type": "text", "topic": "new", "permissions": {"view": ["admin"]}});
    let (s, u) = call(&env, Some(&alice), "PATCH", &path, Some(patch)).await;
    assert_eq!(s, StatusCode::OK, "{u}");
    valid_channel(&u);
    assert_eq!(u["topic"], "new");
    assert_eq!(u["name"], "general");
    assert_eq!(u["permissions"], json!({"view": ["admin"]}));

    let (s, list) = call(&env, Some(&alice), "GET", &base, None).await;
    assert_eq!(s, StatusCode::OK);
    let items = list["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    items.iter().for_each(valid_channel);

    let (s, _) = call(&env, Some(&mia), "DELETE", &path, None).await;
    // `view` now leaves mia out: the channel is hidden from her (§11.3).
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = call(&env, Some(&alice), "DELETE", &path, None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = call(&env, Some(&alice), "GET", &path, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = call(&env, Some(&alice), "DELETE", &path, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn tiers_are_listed_and_advertised() {
    let env = env().await;
    let (s, t) = call(&env, None, "GET", "/api/tiers", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_valid(&schema("tiers-response.json"), &t);
    let ids: Vec<&str> = t["tiers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["private", "group", "public", "discoverable"]);
    let (s, d) = call(&env, None, "GET", "/.well-known/ofscp-provider", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(d["capabilities"]["tiers"], json!(ids));
}
