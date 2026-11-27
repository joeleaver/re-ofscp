//! Group invites (spec §5.6; docs/decisions/0019) on a real
//! rhypedb-server: who may create, list and revoke them, the terms they
//! accept, redeeming them into invite-only and private groups (security
//! requirement 6), remote actors redeeming as themselves and never as a
//! local namesake (requirement 1), expiry, revocation, use limits, and the
//! responses checked against the spec's JSON Schemas.

mod common;

use axum::http::StatusCode;
use common::accounts::{EnvOptions, NOW, env_with};
use common::groups::{
    Env, Party, call, create_channel, create_group, env_with_remotes, id, join, local, remote,
};
use common::harness::{SIGNED_AT, new_key, send, signed, signed_as};
use common::invites::{
    create_invite, create_invite_http, list_invites, redeem, rows_of_group, token, uses,
};
use common::members::{group_with_policy, join_http, leave, roster, set_role};
use common::{assert_valid, schema};
use re_ofscp_server::groups::invites::MAX_INVITES_PER_GROUP;
use re_ofscp_server::signing::{Signer, StaticKeys};
use re_ofscp_types::Authority;
use serde_json::{Value, json};

async fn group(env: &Env, owner: &Party, tier: &str, policy: &str) -> String {
    id(&create_group(env, owner, group_with_policy(tier, policy, json!({}))).await)
}

/// A group with a catalogued `editor` role that alone holds
/// `members.set-nickname`, a permission an `admin` lacks.
async fn editor_group(env: &Env, owner: &Party) -> String {
    let extra = json!({
        "roles": [{"name": "editor"}],
        "permissions": {
            "members.set-nickname": ["editor"],
            "post": ["admin", "member", "editor"]
        }
    });
    id(&create_group(env, owner, group_with_policy("private", "invite", extra)).await)
}

fn has(roster: &[(String, String)], who: &Party, role: &str) -> bool {
    roster.iter().any(|(u, r)| *u == who.actor && r == role)
}

#[tokio::test]
async fn managers_create_list_and_revoke_invites() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let admin = local(&env, "adam").await;
    let plain = local(&env, "pat").await;
    let outsider = local(&env, "olga").await;
    let g = group(&env, &alice, "private", "invite").await;
    join(&env, &g, &admin, "admin").await;
    join(&env, &g, &plain, "member").await;
    let invite_schema = schema("invite.json");
    let created_schema = schema("invite-create-response.json");

    // All fields are optional: the default is a `member` invite. The
    // create's answer carries the token (lost-conn/ofscp#40).
    let (s, inv) = create_invite_http(&env, Some(&admin), &g, json!({})).await;
    assert_eq!(s, StatusCode::CREATED, "{inv}");
    assert_valid(&created_schema, &inv);
    let t = token(&inv);
    assert!(t.starts_with("gi_") && t.len() >= 40, "{t}");
    assert_eq!(
        (
            &inv["groupId"],
            &inv["role"],
            &inv["uses"],
            &inv["createdBy"]
        ),
        (&json!(g), &json!("member"), &json!(0), &json!(admin.actor))
    );
    assert!(inv.get("maxUses").is_none() && inv.get("expiresAt").is_none());
    let limited = create_invite(
        &env,
        &alice,
        &g,
        json!({"maxUses": 3, "expiresAt": "2026-01-02T12:00:00Z", "role": "admin"}),
    )
    .await;
    assert_valid(&created_schema, &limited);
    assert_ne!(token(&limited), t, "every invite has its own token");

    // Only managers.
    for who in [&plain, &outsider] {
        let (s, _) = create_invite_http(&env, Some(who), &g, json!({})).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        let (s, _) = list_invites(&env, Some(who), &g, "").await;
        assert_eq!(s, StatusCode::FORBIDDEN);
    }
    let (s, _) = create_invite_http(&env, Some(&alice), "grp_missing", json!({})).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // The list never carries tokens (only their digests are stored), which
    // §5.6 allows (lost-conn/ofscp#40): each item is a valid `Invite` as it
    // is. Newest first; paged per §7.2.
    let (s, list) = list_invites(&env, Some(&admin), &g, "").await;
    assert_eq!(s, StatusCode::OK, "{list}");
    let items = list["items"].as_array().unwrap();
    assert_eq!(items.len(), 2, "{list}");
    assert!(!list.to_string().contains(&t), "a token leaked: {list}");
    for item in items {
        assert!(item.get("token").is_none(), "{item}");
        assert_valid(&invite_schema, item);
    }
    let (_, first) = list_invites(&env, Some(&admin), &g, "?limit=1").await;
    assert_eq!(first["items"].as_array().unwrap().len(), 1);
    let cursor = first["page"]["nextCursor"].as_str().unwrap().to_owned();
    let (_, second) =
        list_invites(&env, Some(&admin), &g, &format!("?limit=1&cursor={cursor}")).await;
    assert_eq!(second["items"].as_array().unwrap().len(), 1);
    assert_ne!(first["items"][0]["id"], second["items"][0]["id"]);

    // Revoking: managers only; unknown is `404`; a revoked token is gone.
    let iid = id(&inv);
    let path = format!("/api/groups/{g}/invites/{iid}");
    let (s, _) = call(&env, Some(&plain), "DELETE", &path, None).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = call(&env, Some(&admin), "DELETE", &path, None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = call(&env, Some(&admin), "DELETE", &path, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = redeem(&env, Some(&outsider), &t).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // Another group's invite is not this group's.
    let other = group(&env, &alice, "group", "open").await;
    let lid = id(&limited);
    let path = format!("/api/groups/{other}/invites/{lid}");
    let (s, _) = call(&env, Some(&alice), "DELETE", &path, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn invite_terms_are_validated() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let g = editor_group(&env, &alice).await;
    let c = id(&create_channel(&env, &alice, &g, json!({"type": "text"})).await);
    let refused = [
        json!({"role": "owner"}),
        json!({"role": "wizard"}),
        json!({"channelId": "chn_missing"}),
        json!({"grantsGuest": true}),
        json!({"maxUses": 0}),
        json!({"maxUses": 1001}),
        json!({"maxUses": -1}),
        json!({"expiresAt": "2025-12-31T12:00:00Z"}),
        json!({"expiresAt": NOW}),
        json!({"expiresAt": "2027-06-01T00:00:00Z"}),
        json!({"expiresAt": "tomorrow"}),
        json!({"role": 7}),
    ];
    for body in refused {
        let (s, p) = create_invite_http(&env, Some(&alice), &g, body.clone()).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{body}: {p}");
    }
    let (_, p) = create_invite_http(&env, Some(&alice), &g, json!({"grantsGuest": true})).await;
    assert!(
        p["detail"].as_str().unwrap().contains("guest"),
        "the problem says guests are unsupported: {p}"
    );
    // A catalogued role, a channel of the group, and `grantsGuest: false`.
    let inv = create_invite(
        &env,
        &alice,
        &g,
        json!({"role": "editor", "channelId": c, "grantsGuest": false, "maxUses": 1000}),
    )
    .await;
    assert_valid(&schema("invite-create-response.json"), &inv);
    assert_eq!(
        (&inv["role"], &inv["channelId"]),
        (&json!("editor"), &json!(c))
    );
    // A channel of another group is not one of this group's.
    let other = group(&env, &alice, "group", "open").await;
    let oc = id(&create_channel(&env, &alice, &other, json!({"type": "text"})).await);
    let (s, _) = create_invite_http(&env, Some(&alice), &g, json!({"channelId": oc})).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn the_subset_rule_binds_the_invites_role() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let admin = local(&env, "adam").await;
    let g = editor_group(&env, &alice).await;
    join(&env, &g, &admin, "admin").await;
    // `editor` holds `members.set-nickname`, which `admin` lacks.
    let (s, p) = create_invite_http(&env, Some(&admin), &g, json!({"role": "editor"})).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{p}");
    for role in ["admin", "member", "guest"] {
        let (s, p) = create_invite_http(&env, Some(&admin), &g, json!({"role": role})).await;
        assert_eq!(s, StatusCode::CREATED, "{role}: {p}");
    }
    // The owner holds everything.
    create_invite(&env, &alice, &g, json!({"role": "editor"})).await;
}

#[tokio::test]
async fn an_invite_admits_to_private_and_invite_only_groups() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    for (tier, policy) in [
        ("private", "invite"),
        ("private", "open"),
        ("public", "invite"),
    ] {
        let g = group(&env, &alice, tier, policy).await;
        let (s, _) = join_http(&env, &bob, &g, None).await;
        assert_eq!(
            s,
            StatusCode::FORBIDDEN,
            "{tier}/{policy}: no join without an invite"
        );
        let inv = create_invite(&env, &alice, &g, json!({})).await;
        let (s, r) = redeem(&env, Some(&bob), &token(&inv)).await;
        assert_eq!(s, StatusCode::OK, "{tier}/{policy}: {r}");
        assert_eq!(r, json!({"groupId": g, "role": "member"}));
        assert!(has(&roster(&env, &alice, &g).await, &bob, "member"));
        assert_eq!(uses(&env, &alice, &g, &id(&inv)).await, 1);
    }
}

#[tokio::test]
async fn a_remote_actor_redeems_as_themselves_not_as_a_local_namesake() {
    let remote_alice = remote("alice", "providerb.example");
    let env = env_with_remotes(&[&remote_alice]).await;
    let owner = local(&env, "olive").await;
    let alice = local(&env, "alice").await;
    let g = group(&env, &owner, "private", "invite").await;
    let inv = create_invite(&env, &owner, &g, json!({"maxUses": 2, "role": "admin"})).await;
    let t = token(&inv);

    let (s, r) = redeem(&env, Some(&remote_alice), &t).await;
    assert_eq!(s, StatusCode::OK, "{r}");
    assert_eq!(r["role"], json!("admin"));
    let list = roster(&env, &owner, &g).await;
    assert!(has(&list, &remote_alice, "admin"), "{list:?}");
    assert!(!list.iter().any(|(u, _)| *u == alice.actor), "{list:?}");

    // Local alice is someone else: she is not a member, and takes the
    // second use.
    let (s, r) = redeem(&env, Some(&alice), &t).await;
    assert_eq!(s, StatusCode::OK, "{r}");
    let list = roster(&env, &owner, &g).await;
    assert!(has(&list, &alice, "admin") && has(&list, &remote_alice, "admin"));
    assert_eq!(uses(&env, &owner, &g, &id(&inv)).await, 2);
    // Used up now: `409` for the members too (lost-conn/ofscp#35).
    let (s, _) = redeem(&env, Some(&remote_alice), &t).await;
    assert_eq!(s, StatusCode::CONFLICT);
    let carol = local(&env, "carol").await;
    let (s, _) = redeem(&env, Some(&carol), &t).await;
    assert_eq!(s, StatusCode::CONFLICT);
}

#[tokio::test]
async fn members_redeeming_keep_their_role_and_use_nothing() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let admin = local(&env, "adam").await;
    let g = group(&env, &alice, "private", "invite").await;
    join(&env, &g, &admin, "admin").await;
    let inv = create_invite(&env, &alice, &g, json!({"maxUses": 1})).await;
    let t = token(&inv);
    let (s, r) = redeem(&env, Some(&alice), &t).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(r, json!({"groupId": g, "role": "owner"}));
    let (s, r) = redeem(&env, Some(&admin), &t).await;
    assert_eq!((s, &r["role"]), (StatusCode::OK, &json!("admin")));
    assert!(has(&roster(&env, &alice, &g).await, &admin, "admin"));
    assert_eq!(uses(&env, &alice, &g, &id(&inv)).await, 0);
}

#[tokio::test]
async fn an_exhausted_invite_is_a_conflict_and_a_use_stays_used() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let carol = local(&env, "carol").await;
    let g = group(&env, &alice, "private", "invite").await;
    let inv = create_invite(&env, &alice, &g, json!({"maxUses": 1})).await;
    let t = token(&inv);
    assert_eq!(redeem(&env, Some(&bob), &t).await.0, StatusCode::OK);
    let (s, p) = redeem(&env, Some(&carol), &t).await;
    assert_eq!(s, StatusCode::CONFLICT, "{p}");
    // Leaving does not hand the use back.
    assert_eq!(leave(&env, &bob, &g).await, StatusCode::NO_CONTENT);
    assert_eq!(redeem(&env, Some(&bob), &t).await.0, StatusCode::CONFLICT);
    assert_eq!(uses(&env, &alice, &g, &id(&inv)).await, 1);
}

/// §5.6 (lost-conn/ofscp#35): the invite is checked before the caller's
/// membership, so members and the owner get the invite's `404` or `409`
/// rather than their membership.
#[tokio::test]
async fn the_invite_is_checked_before_the_callers_membership() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let g = group(&env, &alice, "private", "invite").await;

    // Used up: `409` for the member who used it and for the owner.
    let used = token(&create_invite(&env, &alice, &g, json!({"maxUses": 1})).await);
    assert_eq!(redeem(&env, Some(&bob), &used).await.0, StatusCode::OK);
    for who in [&bob, &alice] {
        let (s, p) = redeem(&env, Some(who), &used).await;
        assert_eq!(s, StatusCode::CONFLICT, "{}: {p}", who.actor);
    }

    // Revoked: `404` for both.
    let revoked = create_invite(&env, &alice, &g, json!({})).await;
    let path = format!("/api/groups/{g}/invites/{}", id(&revoked));
    let (s, _) = call(&env, Some(&alice), "DELETE", &path, None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    for who in [&bob, &alice] {
        let (s, _) = redeem(&env, Some(who), &token(&revoked)).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{}", who.actor);
    }

    // Expired: `404` for both.
    let soon = create_invite(
        &env,
        &alice,
        &g,
        json!({"expiresAt": "2026-01-01T12:01:00Z"}),
    )
    .await;
    let later = "2026-01-01T12:02:00Z";
    env.clock.set(SIGNED_AT + time::Duration::minutes(2));
    let path = format!("/api/invites/{}/redeem", token(&soon));
    for who in [&bob, &alice] {
        let (s, _, _, _) = send(&env.app, signed_at(who, "POST", &path, later)).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{}", who.actor);
    }
    // Roles are untouched throughout.
    let list = roster(&env, &alice, &g).await;
    assert!(
        has(&list, &alice, "owner") && has(&list, &bob, "member"),
        "{list:?}"
    );
}

/// A request to `path` signed by `by` at `at` (RFC 3339).
fn signed_at(
    by: &Party,
    method: &str,
    path: &str,
    at: &str,
) -> axum::http::Request<axum::body::Body> {
    signed(&by.key, &by.actor, &by.key_id, method, path, "{}", at)
}

#[tokio::test]
async fn an_expired_invite_is_not_found_and_swept() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let g = group(&env, &alice, "private", "invite").await;
    let soon = create_invite(
        &env,
        &alice,
        &g,
        json!({"expiresAt": "2026-01-01T12:01:00Z"}),
    )
    .await;
    let never = create_invite(&env, &alice, &g, json!({})).await;
    assert_eq!(rows_of_group(&env, "GroupInvite", &g).await, 2);

    let later = "2026-01-01T12:02:00Z";
    env.clock.set(SIGNED_AT + time::Duration::minutes(2));
    let path = format!("/api/invites/{}/redeem", token(&soon));
    let (s, _, _, _) = send(&env.app, signed_at(&bob, "POST", &path, later)).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // Expired invites are not listed, and the sweeper deletes them only.
    let list_path = format!("/api/groups/{g}/invites");
    let (s, list, _, _) = send(&env.app, signed_at(&alice, "GET", &list_path, later)).await;
    assert_eq!(s, StatusCode::OK, "{list}");
    assert_eq!(list["items"].as_array().unwrap().len(), 1, "{list}");
    assert_eq!(list["items"][0]["id"], never["id"]);
    let now = (SIGNED_AT + time::Duration::minutes(2)).unix_timestamp();
    env.state.groups.sweep(now).await.unwrap();
    assert_eq!(rows_of_group(&env, "GroupInvite", &g).await, 1);
    let path = format!("/api/invites/{}/redeem", token(&never));
    let (s, _, _, _) = send(&env.app, signed_at(&bob, "POST", &path, later)).await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn an_invite_outranking_its_creator_stops_granting() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let admin = local(&env, "adam").await;
    let bob = local(&env, "bob").await;
    let g = group(&env, &alice, "private", "invite").await;
    join(&env, &g, &admin, "admin").await;
    let inv = create_invite(&env, &admin, &g, json!({"role": "admin"})).await;
    let (s, _) = set_role(&env, &alice, &g, &admin.actor, "member").await;
    assert_eq!(s, StatusCode::OK);
    let (s, p) = redeem(&env, Some(&bob), &token(&inv)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{p}");
    assert!(
        !roster(&env, &alice, &g)
            .await
            .iter()
            .any(|(u, _)| *u == bob.actor)
    );
    // Restored, the invite grants again.
    set_role(&env, &alice, &g, &admin.actor, "admin").await;
    assert_eq!(
        redeem(&env, Some(&bob), &token(&inv)).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn the_redeem_answer_names_the_invites_channel() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let carol = local(&env, "carol").await;
    let g = group(&env, &alice, "private", "invite").await;
    let c = id(&create_channel(&env, &alice, &g, json!({"type": "text"})).await);
    let inv = create_invite(&env, &alice, &g, json!({"channelId": c})).await;
    let (s, r) = redeem(&env, Some(&bob), &token(&inv)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(r, json!({"groupId": g, "channelId": c, "role": "member"}));
    let path = format!("/api/groups/{g}/channels/{c}");
    assert_eq!(
        call(&env, Some(&alice), "DELETE", &path, None).await.0,
        StatusCode::NO_CONTENT
    );
    // A deleted channel does not void the invite: the caller still joins
    // the group, and the answer omits `channelId` (§5.6,
    // lost-conn/ofscp#40).
    let (s, r) = redeem(&env, Some(&carol), &token(&inv)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(r, json!({"groupId": g, "role": "member"}));
    assert!(has(&roster(&env, &alice, &g).await, &carol, "member"));
    // So does the already-a-member answer.
    let (s, r) = redeem(&env, Some(&alice), &token(&inv)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(r, json!({"groupId": g, "role": "owner"}));
}

#[tokio::test]
async fn a_deleted_groups_invites_go_with_it() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let carol = local(&env, "carol").await;
    let g = group(&env, &alice, "private", "invite").await;
    let inv = create_invite(&env, &alice, &g, json!({"maxUses": 5})).await;
    assert_eq!(
        redeem(&env, Some(&bob), &token(&inv)).await.0,
        StatusCode::OK
    );
    assert_eq!(rows_of_group(&env, "GroupInviteUse", &g).await, 1);
    // As if the process died between marking the group and purging it.
    assert!(env.state.groups.store.mark_deleting(&g).await.unwrap());
    assert_eq!(
        redeem(&env, Some(&carol), &token(&inv)).await.0,
        StatusCode::NOT_FOUND
    );
    env.state
        .groups
        .sweep(SIGNED_AT.unix_timestamp())
        .await
        .unwrap();
    assert_eq!(rows_of_group(&env, "GroupInvite", &g).await, 0);
    assert_eq!(rows_of_group(&env, "GroupInviteUse", &g).await, 0);
    assert_eq!(
        redeem(&env, Some(&carol), &token(&inv)).await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn a_group_holds_a_bounded_number_of_invites() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let g = group(&env, &alice, "private", "invite").await;
    let mut last = Value::Null;
    for _ in 0..MAX_INVITES_PER_GROUP {
        last = create_invite(&env, &alice, &g, json!({})).await;
    }
    let (s, _) = create_invite_http(&env, Some(&alice), &g, json!({})).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let path = format!("/api/groups/{g}/invites/{}", id(&last));
    assert_eq!(
        call(&env, Some(&alice), "DELETE", &path, None).await.0,
        StatusCode::NO_CONTENT
    );
    create_invite(&env, &alice, &g, json!({})).await;
}

#[tokio::test]
async fn tokens_and_signatures_are_checked() {
    let provider_key = new_key();
    let authority = Authority::parse_canonical("providerb.example").unwrap();
    let keys = StaticKeys::default().with(
        Signer::Provider(authority),
        "pk_1",
        provider_key.verifying_key(),
    );
    let env = env_with(EnvOptions {
        remote: Some(keys),
        ..Default::default()
    })
    .await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let g = group(&env, &alice, "private", "invite").await;
    let t = token(&create_invite(&env, &alice, &g, json!({})).await);

    for bad in ["gi_nope", "ai_account", "x"] {
        assert_eq!(
            redeem(&env, Some(&bob), bad).await.0,
            StatusCode::NOT_FOUND,
            "{bad}"
        );
    }
    let long = format!("gi_{}", "a".repeat(300));
    assert_eq!(
        redeem(&env, Some(&bob), &long).await.0,
        StatusCode::NOT_FOUND
    );

    let paths = [
        ("POST", format!("/api/invites/{t}/redeem")),
        ("POST", format!("/api/groups/{g}/invites")),
        ("GET", format!("/api/groups/{g}/invites")),
        ("DELETE", format!("/api/groups/{g}/invites/inv_x")),
    ];
    for (method, path) in &paths {
        let (s, _) = call(&env, None, method, path, Some(json!({}))).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "unsigned {method} {path}");
        let req = signed_as(
            &provider_key,
            ("x-ofscp-provider", "providerb.example"),
            "pk_1",
            method,
            path,
            "",
            NOW,
        );
        let (s, _, _, _) = send(&env.app, req).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "provider-signed {method} {path}");
    }
    assert!(
        !roster(&env, &alice, &g)
            .await
            .iter()
            .any(|(u, _)| *u == bob.actor)
    );
}

#[tokio::test]
async fn guest_redemption_is_unsupported() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let g = group(&env, &alice, "private", "invite").await;
    let t = token(&create_invite(&env, &alice, &g, json!({})).await);
    let body = json!({"displayName": "Guest Ada", "public_key": "AAAA", "algorithm": "Ed25519"});
    let path = format!("/api/invites/{t}/guest");
    let (s, p) = call(&env, None, "POST", &path, Some(body.clone())).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{p}");
    assert!(p["detail"].as_str().unwrap().contains("guest"), "{p}");
    let (s, _) = call(&env, Some(&alice), "POST", &path, Some(body)).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = call(&env, None, "POST", "/api/invites/gi_unknown/guest", None).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}
