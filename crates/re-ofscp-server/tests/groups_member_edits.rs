//! Role changes, kicks and nicknames (spec §5.7) on a real rhypedb-server:
//! the subset rule on both the current and the requested role, the owner
//! never a membership row, and authorization before body validation
//! (decision 0014). Ownership transfer is in tests/groups_transfer.rs.

mod common;

use axum::http::StatusCode;
use common::groups::{Env, Party, call, create_group, env_with_remotes, id, join, local, remote};
use common::members::{group_with_policy, kick, nickname, roster, set_role};
use common::{assert_valid, schema};
use serde_json::json;

/// A group owned by `owner` with a catalogued `editor` role that posts and
/// alone holds `members.set-nickname`: a permission an `admin` lacks.
async fn editor_group(env: &Env, owner: &Party) -> String {
    let extra = json!({
        "roles": [{"name": "editor"}],
        "permissions": {
            "members.set-nickname": ["editor"],
            "post": ["admin", "member", "editor"]
        }
    });
    id(&create_group(env, owner, group_with_policy("group", "open", extra)).await)
}

#[tokio::test]
async fn managers_change_roles_within_the_subset_rule() {
    let bob = remote("bob", "providerb.example");
    let env = env_with_remotes(&[&bob]).await;
    let alice = local(&env, "alice").await;
    let carol = local(&env, "carol").await;
    let dave = local(&env, "dave").await;
    let g = editor_group(&env, &alice).await;
    join(&env, &g, &bob, "member").await;
    join(&env, &g, &carol, "editor").await;
    join(&env, &g, &dave, "member").await;
    let member = schema("member.json");

    // A plain member has no `manage`.
    let (s, _) = set_role(&env, &dave, &g, &bob.actor, "admin").await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // The owner holds everything.
    let (s, m) = set_role(&env, &alice, &g, &bob.actor, "admin").await;
    assert_eq!(s, StatusCode::OK, "{m}");
    assert_valid(&member, &m);
    assert_eq!(
        (&m["user"], &m["role"]),
        (&json!(bob.actor), &json!("admin"))
    );

    // Remote admin bob may not demote an editor (current role), nor make
    // anyone an editor (requested role): editors hold a permission he
    // does not.
    let (s, p) = set_role(&env, &bob, &g, "carol", "member").await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{p}");
    let (s, _) = set_role(&env, &bob, &g, "dave", "editor").await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // But he may make dave a guest and back.
    let (s, _) = set_role(&env, &bob, &g, "dave", "guest").await;
    assert_eq!(s, StatusCode::OK);
    let (s, m) = set_role(&env, &bob, &g, "dave", "guest").await;
    assert_eq!(
        (s, &m["role"]),
        (StatusCode::OK, &json!("guest")),
        "unchanged"
    );

    // Roles must exist; targets must be members.
    let (s, _) = set_role(&env, &alice, &g, "dave", "wizard").await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = set_role(&env, &alice, &g, "nobody", "member").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = set_role(&env, &alice, &g, "Not_A_Ref", "member").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let path = format!("/api/groups/{g}/members/dave");
    let (s, _) = call(&env, Some(&alice), "PATCH", &path, Some(json!({}))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // Nobody demotes the owner: the owner gets 409, others 403.
    let (s, _) = set_role(&env, &alice, &g, "alice", "admin").await;
    assert_eq!(s, StatusCode::CONFLICT);
    let (s, _) = set_role(&env, &bob, &g, "alice", "member").await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn moderators_kick_within_the_subset_rule_and_never_the_owner() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let carol = local(&env, "carol").await;
    let dave = local(&env, "dave").await;
    let g = editor_group(&env, &alice).await;
    join(&env, &g, &bob, "admin").await;
    join(&env, &g, &carol, "editor").await;
    join(&env, &g, &dave, "member").await;

    assert_eq!(kick(&env, &dave, &g, "carol").await, StatusCode::FORBIDDEN);
    assert_eq!(kick(&env, &bob, &g, "alice").await, StatusCode::FORBIDDEN);
    assert_eq!(
        kick(&env, &bob, &g, "carol").await,
        StatusCode::FORBIDDEN,
        "subset rule"
    );
    assert_eq!(kick(&env, &bob, &g, "nobody").await, StatusCode::NOT_FOUND);
    assert_eq!(kick(&env, &bob, &g, "dave").await, StatusCode::NO_CONTENT);
    assert_eq!(
        kick(&env, &alice, &g, "carol").await,
        StatusCode::NO_CONTENT
    );
    let left: Vec<String> = roster(&env, &alice, &g)
        .await
        .into_iter()
        .map(|(u, _)| u)
        .collect();
    assert_eq!(left.len(), 2);
    assert!(left.contains(&alice.actor) && left.contains(&bob.actor));
}

#[tokio::test]
async fn nicknames_are_trimmed_bounded_and_need_permission_for_others() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let carol = local(&env, "carol").await;
    let ed = local(&env, "eddie").await;
    let g = editor_group(&env, &alice).await;
    join(&env, &g, &bob, "admin").await;
    join(&env, &g, &carol, "member").await;
    join(&env, &g, &ed, "editor").await;
    let member = schema("member.json");

    let (s, m) = nickname(
        &env,
        &carol,
        &g,
        "carol",
        json!({"displayNameOverride": "  Cee  "}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{m}");
    assert_valid(&member, &m);
    assert_eq!(m["displayNameOverride"], "Cee");
    let long = "n".repeat(65);
    let (s, _) = nickname(
        &env,
        &carol,
        &g,
        "carol",
        json!({"displayNameOverride": long}),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = nickname(&env, &carol, &g, "carol", json!({})).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "the field is required");
    for clear in [json!(null), json!(""), json!("   ")] {
        let (s, m) = nickname(
            &env,
            &carol,
            &g,
            "carol",
            json!({"displayNameOverride": clear}),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        assert!(m.get("displayNameOverride").is_none(), "{m}");
    }

    // Another's needs `members.set-nickname`: admin bob lacks it.
    let body = json!({"displayNameOverride": "C"});
    let (s, _) = nickname(&env, &bob, &g, "carol", body.clone()).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // Editor ed holds it, but the subset rule keeps him off admin bob.
    let (s, _) = nickname(&env, &ed, &g, "carol", body.clone()).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = nickname(&env, &ed, &g, "bob", body.clone()).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = nickname(&env, &ed, &g, "alice", body.clone()).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "nobody outranks the owner");
    let (s, _) = nickname(&env, &ed, &g, "nobody", body.clone()).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // An outsider has no nickname to set.
    let olga = local(&env, "olga").await;
    let (s, _) = nickname(&env, &olga, &g, "olga", body.clone()).await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // The owner has one too, on the group, and shows it in the list.
    let (s, m) = nickname(
        &env,
        &alice,
        &g,
        "alice",
        json!({"displayNameOverride": "Boss"}),
    )
    .await;
    assert_eq!((s, &m["role"]), (StatusCode::OK, &json!("owner")), "{m}");
    let (_, page) = common::members::members(&env, Some(&carol), &g, "").await;
    let owner = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["role"] == "owner")
        .cloned()
        .unwrap();
    assert_eq!(owner["displayNameOverride"], "Boss");
}

#[tokio::test]
async fn a_caller_without_permission_is_refused_whatever_the_body() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let pat = local(&env, "pat").await;
    let olga = local(&env, "olga").await;
    let g = editor_group(&env, &alice).await;
    join(&env, &g, &pat, "member").await;
    let role = format!("/api/groups/{g}/members/alice");
    let nick = format!("/api/groups/{g}/members/alice/display-name");
    for body in [json!({}), json!({"role": 7}), json!("nonsense")] {
        // A plain member lacks `manage` and `members.set-nickname`.
        let (s, p) = call(&env, Some(&pat), "PATCH", &role, Some(body.clone())).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{p}");
        let (s, p) = call(&env, Some(&pat), "PATCH", &nick, Some(body.clone())).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{p}");
        // An outsider is not a member at all.
        let (s, p) = call(&env, Some(&olga), "PATCH", &nick, Some(body)).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{p}");
    }
    // Once authorized, the same bodies are `400`.
    let (s, _) = call(
        &env,
        Some(&alice),
        "PATCH",
        &format!("/api/groups/{g}/members/pat"),
        Some(json!({})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = call(&env, Some(&alice), "PATCH", &nick, Some(json!({}))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // A join to an invite-only group is refused before its body is read.
    let inv = id(&create_group(
        &env,
        &alice,
        group_with_policy("group", "invite", json!({})),
    )
    .await);
    let (s, p) = call(
        &env,
        Some(&olga),
        "POST",
        &format!("/api/groups/{inv}/join"),
        Some(json!("nonsense")),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{p}");
}
