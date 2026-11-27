//! Joining, leaving, join requests and the member list (spec §5.7, §7.2,
//! §8.2) on a real rhypedb-server: each `joinPolicy`, private groups being
//! invite-only (security requirement 6), remote actors acting exactly as
//! local ones and never mistaken for them (requirement 1), and every
//! response checked against the spec's JSON Schemas.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::accounts::{EnvOptions, NOW, env_with};
use common::groups::{
    Env, Party, call, create_group, env_with_remotes, id, local, remote, request,
};
use common::harness::{SIGNED_AT, new_key, send, signed_as};
use common::members::{group_with_policy, join_http, leave, members, roster};
use common::{assert_valid, schema};
use re_ofscp_server::db::Ql;
use re_ofscp_server::groups::PENDING_TTL;
use re_ofscp_server::signing::{Signer, StaticKeys};
use re_ofscp_types::Authority;
use serde_json::{Value, json};
use tower::ServiceExt as _;

async fn group(env: &Env, owner: &Party, tier: &str, policy: &str) -> String {
    id(&create_group(env, owner, group_with_policy(tier, policy, json!({}))).await)
}

#[tokio::test]
async fn an_open_group_admits_at_once_and_joining_again_is_idempotent() {
    let bob = remote("bob", "providerb.example");
    let env = env_with_remotes(&[&bob]).await;
    let alice = local(&env, "alice").await;
    let g = group(&env, &alice, "group", "open").await;
    let member = schema("member.json");

    let (s, m) = join_http(&env, &bob, &g, None).await;
    assert_eq!(s, StatusCode::CREATED, "{m}");
    assert_valid(&member, &m);
    assert_eq!(
        (&m["user"], &m["role"]),
        (&json!(bob.actor), &json!("member"))
    );
    let (s, again) = join_http(&env, &bob, &g, None).await;
    assert_eq!(s, StatusCode::OK, "{again}");
    assert_eq!(again, m);

    // The owner is a member already.
    let (s, o) = join_http(&env, &alice, &g, None).await;
    assert_eq!(s, StatusCode::OK, "{o}");
    assert_eq!(
        (&o["user"], &o["role"]),
        (&json!(alice.actor), &json!("owner"))
    );
    assert_valid(&member, &o);

    // §8.2: the channel alias joins the group, whatever the channel.
    let carol = local(&env, "carol").await;
    let path = format!("/api/groups/{g}/channels/ch_nonexistent/join");
    let (s, c) = call(&env, Some(&carol), "POST", &path, None).await;
    assert_eq!(s, StatusCode::CREATED, "{c}");
    assert_eq!(c["user"], json!(carol.actor));
}

#[tokio::test]
async fn invite_policy_and_private_groups_refuse_joins() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    for (tier, policy) in [
        ("public", "invite"),
        ("private", "open"),
        ("private", "request"),
        ("private", "invite"),
    ] {
        let g = group(&env, &alice, tier, policy).await;
        let (s, p) = join_http(&env, &bob, &g, None).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{tier}/{policy}: {p}");
        let path = format!("/api/groups/{g}/channels/any/join");
        let (s, _) = call(&env, Some(&bob), "POST", &path, None).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{tier}/{policy} via a channel");
    }
    let (s, _) = join_http(&env, &bob, "grp_missing", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_request_group_records_one_pending_request_per_actor() {
    let bob = remote("bob", "providerb.example");
    let env = env_with_remotes(&[&bob]).await;
    let alice = local(&env, "alice").await;
    let mod_ = local(&env, "moira").await;
    let plain = local(&env, "pat").await;
    let g = group(&env, &alice, "public", "request").await;
    common::groups::join(&env, &g, &mod_, "admin").await;
    common::groups::join(&env, &g, &plain, "member").await;
    let jr = schema("join-request.json");

    let (s, r) = join_http(&env, &bob, &g, Some(json!({"message": "hi"}))).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{r}");
    assert_valid(&jr, &r);
    assert_eq!(
        (&r["user"], &r["state"], &r["message"]),
        (&json!(bob.actor), &json!("pending"), &json!("hi"))
    );
    // Asking again answers the same request.
    let (s, again) = join_http(&env, &bob, &g, None).await;
    assert_eq!(s, StatusCode::ACCEPTED);
    assert_eq!(again["id"], r["id"]);
    // An over-long message is refused.
    let carl = local(&env, "carl").await;
    let long = "x".repeat(501);
    let (s, _) = join_http(&env, &carl, &g, Some(json!({"message": long}))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // Reviewers list it; plain members may not.
    let path = format!("/api/groups/{g}/requests");
    let (s, list) = call(&env, Some(&mod_), "GET", &path, None).await;
    assert_eq!(s, StatusCode::OK, "{list}");
    assert_eq!(list["items"].as_array().unwrap().len(), 1, "{list}");
    assert_valid(&jr, &list["items"][0]);
    assert!(list["page"].get("nextCursor").is_none(), "{list}");
    let (s, _) = call(&env, Some(&plain), "GET", &path, None).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = call(&env, None, "GET", &path, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // Approval makes a `member`; the request is gone after.
    let rid = id(&r);
    let approve = format!("/api/groups/{g}/requests/{rid}/approve");
    let (s, _) = call(&env, Some(&plain), "POST", &approve, None).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, m) = call(&env, Some(&mod_), "POST", &approve, None).await;
    assert_eq!(s, StatusCode::OK, "{m}");
    assert_valid(&schema("member.json"), &m);
    assert_eq!(
        (&m["user"], &m["role"]),
        (&json!(bob.actor), &json!("member"))
    );
    let (s, _) = call(&env, Some(&mod_), "POST", &approve, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, already) = join_http(&env, &bob, &g, None).await;
    assert_eq!(s, StatusCode::OK, "{already}");
}

#[tokio::test]
async fn a_denied_requester_may_ask_again() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let g = group(&env, &alice, "group", "request").await;
    let (_, first) = join_http(&env, &bob, &g, None).await;
    let deny = format!("/api/groups/{g}/requests/{}/deny", id(&first));
    let (s, _) = call(&env, Some(&alice), "POST", &deny, None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = call(&env, Some(&alice), "POST", &deny, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, second) = join_http(&env, &bob, &g, None).await;
    assert_eq!(s, StatusCode::ACCEPTED);
    assert_ne!(second["id"], first["id"]);
    // A request id of another group names nothing here.
    let other = group(&env, &alice, "group", "request").await;
    let path = format!("/api/groups/{other}/requests/{}/approve", id(&second));
    let (s, _) = call(&env, Some(&alice), "POST", &path, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn leaving_ends_a_membership_but_the_owner_must_transfer_first() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let g = group(&env, &alice, "group", "open").await;
    join_http(&env, &bob, &g, None).await;
    assert_eq!(leave(&env, &bob, &g).await, StatusCode::NO_CONTENT);
    assert_eq!(leave(&env, &bob, &g).await, StatusCode::NOT_FOUND);
    assert_eq!(leave(&env, &alice, &g).await, StatusCode::CONFLICT);
    assert_eq!(roster(&env, &alice, &g).await.len(), 1);
}

#[tokio::test]
async fn mutations_need_a_user_signature() {
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
    let g = group(&env, &alice, "public", "open").await;
    let paths = [
        ("POST", format!("/api/groups/{g}/join")),
        ("POST", format!("/api/groups/{g}/leave")),
        ("GET", format!("/api/groups/{g}/members")),
        ("GET", format!("/api/groups/{g}/requests")),
        ("DELETE", format!("/api/groups/{g}/members/alice")),
    ];
    for (method, path) in &paths {
        let (s, _) = call(&env, None, method, path, None).await;
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
}

#[tokio::test]
async fn the_member_list_is_for_members_and_includes_the_owner() {
    let bob = remote("bob", "providerb.example");
    let env = env_with_remotes(&[&bob]).await;
    let alice = local(&env, "alice").await;
    let g = group(&env, &alice, "public", "open").await;
    let outsider = local(&env, "olga").await;
    let (s, _) = members(&env, Some(&outsider), &g, "").await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "even a public group's list is members-only"
    );
    let (s, _) = members(&env, None, &g, "").await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = members(&env, Some(&alice), "grp_missing", "").await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    join_http(&env, &bob, &g, None).await;
    let (s, page) = members(&env, Some(&bob), &g, "").await;
    assert_eq!(s, StatusCode::OK, "{page}");
    let member = schema("member.json");
    for m in page["items"].as_array().unwrap() {
        assert_valid(&member, m);
    }
    let created = create_group_created_at(&env, &alice, &g).await;
    let owner = &page["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["role"] == "owner")
        .cloned()
        .unwrap();
    assert_eq!(owner["user"], json!(alice.actor));
    assert_eq!(
        owner["joinedAt"], created,
        "the owner joined when the group was made"
    );
    let (s, _) = members(&env, Some(&bob), &g, "?cursor=bm90LWEtY3Vyc29y").await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

async fn create_group_created_at(env: &Env, by: &Party, g: &str) -> Value {
    let (_, group) = call(env, Some(by), "GET", &format!("/api/groups/{g}"), None).await;
    group["createdAt"].clone()
}

#[tokio::test]
async fn the_member_list_pages_through_opaque_cursors() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let g = group(&env, &alice, "group", "open").await;
    let mut everyone = vec![alice.actor.clone()];
    for h in ["bob", "carol", "dave", "erin"] {
        let p = local(&env, h).await;
        join_http(&env, &p, &g, None).await;
        everyone.push(p.actor.clone());
    }
    // Backward (the default) walks (joinedAt, user) newest first, two at a
    // time, each page continuing from the last one's nextCursor.
    let mut walked = Vec::new();
    let mut query = "?limit=2".to_owned();
    let mut pages = 0;
    loop {
        let (s, page) = members(&env, Some(&alice), &g, &query).await;
        assert_eq!(s, StatusCode::OK, "{page}");
        pages += 1;
        let items = page["items"].as_array().unwrap();
        assert!(items.len() <= 2);
        walked.extend(items.iter().map(|m| m["user"].as_str().unwrap().to_owned()));
        if pages > 1 {
            let prev = page["page"]["prevCursor"].as_str().unwrap();
            assert!(!prev.contains('@'), "cursors are opaque");
        }
        match page["page"]["nextCursor"].as_str() {
            Some(next) => query = format!("?limit=2&cursor={next}"),
            None => break,
        }
    }
    assert_eq!(pages, 3);
    let mut sorted = walked.clone();
    sorted.sort();
    let mut all = everyone.clone();
    all.sort();
    assert_eq!(sorted, all, "every member exactly once");
    // Forward walks the other way.
    let (_, fwd) = members(&env, Some(&alice), &g, "?direction=forward&limit=100").await;
    let fwd: Vec<String> = fwd["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["user"].as_str().unwrap().to_owned())
        .collect();
    let mut back = walked;
    back.reverse();
    // Forward is the same order reversed: oldest first.
    assert_eq!(fwd, back);
}

#[tokio::test]
async fn a_remote_alice_is_never_the_local_alice() {
    let ralice = remote("alice", "providerb.example");
    let env = env_with_remotes(&[&ralice]).await;
    let alice = local(&env, "alice").await;
    let g = group(&env, &alice, "group", "open").await;
    let (s, m) = join_http(&env, &ralice, &g, None).await;
    assert_eq!(s, StatusCode::CREATED, "{m}");
    assert_eq!(m["user"], "alice@providerb.example");
    let list = roster(&env, &alice, &g).await;
    assert!(list.contains(&(alice.actor.clone(), "owner".to_owned())));
    assert!(list.contains(&(ralice.actor.clone(), "member".to_owned())));
    // The remote alice cannot act as the owner, nor leave in her name.
    assert_eq!(leave(&env, &ralice, &g).await, StatusCode::NO_CONTENT);
    assert_eq!(roster(&env, &alice, &g).await.len(), 1);
    // A bare handle names the local user; the full actor the remote one.
    join_http(&env, &ralice, &g, None).await;
    assert_eq!(
        common::members::kick(&env, &alice, &g, "alice").await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        common::members::kick(&env, &alice, &g, "alice@providerb.example").await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(roster(&env, &alice, &g).await.len(), 1);
}

#[tokio::test]
async fn a_signed_member_sees_their_membership_on_the_group() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let olga = local(&env, "olga").await;
    let g = group(&env, &alice, "public", "open").await;
    join_http(&env, &bob, &g, None).await;
    let group_schema = schema("group.json");
    let path = format!("/api/groups/{g}");

    let (_, as_bob) = call(&env, Some(&bob), "GET", &path, None).await;
    assert_valid(&group_schema, &as_bob);
    assert_eq!(as_bob["membership"]["role"], "member", "{as_bob}");
    assert!(as_bob["membership"]["joinedAt"].is_string());
    let (_, as_owner) = call(&env, Some(&alice), "GET", &path, None).await;
    assert_eq!(as_owner["membership"]["role"], "owner", "{as_owner}");
    for who in [Some(&olga), None] {
        let (s, g) = call(&env, who, "GET", &path, None).await;
        assert_eq!(s, StatusCode::OK);
        assert!(g.get("membership").is_none(), "{g}");
    }

    // Never stored by a shared cache: the body is per caller.
    let req: Request<Body> = request(Some(&bob), "GET", &path, None);
    let res = env.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.headers()["cache-control"], "private, no-cache");
}

#[tokio::test]
async fn a_malformed_join_body_is_400_once_the_caller_is_let_in() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let bad = Some(json!({ "message": 5 }));
    // An open group, and the owner who is a member already: 400.
    let open = group(&env, &alice, "group", "open").await;
    let (s, p) = join_http(&env, &bob, &open, bad.clone()).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{p}");
    assert!(roster(&env, &alice, &open).await.len() == 1, "not admitted");
    let (s, p) = join_http(&env, &alice, &open, bad.clone()).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{p}");
    // Refused anyway: 403 before the body is looked at.
    let closed = group(&env, &alice, "public", "invite").await;
    let (s, p) = join_http(&env, &bob, &closed, bad).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{p}");
}

/// A removal that crashed between making a row `leaving` and deleting it
/// leaves the row behind (docs/decisions/0020, "Leaving during a
/// transfer"): it blocks a rejoin (`409`) until the sweeper deletes it,
/// `PENDING_TTL` after it was retired.
#[tokio::test]
async fn a_stuck_leaving_row_blocks_a_rejoin_until_swept() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let g = group(&env, &alice, "group", "open").await;
    let (s, _) = join_http(&env, &bob, &g, None).await;
    assert_eq!(s, StatusCode::CREATED);
    let retired_at = SIGNED_AT.unix_timestamp();
    let q = Ql::new("Membership.filter(.group_id == ")
        .str(&g)
        .raw(" && .status == \"active\").update({ status: \"leaving\", updated_at: ")
        .unix_seconds(retired_at)
        .raw(" })");
    env.state.db.execute(&q).await.unwrap();
    assert_eq!(
        roster(&env, &alice, &g).await.len(),
        1,
        "no longer a member"
    );

    let (s, p) = join_http(&env, &bob, &g, None).await;
    assert_eq!(s, StatusCode::CONFLICT, "{p}");
    // Not yet past the TTL: kept.
    let ttl = PENDING_TTL.as_secs() as i64;
    env.state.groups.sweep(retired_at + ttl - 1).await.unwrap();
    let (s, p) = join_http(&env, &bob, &g, None).await;
    assert_eq!(s, StatusCode::CONFLICT, "{p}");
    // Past it: swept, and bob joins again.
    env.state.groups.sweep(retired_at + ttl + 1).await.unwrap();
    let (s, p) = join_http(&env, &bob, &g, None).await;
    assert_eq!(s, StatusCode::CREATED, "{p}");
    assert_eq!(roster(&env, &alice, &g).await.len(), 2);
}
