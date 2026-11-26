//! Profiles and `GET /api/me` (spec §5.1, §6.2, §6.3), against a real
//! rhypedb-server. Responses are validated against the spec's schemas.

mod common;

use axum::http::StatusCode;
use common::accounts::*;
use common::harness::{SIGNED_AT, send};
use common::profiles::*;
use serde_json::{Value, json};

fn check(schema: &str, body: &Value) {
    common::assert_valid(&common::schema(schema), body);
}

fn problem(status: StatusCode, body: &Value, expected: StatusCode) {
    assert_eq!(status, expected, "{body}");
    check("problem-details.json", body);
}

#[tokio::test]
async fn me_patch_and_public_profile_round_trip() {
    let env = env().await;
    let alice = local(&env, "alice").await;

    // GET /api/me: the account's profile before any change (an account
    // without profile fields: updatedAt falls back to its creation).
    let (status, me) = call(&env, &alice, "GET", "/api/me", None).await;
    assert_eq!(status, StatusCode::OK, "{me}");
    check("user-account.json", &me);
    assert_eq!(
        me,
        json!({
            "profile": {
                "id": "https://providera.com/api/users/alice",
                "handle": "alice",
                "domain": "providera.com",
                "displayName": "Some Name",
                "updatedAt": "2026-01-01T12:00:00Z",
                "metadata": [],
            },
            "settings": {},
        })
    );

    // PATCH some fields; updatedAt is the time of the change.
    env.clock.set(SIGNED_AT + time::Duration::seconds(30));
    let meta = json!({"schema": "https://example.org/pronouns", "version": "1", "data": "they"});
    let body = json!({"displayName": " Alice A. ", "bio": "Hello!\nWorld", "metadata": [meta]});
    let (status, updated) = call(&env, &alice, "PATCH", "/api/me/profile", Some(&body)).await;
    assert_eq!(status, StatusCode::OK, "{updated}");
    check("user-profile.json", &updated);
    check("user-public-profile-response.json", &updated);
    assert_eq!(updated["displayName"], "Alice A.");
    assert_eq!(updated["bio"], "Hello!\nWorld");
    assert_eq!(updated["metadata"], json!([meta]));
    assert_eq!(updated["updatedAt"], "2026-01-01T12:00:30Z");

    // Absent fields are unchanged; the empty bio removes it.
    let (status, again) = call(
        &env,
        &alice,
        "PATCH",
        "/api/me/profile",
        Some(&json!({"bio": ""})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!(again["displayName"], "Alice A.");
    assert_eq!(again["metadata"], json!([meta]));
    assert!(again.get("bio").is_none(), "{again}");

    // A PATCH that changes nothing leaves updatedAt alone (§6.3).
    env.clock.set(SIGNED_AT + time::Duration::seconds(90));
    let (status, same) = call(&env, &alice, "PATCH", "/api/me/profile", Some(&json!({}))).await;
    assert_eq!(status, StatusCode::OK, "{same}");
    assert_eq!(same, again);

    // The public profile, as alice sees it and as GET /api/me reports it.
    let (status, public) = call(&env, &alice, "GET", "/api/users/alice/profile", None).await;
    assert_eq!(status, StatusCode::OK, "{public}");
    check("user-public-profile-response.json", &public);
    assert_eq!(public, again);
    let (_, me) = call(&env, &alice, "GET", "/api/me", None).await;
    assert_eq!(me["profile"], again);
}

#[tokio::test]
async fn bad_updates_are_refused_and_change_nothing() {
    let env = env().await;
    let alice = local(&env, "alice").await;
    for body in [
        json!({"displayName": ""}),
        json!({"displayName": 5}),
        json!({"displayName": null}),
        json!({"bio": "x".repeat(2001)}),
        json!({"avatar": "http://cdn.example/a.png"}),
        json!({"avatar": "https://cdn.example/a.png"}),
        json!({"metadata": [{"schema": "nope", "version": "1", "data": 1}]}),
        json!({"metadata": [{"schema": "https://s", "version": "1"}]}),
        json!([1, 2]),
    ] {
        let (status, p) = call(&env, &alice, "PATCH", "/api/me/profile", Some(&body)).await;
        problem(status, &p, StatusCode::BAD_REQUEST);
    }
    // Removing an avatar is accepted (there is none to remove).
    let (status, p) = call(
        &env,
        &alice,
        "PATCH",
        "/api/me/profile",
        Some(&json!({"avatar": null})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{p}");
    assert!(p.get("avatar").is_none());
    assert_eq!(p["displayName"], "Some Name");
}

#[tokio::test]
async fn local_endpoints_need_a_local_signature() {
    let remote = Remote::new();
    let env = env_with(EnvOptions {
        remote: Some(remote.keys()),
        ..EnvOptions::default()
    })
    .await;
    // A local "bob" exists, and bob@providerb.com is still not him.
    local(&env, "bob").await;
    for path in ["/api/me", "/api/me/privacy"] {
        let (status, p, _, _) = send(&env.app, get(path)).await;
        problem(status, &p, StatusCode::UNAUTHORIZED);
    }
    let calls = [
        ("GET", "/api/me", None),
        ("GET", "/api/me/privacy", None),
        ("PATCH", "/api/me/profile", Some(json!({"bio": "pwned"}))),
        (
            "PUT",
            "/api/me/privacy",
            Some(json!({"profileVisibility": "public"})),
        ),
        (
            "PUT",
            "/api/me/presence",
            Some(json!({"availability": "away"})),
        ),
    ];
    for caller in [&remote.bob, &remote.provider] {
        for (method, path, body) in &calls {
            let (status, p) = call(&env, caller, method, path, body.as_ref()).await;
            problem(status, &p, StatusCode::FORBIDDEN);
        }
    }
    // Local bob's profile is untouched.
    let (_, profile) = call(&env, &remote.bob, "GET", "/api/users/bob/profile", None).await;
    assert!(profile.get("bio").is_none(), "{profile}");
}

#[tokio::test]
async fn every_user_ref_form_resolves_and_nothing_else_does() {
    let remote = Remote::new();
    let env = env_with(EnvOptions {
        remote: Some(remote.keys()),
        ..EnvOptions::default()
    })
    .await;
    let alice = local(&env, "alice").await;
    for path in [
        "/api/users/alice/profile",
        "/api/users/alice%40providera.com/profile",
        "/api/users/alice%40PROVIDERA.COM/profile",
        "/api/users/https%3A%2F%2Fprovidera.com%2Fapi%2Fusers%2Falice/profile",
    ] {
        let (status, body) = call(&env, &remote.bob, "GET", path, None).await;
        assert_eq!(status, StatusCode::OK, "{path}: {body}");
        assert_eq!(body["handle"], "alice", "{path}");
    }
    // Disable a second account: it is answered like one that never existed.
    local(&env, "carol").await;
    let carol = env
        .state
        .accounts
        .store
        .find_user("carol")
        .await
        .unwrap()
        .unwrap();
    env.state.accounts.disable_account(&carol, 0).await.unwrap();
    let mut answers = Vec::new();
    for path in [
        "/api/users/nobody/profile",
        "/api/users/carol/profile",
        "/api/users/carol/presence",
        "/api/users/carol/groups",
        "/api/users/Alice/profile",
        "/api/users/alice%40providerb.com/profile",
        "/api/users/bob%40providerb.com/profile",
        "/api/users/https%3A%2F%2Fproviderb.com%2Fapi%2Fusers%2Falice/profile",
    ] {
        let (status, p) = call(&env, &alice, "GET", path, None).await;
        problem(status, &p, StatusCode::NOT_FOUND);
        answers.push(p["detail"].clone());
    }
    answers.dedup();
    assert_eq!(answers.len(), 1, "{answers:?}");
}

/// Alice's bio as `caller` sees it.
async fn bio(env: &Env, caller: &Caller) -> Option<String> {
    let (status, body) = call(env, caller, "GET", "/api/users/alice/profile", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    check("user-public-profile-response.json", &body);
    // The base profile is always there.
    assert_eq!(body["handle"], "alice");
    body["bio"].as_str().map(str::to_owned)
}

#[tokio::test]
async fn the_bio_follows_profile_visibility_by_full_actor() {
    let remote = Remote::new();
    let env = env_with(EnvOptions {
        remote: Some(remote.keys()),
        ..EnvOptions::default()
    })
    .await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let patch = json!({"bio": "hi"});
    call(&env, &alice, "PATCH", "/api/me/profile", Some(&patch)).await;
    let set = |privacy: Value| {
        let alice = &alice;
        let env = &env;
        async move {
            let (status, body) = call(env, alice, "PUT", "/api/me/privacy", Some(&privacy)).await;
            assert_eq!(status, StatusCode::OK, "{body}");
        }
    };
    let hi = Some("hi".to_owned());

    // Default (public): everyone, providers included.
    for c in [&alice, &bob, &remote.bob, &remote.provider] {
        assert_eq!(bio(&env, c).await, hi);
    }
    // authenticated: users, not providers.
    set(json!({"profileVisibility": "authenticated"})).await;
    assert_eq!(bio(&env, &remote.bob).await, hi);
    assert_eq!(bio(&env, &remote.provider).await, None);
    // nobody, with remote bob allowed: local bob is not remote bob.
    set(json!({"profileVisibility": "nobody", "allowList": ["bob@providerb.com"]})).await;
    assert_eq!(bio(&env, &remote.bob).await, hi);
    assert_eq!(bio(&env, &bob).await, None);
    assert_eq!(bio(&env, &alice).await, hi);
    // public, with local bob denied: remote bob still sees it.
    set(json!({"profileVisibility": "public", "allowList": [], "denyList": ["bob@providera.com"]}))
        .await;
    assert_eq!(bio(&env, &bob).await, None);
    assert_eq!(bio(&env, &remote.bob).await, hi);
    // sharedGroups and contacts: no groups or contacts exist here yet.
    for v in ["sharedGroups", "contacts"] {
        set(json!({ "profileVisibility": v, "denyList": [] })).await;
        assert_eq!(bio(&env, &bob).await, None, "{v}");
        assert_eq!(bio(&env, &alice).await, hi, "{v}");
    }
}

#[tokio::test]
async fn shared_groups_use_the_group_seam() {
    let remote = Remote::new();
    let (groups, _) = fakes();
    let env = env_with(EnvOptions {
        remote: Some(remote.keys()),
        groups: Some(groups.clone()),
        ..EnvOptions::default()
    })
    .await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    call(
        &env,
        &alice,
        "PATCH",
        "/api/me/profile",
        Some(&json!({"bio": "hi"})),
    )
    .await;
    call(
        &env,
        &alice,
        "PUT",
        "/api/me/privacy",
        Some(&json!({"profileVisibility": "sharedGroups"})),
    )
    .await;
    groups
        .shared
        .lock()
        .unwrap()
        .push((actor("alice@providera.com"), actor("bob@providerb.com")));
    assert_eq!(bio(&env, &remote.bob).await.as_deref(), Some("hi"));
    assert_eq!(bio(&env, &bob).await, None);
}

#[tokio::test]
async fn unsigned_viewers_are_anonymous_and_bad_signatures_are_401() {
    let remote = Remote::new();
    let env = env_with(EnvOptions {
        remote: Some(remote.keys()),
        ..EnvOptions::default()
    })
    .await;
    let alice = local(&env, "alice").await;
    call(
        &env,
        &alice,
        "PATCH",
        "/api/me/profile",
        Some(&json!({"bio": "hi"})),
    )
    .await;
    let anonymous = |path: &'static str| {
        let env = &env;
        async move {
            let (status, body, _, _) = send(&env.app, get(path)).await;
            assert_eq!(status, StatusCode::OK, "{path}: {body}");
            body
        }
    };
    // public (the profile default): the anonymous viewer sees the bio.
    let profile = anonymous("/api/users/alice/profile").await;
    check("user-public-profile-response.json", &profile);
    assert_eq!(profile["bio"], "hi");
    // authenticated (the membership default) and sharedGroups (presence):
    // not for anonymous viewers, who get the uniform empty answers.
    let groups = anonymous("/api/users/alice/groups").await;
    check("user-groups-response.json", &groups);
    assert_eq!(groups, json!({"groups": [], "metadata": []}));
    let presence = anonymous("/api/users/alice/presence").await;
    check("presence.json", &presence);
    assert_eq!(presence, json!({"availability": "offline", "metadata": []}));
    // authenticated profile: signed users only. No list matches anonymous.
    let privacy = json!({"profileVisibility": "authenticated", "allowList": ["bob@providerb.com"]});
    call(&env, &alice, "PUT", "/api/me/privacy", Some(&privacy)).await;
    let profile = anonymous("/api/users/alice/profile").await;
    assert!(profile.get("bio").is_none(), "{profile}");
    assert_eq!(profile["handle"], "alice");
    // Unknown users are still 404 to anonymous callers.
    let (status, p, _, _) = send(&env.app, get("/api/users/nobody/profile")).await;
    problem(status, &p, StatusCode::NOT_FOUND);

    // A signature that does not verify is 401, never treated as anonymous.
    let forged = Caller {
        key: common::harness::new_key(),
        ..Remote::new().bob
    };
    for path in [
        "/api/users/alice/profile",
        "/api/users/alice/presence",
        "/api/users/alice/groups",
    ] {
        let (status, p) = call(&env, &forged, "GET", path, None).await;
        problem(status, &p, StatusCode::UNAUTHORIZED);
    }
}
