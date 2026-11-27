//! Privacy settings, presence and membership listing (spec §6.1, §6.4–§6.6),
//! against a real rhypedb-server. Responses are validated against the
//! spec's schemas.

mod common;

use axum::http::StatusCode;
use common::accounts::*;
use common::profiles::*;
use serde_json::{Value, json};

fn check(schema: &str, body: &Value) {
    common::assert_valid(&common::schema(schema), body);
}

async fn put_privacy(env: &Env, who: &Caller, body: Value) -> Value {
    let (status, settings) = call(env, who, "PUT", "/api/me/privacy", Some(&body)).await;
    assert_eq!(status, StatusCode::OK, "{settings}");
    check("privacy-settings.json", &settings);
    settings
}

#[tokio::test]
async fn privacy_settings_default_then_change_field_by_field() {
    let env = env().await;
    let alice = local(&env, "alice").await;
    let (status, defaults) = call(&env, &alice, "GET", "/api/me/privacy", None).await;
    assert_eq!(status, StatusCode::OK, "{defaults}");
    check("privacy-settings.json", &defaults);
    assert_eq!(
        defaults,
        json!({
            "presenceVisibility": "sharedGroups",
            "profileVisibility": "public",
            "membershipVisibility": "authenticated",
            "allowList": [],
            "denyList": [],
            "metadata": [],
        })
    );

    // The first save: one field, canonicalized lists; the rest stay default.
    let saved = put_privacy(
        &env,
        &alice,
        json!({"presenceVisibility": "contacts", "allowList": ["Jane@a.com".to_lowercase(), "jane@A.COM"]}),
    )
    .await;
    assert_eq!(saved["presenceVisibility"], "contacts");
    assert_eq!(saved["profileVisibility"], "public");
    assert_eq!(saved["allowList"], json!(["jane@a.com"]));

    // A later save changes only what it names.
    let meta = json!({"schema": "https://example.org/p", "version": "2", "data": []});
    let saved = put_privacy(
        &env,
        &alice,
        json!({"membershipVisibility": "nobody", "denyList": ["spam@b.com"], "metadata": [meta]}),
    )
    .await;
    assert_eq!(
        saved,
        json!({
            "presenceVisibility": "contacts",
            "profileVisibility": "public",
            "membershipVisibility": "nobody",
            "allowList": ["jane@a.com"],
            "denyList": ["spam@b.com"],
            "metadata": [meta],
        })
    );
    let (_, read) = call(&env, &alice, "GET", "/api/me/privacy", None).await;
    assert_eq!(read, saved);

    // Refused: unknown values, non-actors, an actor on both lists (also
    // against the stored list), `null`. Nothing changes.
    for body in [
        json!({"profileVisibility": "friends"}),
        json!({"allowList": ["jane"]}),
        json!({"allowList": "jane@a.com"}),
        json!({"allowList": ["spam@B.com"]}),
        json!({"denyList": null}),
    ] {
        let (status, p) = call(&env, &alice, "PUT", "/api/me/privacy", Some(&body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {p}");
        check("problem-details.json", &p);
    }
    let (_, read) = call(&env, &alice, "GET", "/api/me/privacy", None).await;
    assert_eq!(read, saved);
}

#[tokio::test]
async fn concurrent_first_saves_both_take_effect() {
    let env = env().await;
    let alice = local(&env, "alice").await;
    let a = json!({"presenceVisibility": "public"});
    let b = json!({"profileVisibility": "nobody"});
    let (ra, rb) = tokio::join!(
        call(&env, &alice, "PUT", "/api/me/privacy", Some(&a)),
        call(&env, &alice, "PUT", "/api/me/privacy", Some(&b)),
    );
    assert_eq!(ra.0, StatusCode::OK, "{}", ra.1);
    assert_eq!(rb.0, StatusCode::OK, "{}", rb.1);
    let (_, read) = call(&env, &alice, "GET", "/api/me/privacy", None).await;
    assert_eq!(read["presenceVisibility"], "public");
    assert_eq!(read["profileVisibility"], "nobody");
}

#[tokio::test]
async fn concurrent_list_changes_never_put_an_actor_on_both_lists() {
    let env = env().await;
    let alice = local(&env, "alice").await;
    // Both with and without an existing row.
    for round in 0..2 {
        let x = format!("xavier{round}@b.com");
        let allow = json!({ "allowList": [x] });
        let deny = json!({ "denyList": [x] });
        let (ra, rd) = tokio::join!(
            call(&env, &alice, "PUT", "/api/me/privacy", Some(&allow)),
            call(&env, &alice, "PUT", "/api/me/privacy", Some(&deny)),
        );
        // Either the later one sees x on the other list and is refused, or
        // both land and the later pair wins whole: never x on both lists.
        for (status, body) in [&ra, &rd] {
            assert!(
                [StatusCode::OK, StatusCode::BAD_REQUEST].contains(status),
                "{status}: {body}"
            );
        }
        let (_, read) = call(&env, &alice, "GET", "/api/me/privacy", None).await;
        let on = |list: &str| read[list].as_array().unwrap().contains(&json!(x));
        assert!(on("allowList") || on("denyList"), "{read}");
        assert!(!(on("allowList") && on("denyList")), "{read}");
        // And settings stay updatable.
        put_privacy(&env, &alice, json!({"presenceVisibility": "nobody"})).await;
    }
}

#[tokio::test]
async fn concurrent_first_presence_saves_both_succeed() {
    let env = env().await;
    let alice = local(&env, "alice").await;
    let a = json!({"availability": "away", "status": "a"});
    let b = json!({"availability": "dnd", "status": "b"});
    let (ra, rb) = tokio::join!(
        call(&env, &alice, "PUT", "/api/me/presence", Some(&a)),
        call(&env, &alice, "PUT", "/api/me/presence", Some(&b)),
    );
    assert_eq!(ra.0, StatusCode::OK, "{}", ra.1);
    assert_eq!(rb.0, StatusCode::OK, "{}", rb.1);
    // Each write is whole: the stored status is one of the two, intact.
    let (_, own) = call(&env, &alice, "GET", "/api/users/alice/presence", None).await;
    assert!(own["status"] == "a" || own["status"] == "b", "{own}");
}

async fn presence(env: &Env, viewer: &Caller, path: &str) -> Value {
    let (status, p) = call(env, viewer, "GET", path, None).await;
    assert_eq!(status, StatusCode::OK, "{p}");
    check("presence.json", &p);
    p
}

#[tokio::test]
async fn presence_is_derived_from_liveness_and_filtered_by_policy() {
    let remote = Remote::new();
    let (_, live) = fakes();
    let env = env_with(EnvOptions {
        remote: Some(remote.keys()),
        liveness: Some(live.clone()),
        ..EnvOptions::default()
    })
    .await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let path = "/api/users/alice/presence";
    let hidden = json!({"availability": "offline", "metadata": []});

    // Never set, not connected: offline.
    assert_eq!(presence(&env, &alice, path).await, hidden);

    // Set away with a status. Not connected, so it reads offline, status kept.
    let meta = json!({"schema": "https://example.org/m", "version": "1", "data": null});
    let body = json!({"availability": "away", "status": "On vacation", "metadata": [meta]});
    let (status, own) = call(&env, &alice, "PUT", "/api/me/presence", Some(&body)).await;
    assert_eq!(status, StatusCode::OK, "{own}");
    check("presence.json", &own);
    let offline_with_status =
        json!({"availability": "offline", "status": "On vacation", "metadata": [meta]});
    assert_eq!(own, offline_with_status);

    // Connected: the explicit availability shows, to alice herself.
    live.0.lock().unwrap().push(actor("alice@providera.com"));
    let real = json!({"availability": "away", "status": "On vacation", "metadata": [meta]});
    assert_eq!(presence(&env, &alice, path).await, real);
    // Default policy sharedGroups and no groups: everyone else sees the
    // uniform offline, identical to really being offline.
    for viewer in [&bob, &remote.bob] {
        assert_eq!(presence(&env, viewer, path).await, hidden);
    }
    // Public: everyone sees it; remote bob denied by full actor.
    put_privacy(
        &env,
        &alice,
        json!({"presenceVisibility": "public", "denyList": ["bob@providerb.com"]}),
    )
    .await;
    assert_eq!(presence(&env, &bob, path).await, real);
    assert_eq!(presence(&env, &remote.bob, path).await, hidden);
    // A provider signature is never an anonymous viewer, even of public
    // presence: 401 (§4.5 *Anonymous viewers*, lost-conn/ofscp#42).
    let (status, p) = call(&env, &remote.provider, "GET", path, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{p}");

    // PUT replaces: no status now. `offline` cannot be set.
    let (status, own) = call(
        &env,
        &alice,
        "PUT",
        "/api/me/presence",
        Some(&json!({"availability": "dnd"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{own}");
    assert_eq!(own, json!({"availability": "dnd", "metadata": []}));
    for body in [
        json!({"availability": "offline"}),
        json!({"availability": "busy"}),
        json!({"status": "no availability"}),
        json!({"availability": "away", "status": "x".repeat(201)}),
    ] {
        let (status, p) = call(&env, &alice, "PUT", "/api/me/presence", Some(&body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {p}");
    }
    assert_eq!(
        presence(&env, &bob, path).await,
        json!({"availability": "dnd", "metadata": []})
    );
}

async fn groups(env: &Env, viewer: &Caller) -> Value {
    let (status, g) = call(env, viewer, "GET", "/api/users/alice/groups", None).await;
    assert_eq!(status, StatusCode::OK, "{g}");
    check("user-groups-response.json", &g);
    g
}

#[tokio::test]
async fn memberships_follow_membership_visibility() {
    let remote = Remote::new();
    let (fake, _) = fakes();
    let env = env_with(EnvOptions {
        remote: Some(remote.keys()),
        groups: Some(fake.clone()),
        ..EnvOptions::default()
    })
    .await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let uri = "https://providera.com/api/groups/grp_1";
    fake.listed.lock().unwrap().push(uri.to_owned());
    let listed = json!({"groups": [{"id": uri}], "metadata": []});
    let empty = json!({"groups": [], "metadata": []});

    // Default authenticated: users see it. A provider signature is refused
    // outright (lost-conn/ofscp#42).
    assert_eq!(groups(&env, &bob).await, listed);
    assert_eq!(groups(&env, &remote.bob).await, listed);
    let (status, p) = call(
        &env,
        &remote.provider,
        "GET",
        "/api/users/alice/groups",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{p}");
    // nobody: only alice; refusal looks like having no groups.
    put_privacy(&env, &alice, json!({"membershipVisibility": "nobody"})).await;
    assert_eq!(groups(&env, &alice).await, listed);
    assert_eq!(groups(&env, &bob).await, empty);
    assert_eq!(groups(&env, &remote.bob).await, empty);
    // sharedGroups: only who shares one.
    put_privacy(
        &env,
        &alice,
        json!({"membershipVisibility": "sharedGroups"}),
    )
    .await;
    fake.shared
        .lock()
        .unwrap()
        .push((actor("bob@providerb.com"), actor("alice@providera.com")));
    assert_eq!(groups(&env, &remote.bob).await, listed);
    assert_eq!(groups(&env, &bob).await, empty);
}

#[tokio::test]
async fn with_no_groups_the_listing_is_empty() {
    let env = env().await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let empty = json!({"groups": [], "metadata": []});
    assert_eq!(groups(&env, &bob).await, empty);
    assert_eq!(groups(&env, &alice).await, empty);
}
