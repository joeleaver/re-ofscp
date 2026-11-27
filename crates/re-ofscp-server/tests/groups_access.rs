//! Effective read access (§11.3, security requirement 5) through the HTTP
//! surface, actor identity as `(handle, domain)` (requirement 1), provider
//! signatures, and the change events live surfaces re-check access on.

mod common;

use axum::http::StatusCode;
use common::accounts::{EnvOptions, NOW, env_with};
use common::groups::{
    Env, Party, call, create_channel, create_group, env_with_remotes, group_body, id, join, local,
    remote,
};
use common::harness::{new_key, send, signed_as};
use re_ofscp_server::groups::AccessChange;
use serde_json::{Value, json};

const TIERS: [&str; 4] = ["private", "group", "public", "discoverable"];
const VIEWS: [Option<&str>; 3] = [None, Some("member"), Some("admin")];

/// The caller kinds the matrix covers, and the role each holds.
#[derive(Clone, Copy, Debug)]
enum Kind {
    Anonymous,
    LocalOutsider,
    RemoteOutsider,
    Guest,
    Member,
    RemoteAdmin,
    Owner,
}

impl Kind {
    fn role(self) -> Option<&'static str> {
        match self {
            Kind::Anonymous | Kind::LocalOutsider | Kind::RemoteOutsider => None,
            Kind::Guest => Some("guest"),
            Kind::Member => Some("member"),
            Kind::RemoteAdmin => Some("admin"),
            Kind::Owner => Some("owner"),
        }
    }
}

/// §11.3 as the spec states it, written apart from the implementation:
/// public and discoverable tiers admit anyone, the others members only,
/// both tiers must admit, and `view`, when set, admits only the roles it
/// lists (the owner always).
fn expected(kind: Kind, group_tier: &str, channel_tier: &str, view: Option<&str>) -> bool {
    let open = |t: &str| t == "public" || t == "discoverable";
    let role = kind.role();
    let member = role.is_some();
    (open(group_tier) || member)
        && (open(channel_tier) || member)
        && view.is_none_or(|v| role == Some("owner") || role == Some(v))
}

struct Cast {
    env: Env,
    owner: Party,
    guest: Party,
    member: Party,
    outsider: Party,
    remote_outsider: Party,
    remote_admin: Party,
}

impl Cast {
    async fn new() -> Self {
        let remote_outsider = remote("rob", "providerb.example");
        let remote_admin = remote("ada", "providerb.example");
        let env = env_with_remotes(&[&remote_outsider, &remote_admin]).await;
        Self {
            owner: local(&env, "alice").await,
            guest: local(&env, "gus").await,
            member: local(&env, "mia").await,
            outsider: local(&env, "olga").await,
            remote_outsider,
            remote_admin,
            env,
        }
    }

    fn party(&self, kind: Kind) -> Option<&Party> {
        match kind {
            Kind::Anonymous => None,
            Kind::LocalOutsider => Some(&self.outsider),
            Kind::RemoteOutsider => Some(&self.remote_outsider),
            Kind::Guest => Some(&self.guest),
            Kind::Member => Some(&self.member),
            Kind::RemoteAdmin => Some(&self.remote_admin),
            Kind::Owner => Some(&self.owner),
        }
    }

    async fn join_all(&self, gid: &str) {
        join(&self.env, gid, &self.guest, "guest").await;
        join(&self.env, gid, &self.member, "member").await;
        join(&self.env, gid, &self.remote_admin, "admin").await;
    }
}

/// One channel of the matrix: (group tier, channel tier, view, channel id).
type Cell = (&'static str, &'static str, Option<&'static str>, String);

#[tokio::test]
async fn list_and_get_agree_with_effective_read_access_for_every_caller() {
    let cast = Cast::new().await;
    let env = &cast.env;
    let mut groups = Vec::new();
    let mut cells: Vec<Cell> = Vec::new();
    for gt in TIERS {
        let gid = id(&create_group(env, &cast.owner, group_body(gt, gt)).await);
        cast.join_all(&gid).await;
        for ct in TIERS {
            for view in VIEWS {
                let mut body = json!({"type": "text", "tier": ct});
                if let Some(v) = view {
                    body["permissions"] = json!({"view": [v]});
                }
                let c = create_channel(env, &cast.owner, &gid, body).await;
                cells.push((gt, ct, view, id(&c)));
            }
        }
        groups.push((gt, gid));
    }

    let kinds = [
        Kind::Anonymous,
        Kind::LocalOutsider,
        Kind::RemoteOutsider,
        Kind::Guest,
        Kind::Member,
        Kind::RemoteAdmin,
        Kind::Owner,
    ];
    for kind in kinds {
        let by = cast.party(kind);
        for (gt, gid) in &groups {
            let group_readable = kind.role().is_some() || *gt == "public" || *gt == "discoverable";
            let (s, g) = call(env, by, "GET", &format!("/api/groups/{gid}"), None).await;
            let want = if group_readable {
                StatusCode::OK
            } else {
                StatusCode::FORBIDDEN
            };
            assert_eq!(s, want, "{kind:?} GET group {gt}: {g}");

            let (s, list) =
                call(env, by, "GET", &format!("/api/groups/{gid}/channels"), None).await;
            assert_eq!(s, want, "{kind:?} list {gt}: {list}");
            let listed: Vec<&str> = if group_readable {
                list["items"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|c| c["id"].as_str().unwrap())
                    .collect()
            } else {
                Vec::new()
            };
            for (cgt, ct, view, cid) in cells.iter().filter(|c| c.0 == *gt) {
                let readable = expected(kind, cgt, ct, *view);
                let what = format!("{kind:?} group {cgt} channel {ct} view {view:?}");
                assert_eq!(listed.contains(&cid.as_str()), readable, "list: {what}");
                let path = format!("/api/groups/{gid}/channels/{cid}");
                let (s, body) = call(env, by, "GET", &path, None).await;
                // A hidden channel is `404`, as if absent, whatever hides
                // it, its group's tier included (lost-conn/ofscp#26).
                let want = if readable {
                    StatusCode::OK
                } else {
                    StatusCode::NOT_FOUND
                };
                assert_eq!(s, want, "GET: {what}: {body}");
            }
        }
    }
}

#[tokio::test]
async fn a_remote_actor_is_never_the_local_account_of_the_same_handle() {
    let remote_alice = remote("alice", "providerb.example");
    let remote_mia = remote("mia", "providerb.example");
    let env = env_with_remotes(&[&remote_alice, &remote_mia]).await;
    let alice = local(&env, "alice").await;
    let mia = local(&env, "mia").await;
    let gid = id(&create_group(&env, &alice, group_body("G", "private")).await);
    let path = format!("/api/groups/{gid}");

    // The owner's handle at another provider owns nothing here.
    let (s, _) = call(&env, Some(&remote_alice), "GET", &path, None).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = call(
        &env,
        Some(&remote_alice),
        "PATCH",
        &path,
        Some(json!({"name": "x"})),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = call(&env, Some(&remote_alice), "DELETE", &path, None).await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // A membership held by mia@providerb.example is not local mia's.
    join(&env, &gid, &remote_mia, "admin").await;
    let (s, _) = call(&env, Some(&mia), "GET", &path, None).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = call(&env, Some(&remote_mia), "GET", &path, None).await;
    assert_eq!(s, StatusCode::OK);
    // A remote admin manages exactly as a local one does.
    let (s, g) = call(
        &env,
        Some(&remote_mia),
        "PATCH",
        &path,
        Some(json!({"name": "by remote"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{g}");
    let c = create_channel(&env, &remote_mia, &gid, json!({"type": "text"})).await;
    let cpath = format!("{path}/channels/{}", id(&c));
    let (s, real) = call(&env, Some(&mia), "GET", &cpath, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // Indistinguishable from a channel id that does not exist.
    let fake = format!("{path}/channels/chn_doesnotexist");
    let (s, made_up) = call(&env, Some(&mia), "GET", &fake, None).await;
    assert_eq!((s, made_up), (StatusCode::NOT_FOUND, real));
    for method in ["PATCH", "DELETE"] {
        let b = (method == "PATCH").then(|| json!({"type": "text"}));
        let (s, p) = call(&env, Some(&remote_alice), method, &cpath, b).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{method}: {p}");
    }
    let store = &env.state.groups.store;
    assert_eq!(
        store
            .role_of(&gid, &remote_mia.id())
            .await
            .unwrap()
            .as_deref(),
        Some("admin")
    );
    assert_eq!(store.role_of(&gid, &mia.id()).await.unwrap(), None);
}

#[tokio::test]
async fn a_provider_signature_is_never_an_anonymous_viewer() {
    // §4.5 *Anonymous viewers*, §5.5, §8 *Authorization*
    // (lost-conn/ofscp#42): a provider-signed request is a signed request,
    // and no route accepts provider signatures, so a permitted provider
    // gets 401 even where an unsigned request would be served.
    let provider_key = new_key();
    // No resolver knows its key: it is never resolved (lost-conn/ofscp#42).
    let env = env_with(EnvOptions::default()).await;
    let alice = local(&env, "alice").await;
    let open = id(&create_group(&env, &alice, group_body("Open", "public")).await);
    let closed = id(&create_group(&env, &alice, group_body("Closed", "group")).await);
    let as_provider = |method: &str, path: &str, body: &str| {
        signed_as(
            &provider_key,
            ("x-ofscp-provider", "providerb.example"),
            "pk_1",
            method,
            path,
            body,
            NOW,
        )
    };

    for path in [
        format!("/api/groups/{open}"),
        format!("/api/groups/{open}/channels"),
        format!("/api/groups/{closed}"),
    ] {
        let (s, p, _, _) = send(&env.app, as_provider("GET", &path, "")).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{path}: {p}");
        assert_eq!(p["errorCode"], "unauthorized");
    }
    // The same reads unsigned are an anonymous viewer's.
    for path in [
        format!("/api/groups/{open}"),
        format!("/api/groups/{open}/channels"),
    ] {
        assert_eq!(call(&env, None, "GET", &path, None).await.0, StatusCode::OK);
    }
    assert_eq!(
        call(&env, None, "GET", &format!("/api/groups/{closed}"), None)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let body = json!({"name": "x"}).to_string();
    let (s, p, _, _) = send(
        &env.app,
        as_provider("PATCH", &format!("/api/groups/{open}"), &body),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "{p}");
    let (s, p, _, _) = send(&env.app, as_provider("POST", "/api/groups", &body)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "{p}");
}

/// The next change event (none may be pending but this one).
async fn next(rx: &mut tokio::sync::broadcast::Receiver<AccessChange>) -> AccessChange {
    rx.recv().await.unwrap()
}

#[tokio::test]
async fn access_changes_are_announced_and_take_effect_at_once() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let mia = local(&env, "mia").await;
    let gid = id(&create_group(&env, &alice, group_body("G", "public")).await);
    let c = create_channel(
        &env,
        &alice,
        &gid,
        json!({"type": "text", "tier": "public"}),
    )
    .await;
    let cid = id(&c);
    let gpath = format!("/api/groups/{gid}");
    let cpath = format!("{gpath}/channels/{cid}");
    let mut rx = env.state.groups.subscribe_changes();
    let groups = &env.state.groups;

    join(&env, &gid, &mia, "member").await;
    let member = AccessChange::Member {
        group_id: gid.clone(),
        actor: mia.id(),
    };
    assert_eq!(next(&mut rx).await, member);

    // The group closes: anonymous readers lose it, the member keeps it.
    let (s, _) = call(
        &env,
        Some(&alice),
        "PATCH",
        &gpath,
        Some(json!({"tier": "group"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        next(&mut rx).await,
        AccessChange::Group {
            group_id: gid.clone()
        }
    );
    let (s, _) = call(&env, None, "GET", &cpath, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = call(&env, Some(&mia), "GET", &cpath, None).await;
    assert_eq!(s, StatusCode::OK);

    // A `view` list that leaves the member out.
    let patch = json!({"type": "text", "permissions": {"view": ["admin"]}});
    let (s, _) = call(&env, Some(&alice), "PATCH", &cpath, Some(patch)).await;
    assert_eq!(s, StatusCode::OK);
    let channel = AccessChange::Channel {
        group_id: gid.clone(),
        channel_id: cid.clone(),
    };
    assert_eq!(next(&mut rx).await, channel);
    let (s, _) = call(&env, Some(&mia), "GET", &cpath, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "hidden, as if absent");

    // Promotion admits; removal revokes.
    assert!(groups.set_role(&gid, &mia.id(), "admin").await.unwrap());
    assert_eq!(next(&mut rx).await, member);
    let (s, _) = call(&env, Some(&mia), "GET", &cpath, None).await;
    assert_eq!(s, StatusCode::OK);
    groups.remove_member(&gid, &mia.id()).await.unwrap();
    assert_eq!(next(&mut rx).await, member);
    let (s, _) = call(&env, Some(&mia), "GET", &gpath, None).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = call(&env, Some(&mia), "GET", &cpath, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Deleting the channel is a change too.
    let (s, _) = call(&env, Some(&alice), "DELETE", &cpath, None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(next(&mut rx).await, channel);
    assert!(rx.try_recv().is_err(), "no other change was announced");
}

#[tokio::test]
async fn private_groups_list_unreadable_groups_as_forbidden_not_their_channels() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let gid = id(&create_group(&env, &alice, group_body("G", "private")).await);
    create_channel(
        &env,
        &alice,
        &gid,
        json!({"type": "text", "tier": "public"}),
    )
    .await;
    let (s, p): (StatusCode, Value) = call(
        &env,
        None,
        "GET",
        &format!("/api/groups/{gid}/channels"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(p.get("items").is_none(), "{p}");
}

#[tokio::test]
async fn a_manager_whom_view_leaves_out_cannot_see_or_change_the_channel() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let adam = local(&env, "adam").await;
    let mia = local(&env, "mia").await;
    let gid = id(&create_group(&env, &alice, group_body("G", "public")).await);
    join(&env, &gid, &adam, "admin").await;
    join(&env, &gid, &mia, "member").await;
    let body = json!({"type": "text", "tier": "public", "permissions": {"view": ["member"]}});
    let cid = id(&create_channel(&env, &adam, &gid, body).await);
    let cpath = format!("/api/groups/{gid}/channels/{cid}");
    let patch = json!({"type": "text", "topic": "t"});

    // §5.5 (lost-conn/ofscp#26): read access first (`404`), then `manage` (`403`).
    for method in ["GET", "PATCH", "DELETE"] {
        let b = (method == "PATCH").then(|| patch.clone());
        let (s, p) = call(&env, Some(&adam), method, &cpath, b).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "admin {method}: {p}");
    }
    for method in ["PATCH", "DELETE"] {
        let b = (method == "PATCH").then(|| patch.clone());
        let (s, p) = call(&env, Some(&mia), method, &cpath, b).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "member {method}: {p}");
    }
    let (s, list) = call(
        &env,
        Some(&adam),
        "GET",
        &format!("/api/groups/{gid}/channels"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(list["items"], json!([]));
    // The owner always passes `view`.
    let (s, _) = call(&env, Some(&alice), "PATCH", &cpath, Some(patch)).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = call(&env, Some(&alice), "DELETE", &cpath, None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
}
