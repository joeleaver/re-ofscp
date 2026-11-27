//! An owner renaming themselves while an ownership transfer runs (spec
//! §5.7) never locks the group (docs/decisions/0020, "Nicknames"): the
//! rename is a revisioned edit under the next revision's claim, so it waits
//! for a transfer holding that claim, and a transfer it beat retries on a
//! fresh revision. Kicks and group edits right after still go through.
//! Over a real rhypedb-server.

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use common::groups::{Env, Party, call, create_group, env_with_remotes, id, join, local};
use common::harness::SIGNED_AT;
use common::members::{group_with_policy, kick, nickname, set_role};
use re_ofscp_server::groups::model::{Handover, StoredGroup};
use re_ofscp_server::timefmt;
use serde_json::json;

fn now() -> i64 {
    SIGNED_AT.unix_timestamp()
}

async fn open_group(env: &Env, owner: &Party) -> String {
    id(&create_group(env, owner, group_with_policy("group", "open", json!({}))).await)
}

async fn stored(env: &Env, g: &str) -> StoredGroup {
    env.state.groups.store.group(g).await.unwrap().unwrap()
}

/// A transfer of `g` marks `who` and stalls; `by` kicks them, then renames
/// the group. Neither may be refused for a claim nobody is using.
async fn kick_marked_then_edit(env: &Env, g: &str, by: &Party, who: &Party, handle: &str) {
    let store = &env.state.groups.store;
    store
        .mark_transfer(g, &who.id(), "xfr_stalled")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(kick(env, by, g, handle).await, StatusCode::NO_CONTENT);
    assert!(store.member_row(g, &who.id()).await.unwrap().is_none());
    let path = format!("/api/groups/{g}");
    let (s, p) = call(
        env,
        Some(by),
        "PATCH",
        &path,
        Some(json!({"name": "after"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{p}");
}

#[tokio::test]
async fn an_owner_rename_waits_for_a_transfer_holding_the_claim() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let carol = local(&env, "carol").await;
    let g = open_group(&env, &alice).await;
    join(&env, &g, &bob, "member").await;
    join(&env, &g, &carol, "member").await;
    let store = &env.state.groups.store;

    // A transfer to bob, by hand up to its commit: bob marked, the group
    // read, alice's row prepared, and the next revision claimed.
    let marked = store
        .mark_transfer(&g, &bob.id(), "xfr_bob")
        .await
        .unwrap()
        .unwrap();
    let read = stored(&env, &g).await;
    assert!(
        store
            .add_member(&g, &alice.id(), "admin", None, now())
            .await
            .unwrap()
    );
    assert!(store.activate_member(&g, &alice.id()).await.unwrap());
    // The claim key's format is claims.rs's `group_key`.
    let key = format!("group:{g}:{}", read.revision + 1);
    assert!(store.claim(&key, now()).await.unwrap());

    // Alice renames herself through the route meanwhile; the transfer
    // commits a moment later.
    let rename = nickname(
        &env,
        &alice,
        &g,
        "alice",
        json!({"displayNameOverride": "Ali"}),
    );
    let commit = async {
        tokio::time::sleep(Duration::from_millis(30)).await;
        store
            .transfer_owner(
                &read,
                &Handover {
                    to: &bob.id(),
                    display_name: None,
                    joined_at: timefmt::unix(&marked.joined_at).unwrap(),
                    transfer_id: "xfr_bob",
                },
                now(),
            )
            .await
    };
    let ((s, m), committed) = tokio::join!(rename, commit);
    assert!(committed.unwrap().is_some(), "the transfer committed");
    // The rename waited, then landed on the row alice now holds.
    assert_eq!(s, StatusCode::OK, "{m}");
    assert_eq!(
        (&m["role"], &m["displayNameOverride"]),
        (&json!("admin"), &json!("Ali"))
    );
    let after = stored(&env, &g).await;
    assert_eq!(after.owner, bob.id());
    assert!(after.transfer.is_none(), "the rename finished the transfer");

    kick_marked_then_edit(&env, &g, &bob, &carol, "carol").await;
}

#[tokio::test]
async fn renames_racing_transfers_through_the_routes_never_conflict() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let carol = local(&env, "carol").await;
    let g = open_group(&env, &alice).await;
    join(&env, &g, &bob, "member").await;
    join(&env, &g, &carol, "member").await;
    let store = &env.state.groups.store;

    let parties = [(&alice, "alice"), (&bob, "bob")];
    for round in 0..8 {
        let (from, from_ref) = parties[round % 2];
        let (to, to_ref) = parties[(round + 1) % 2];
        let name = format!("n{round}");
        let ((ts, tm), (ns, nm)) = tokio::join!(
            set_role(&env, from, &g, to_ref, "owner"),
            nickname(
                &env,
                from,
                &g,
                from_ref,
                json!({ "displayNameOverride": name })
            ),
        );
        assert_eq!(ts, StatusCode::OK, "round {round}: transfer {tm}");
        assert_eq!(ns, StatusCode::OK, "round {round}: rename {nm}");
        assert_eq!(stored(&env, &g).await.owner, to.id());
        // Before the handover or after it, the rename ends on the row the
        // former owner holds now.
        let row = store.member(&g, &from.id()).await.unwrap().unwrap();
        assert_eq!(
            row.display_name.as_deref(),
            Some(name.as_str()),
            "round {round}"
        );
    }

    kick_marked_then_edit(&env, &g, &alice, &carol, "carol").await;
}
