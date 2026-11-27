//! Ownership transfer (spec §5.7, role `owner`) on a real rhypedb-server
//! (docs/decisions/0020, "Ownership transfer"): nobody's `joinedAt` moves
//! (lost-conn/ofscp#35), a transfer a crash interrupted is finished, a row
//! it left is ignored, a late finisher never deletes a newer row, leaving
//! or a nickname change racing a transfer stays consistent, concurrent
//! transfers leave one owner, and the limits hold.

mod common;

use axum::http::StatusCode;
use common::groups::{Env, Party, call, create_group, env_with_remotes, id, join, local, remote};
use common::harness::SIGNED_AT;
use common::members::{group_with_policy, kick, leave, members, nickname, roster, set_role};
use common::{assert_valid, schema};
use re_ofscp_server::db::Ql;
use re_ofscp_server::groups::access::Standing;
use re_ofscp_server::groups::model::{Handover, StoredGroup};
use re_ofscp_server::groups::{Caller, MAX_GROUPS_PER_OWNER, MAX_MEMBERSHIPS_PER_ACTOR};
use re_ofscp_server::timefmt;
use serde::Deserialize;
use serde_json::{Value, json};

/// The transfer id the hand-run steps use.
const T: &str = "xfr_test";

fn now() -> i64 {
    SIGNED_AT.unix_timestamp()
}

async fn open_group(env: &Env, owner: &Party) -> String {
    id(&create_group(env, owner, group_with_policy("group", "open", json!({}))).await)
}

/// `who` added to `g` as a `member` at `at` (unix seconds).
async fn join_at(env: &Env, g: &str, who: &Party, at: i64) {
    assert!(
        env.state
            .groups
            .add_member(g, &who.id(), "member", at)
            .await
            .unwrap()
    );
}

/// Every listed member of `g` as `user -> member`, read as `who`.
async fn listed(env: &Env, who: &Party, g: &str) -> Vec<Value> {
    let (s, page) = members(env, Some(who), g, "?limit=100").await;
    assert_eq!(s, StatusCode::OK, "{page}");
    page["items"].as_array().unwrap().clone()
}

fn find<'a>(list: &'a [Value], who: &Party) -> &'a Value {
    let found: Vec<_> = list.iter().filter(|m| m["user"] == who.actor).collect();
    assert_eq!(
        found.len(),
        1,
        "{who:?} listed once in {list:?}",
        who = who.actor
    );
    found[0]
}

async fn standing(env: &Env, group: &StoredGroup, who: &Party) -> Standing {
    env.state
        .groups
        .standing(&Caller::Actor(who.id()), group)
        .await
        .unwrap()
}

async fn stored(env: &Env, g: &str) -> StoredGroup {
    env.state.groups.store.group(g).await.unwrap().unwrap()
}

/// Steps 1 to 5 of a transfer of `g` from `from` to `to` run by hand under
/// id [`T`], then a crash: the committed, unfinished group.
async fn commit_by_hand(env: &Env, g: &str, from: &Party, to: &Party) -> StoredGroup {
    let store = &env.state.groups.store;
    let marked = store.mark_transfer(g, &to.id(), T).await.unwrap().unwrap();
    store
        .set_owner_display_name(g, &from.id(), None)
        .await
        .unwrap();
    assert!(
        store
            .add_member(g, &from.id(), "admin", None, now())
            .await
            .unwrap()
    );
    assert!(store.activate_member(g, &from.id()).await.unwrap());
    let before = stored(env, g).await;
    let joined = timefmt::unix(&marked.joined_at).unwrap();
    store
        .transfer_owner(
            &before,
            true,
            &Handover {
                to: &to.id(),
                display_name: None,
                joined_at: joined,
                transfer_id: T,
            },
            now(),
        )
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn the_owner_hands_the_group_on_and_nobodys_joined_at_moves() {
    let bob = remote("bob", "providerb.example");
    let env = env_with_remotes(&[&bob]).await;
    let alice = local(&env, "alice").await;
    let carol = local(&env, "carol").await;
    let created = create_group(&env, &alice, group_with_policy("group", "open", json!({}))).await;
    let g = id(&created);
    join_at(&env, &g, &bob, now() + 60).await;
    join(&env, &g, &carol, "admin").await;
    nickname(
        &env,
        &alice,
        &g,
        "alice",
        json!({"displayNameOverride": "Al"}),
    )
    .await;
    nickname(
        &env,
        &bob,
        &g,
        &bob.actor,
        json!({"displayNameOverride": "Bobby"}),
    )
    .await;
    let bob_joined = find(&listed(&env, &carol, &g).await, &bob)["joinedAt"].clone();
    assert_eq!(
        find(&listed(&env, &carol, &g).await, &alice)["joinedAt"],
        created["createdAt"]
    );

    // Only the owner may assign `owner`, and only to a member.
    let (s, _) = set_role(&env, &carol, &g, &bob.actor, "owner").await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = set_role(&env, &alice, &g, "nobody", "owner").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, m) = set_role(&env, &alice, &g, "alice", "owner").await;
    assert_eq!((s, &m["role"]), (StatusCode::OK, &json!("owner")));

    env.clock.set(SIGNED_AT + time::Duration::seconds(120));
    let (s, m) = set_role(&env, &alice, &g, &bob.actor, "owner").await;
    assert_eq!(s, StatusCode::OK, "{m}");
    assert_valid(&schema("member.json"), &m);
    assert_eq!(
        (&m["user"], &m["role"]),
        (&json!(bob.actor), &json!("owner"))
    );
    assert_eq!(m["displayNameOverride"], "Bobby", "the nickname follows");
    assert_eq!(
        m["joinedAt"], bob_joined,
        "the new owner keeps their joinedAt"
    );

    let (_, group) = call(&env, Some(&alice), "GET", &format!("/api/groups/{g}"), None).await;
    assert_eq!(group["owner"], json!(bob.actor));
    assert_eq!(group["membership"]["role"], "admin");
    assert_eq!(group["membership"]["displayNameOverride"], "Al");
    let list = listed(&env, &alice, &g).await;
    assert_eq!(list.len(), 3, "one owner, no leftover row: {list:?}");
    assert_eq!(find(&list, &bob)["role"], "owner");
    assert_eq!(find(&list, &bob)["joinedAt"], bob_joined);
    assert_eq!(find(&list, &alice)["role"], "admin");
    assert_eq!(
        find(&list, &alice)["joinedAt"],
        created["createdAt"],
        "the former owner keeps theirs: the group's creation"
    );
    assert_eq!(stored(&env, &g).await.transfer, None, "finished");
    let store = &env.state.groups.store;
    assert!(store.member_row(&g, &bob.id()).await.unwrap().is_none());

    // The new owner is bound as the old one was; the old one is free.
    assert_eq!(leave(&env, &bob, &g).await, StatusCode::CONFLICT);
    let (s, _) = set_role(&env, &alice, &g, "carol", "owner").await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(leave(&env, &alice, &g).await, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn the_sweeper_finishes_a_transfer_a_crash_interrupted() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let carol = local(&env, "carol").await;
    let g = open_group(&env, &alice).await;
    join(&env, &g, &bob, "member").await;
    join(&env, &g, &carol, "member").await;
    let store = &env.state.groups.store;
    let handed = commit_by_hand(&env, &g, &alice, &bob).await;

    // Unfinished, read straight from the store: bob's old row is still
    // there, yet bob stands as the owner and alice as an admin.
    let group = stored(&env, &g).await;
    assert_eq!(group.transfer, handed.transfer);
    assert_eq!(group.transfer.as_ref().map(|t| t.id.as_str()), Some(T));
    assert!(store.member_row(&g, &bob.id()).await.unwrap().is_some());
    assert_eq!(standing(&env, &group, &bob).await, Standing::Owner);
    assert_eq!(
        standing(&env, &group, &alice).await,
        Standing::Member("admin".into())
    );

    // The sweeper, before any route settles it, finishes it.
    env.state.groups.sweep(now() + 2).await.unwrap();
    assert_eq!(stored(&env, &g).await.transfer, None);
    assert!(store.member_row(&g, &bob.id()).await.unwrap().is_none());
    assert_eq!(
        store.role_of(&g, &alice.id()).await.unwrap().as_deref(),
        Some("admin")
    );
    // Finishing again changes nothing.
    env.state.groups.sweep(now() + 3).await.unwrap();
    assert_eq!(roster(&env, &carol, &g).await.len(), 3);
}

#[tokio::test]
async fn a_membership_change_finishes_an_interrupted_transfer_first() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let g = open_group(&env, &alice).await;
    join(&env, &g, &bob, "member").await;
    commit_by_hand(&env, &g, &alice, &bob).await;
    // The new owner demotes the old one: the transfer is finished first.
    let (s, m) = set_role(&env, &bob, &g, "alice", "member").await;
    assert_eq!((s, &m["role"]), (StatusCode::OK, &json!("member")), "{m}");
    assert_eq!(stored(&env, &g).await.transfer, None);
    let store = &env.state.groups.store;
    assert!(store.member_row(&g, &bob.id()).await.unwrap().is_none());
}

#[tokio::test]
async fn a_row_left_for_the_owner_by_a_crash_before_the_commit_is_ignored() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let created = create_group(&env, &alice, group_with_policy("group", "open", json!({}))).await;
    let g = id(&created);
    join(&env, &g, &bob, "member").await;
    let store = &env.state.groups.store;
    // Step 3 of a transfer, an hour on, then a crash.
    let later = now() + 3600;
    assert!(
        store
            .add_member(&g, &alice.id(), "admin", None, later)
            .await
            .unwrap()
    );
    assert!(store.activate_member(&g, &alice.id()).await.unwrap());

    let group = stored(&env, &g).await;
    assert_eq!(standing(&env, &group, &alice).await, Standing::Owner);
    let list = listed(&env, &bob, &g).await;
    assert_eq!(list.len(), 2, "{list:?}");
    assert_eq!(find(&list, &alice)["role"], "owner");
    let (_, me) = call(&env, Some(&alice), "GET", &format!("/api/groups/{g}"), None).await;
    assert_eq!(me["membership"]["role"], "owner");

    // A real transfer reuses the row, with the owner's own joinedAt.
    let (s, m) = set_role(&env, &alice, &g, "bob", "owner").await;
    assert_eq!(s, StatusCode::OK, "{m}");
    let list = listed(&env, &bob, &g).await;
    assert_eq!(list.len(), 2, "{list:?}");
    assert_eq!(find(&list, &alice)["role"], "admin");
    assert_eq!(find(&list, &alice)["joinedAt"], created["createdAt"]);
}

#[tokio::test]
async fn a_late_finisher_never_deletes_a_row_written_since() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let carol = local(&env, "carol").await;
    let g = open_group(&env, &alice).await;
    join(&env, &g, &bob, "member").await;
    join(&env, &g, &carol, "member").await;
    let store = &env.state.groups.store;
    commit_by_hand(&env, &g, &alice, &bob).await;
    env.state.groups.sweep(now() + 1).await.unwrap();

    // Bob hands the group on within the same second: he gets a new row.
    let (s, m) = set_role(&env, &bob, &g, "carol", "owner").await;
    assert_eq!(s, StatusCode::OK, "{m}");
    let row = store.member_row(&g, &bob.id()).await.unwrap().unwrap();
    assert_eq!((row.role.as_str(), row.transfer_id), ("admin", None));

    // A finisher of the first transfer that stalled until now does its
    // writes: neither touches the new state.
    store
        .remove_transferred_member(&g, &bob.id(), T)
        .await
        .unwrap();
    store.clear_transfer(&g, T).await.unwrap();
    assert_eq!(
        store.role_of(&g, &bob.id()).await.unwrap().as_deref(),
        Some("admin")
    );
    assert_eq!(stored(&env, &g).await.owner, carol.id());
    assert_eq!(roster(&env, &alice, &g).await.len(), 3);
}

#[tokio::test]
async fn concurrent_transfers_leave_exactly_one_owner() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let carol = local(&env, "carol").await;
    let g = open_group(&env, &alice).await;
    join(&env, &g, &bob, "member").await;
    join(&env, &g, &carol, "member").await;

    let (to_bob, to_carol) = tokio::join!(
        set_role(&env, &alice, &g, "bob", "owner"),
        set_role(&env, &alice, &g, "carol", "owner"),
    );
    let ok = [&to_bob, &to_carol]
        .iter()
        .filter(|(s, _)| *s == StatusCode::OK)
        .count();
    assert_eq!(ok, 1, "{to_bob:?} {to_carol:?}");
    for (s, p) in [&to_bob, &to_carol] {
        assert!(
            [StatusCode::OK, StatusCode::FORBIDDEN, StatusCode::CONFLICT].contains(s),
            "{s} {p}"
        );
    }
    let (winner, loser) = if to_bob.0 == StatusCode::OK {
        (&bob, &carol)
    } else {
        (&carol, &bob)
    };
    let group = stored(&env, &g).await;
    assert_eq!(group.owner, winner.id());
    assert_eq!(group.transfer, None);
    let list = listed(&env, &alice, &g).await;
    assert_eq!(list.len(), 3, "{list:?}");
    assert_eq!(find(&list, winner)["role"], "owner");
    assert_eq!(find(&list, loser)["role"], "member");
    assert_eq!(find(&list, &alice)["role"], "admin");
}

#[tokio::test]
async fn leaving_or_a_kick_during_a_transfer_fences_it() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let carol = local(&env, "carol").await;
    let dave = local(&env, "dave").await;
    let g = open_group(&env, &alice).await;
    for p in [&bob, &carol, &dave] {
        join(&env, &g, p, "member").await;
    }
    let store = &env.state.groups.store;
    store
        .set_owner_display_name(&g, &alice.id(), None)
        .await
        .unwrap();

    // Without a transfer in flight, leaving does not touch the group.
    let before = stored(&env, &g).await;
    assert_eq!(leave(&env, &dave, &g).await, StatusCode::NO_CONTENT);
    assert_eq!(stored(&env, &g).await.revision, before.revision);

    // A transfer to bob has marked him and read the group; bob leaves.
    store
        .mark_transfer(&g, &bob.id(), T)
        .await
        .unwrap()
        .unwrap();
    let read = stored(&env, &g).await;
    assert_eq!(leave(&env, &bob, &g).await, StatusCode::NO_CONTENT);
    let bob_joined = now();
    let late = store
        .transfer_owner(
            &read,
            true,
            &Handover {
                to: &bob.id(),
                display_name: None,
                joined_at: bob_joined,
                transfer_id: T,
            },
            now(),
        )
        .await;
    assert_eq!(late.unwrap(), None, "the transfer can no longer commit");
    assert_eq!(stored(&env, &g).await.owner, alice.id());

    // The same for a kick.
    store
        .mark_transfer(&g, &carol.id(), "xfr_other")
        .await
        .unwrap()
        .unwrap();
    let read = stored(&env, &g).await;
    assert_eq!(
        kick(&env, &alice, &g, "carol").await,
        StatusCode::NO_CONTENT
    );
    let late = store
        .transfer_owner(
            &read,
            true,
            &Handover {
                to: &carol.id(),
                display_name: None,
                joined_at: now(),
                transfer_id: "xfr_other",
            },
            now(),
        )
        .await;
    assert_eq!(late.unwrap(), None);
    assert_eq!(roster(&env, &alice, &g).await.len(), 1);
}

#[tokio::test]
async fn a_transfer_that_committed_first_wins_over_a_removal() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let g = open_group(&env, &alice).await;
    join(&env, &g, &bob, "member").await;
    commit_by_hand(&env, &g, &alice, &bob).await;
    // A removal of bob that read the group before the commit.
    let removed = env.state.groups.remove_member(&g, &bob.id()).await;
    assert!(removed.is_err(), "{removed:?}");
    let store = &env.state.groups.store;
    assert!(
        store.member(&g, &bob.id()).await.unwrap().is_some(),
        "row put back"
    );
    env.state.groups.sweep(now() + 1).await.unwrap();
    assert!(store.member_row(&g, &bob.id()).await.unwrap().is_none());
    assert_eq!(stored(&env, &g).await.owner, bob.id());
}

#[tokio::test]
async fn nicknames_set_during_a_transfer_are_kept() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let carol = local(&env, "carol").await;
    let g = open_group(&env, &alice).await;
    join(&env, &g, &bob, "member").await;
    join(&env, &g, &carol, "member").await;
    let store = &env.state.groups.store;

    // Bob renames himself on his row after the transfer read it.
    commit_by_hand(&env, &g, &alice, &bob).await;
    store
        .set_member_display_name(&g, &bob.id(), Some("Bobby"))
        .await
        .unwrap();
    env.state.groups.sweep(now() + 1).await.unwrap();
    assert_eq!(
        stored(&env, &g).await.owner_display_name.as_deref(),
        Some("Bobby")
    );

    // Bob, owning, renames himself while his own transfer to carol has
    // written his row and read the group: the row follows, and the
    // transfer's commit fails its guard (it retries with the new name).
    assert!(
        store
            .add_member(&g, &bob.id(), "admin", None, now())
            .await
            .unwrap()
    );
    assert!(store.activate_member(&g, &bob.id()).await.unwrap());
    let read = stored(&env, &g).await;
    let (s, _) = nickname(&env, &bob, &g, "bob", json!({"displayNameOverride": "B"})).await;
    assert_eq!(s, StatusCode::OK);
    let row = store.member_row(&g, &bob.id()).await.unwrap().unwrap();
    assert_eq!(row.display_name.as_deref(), Some("B"));
    store
        .mark_transfer(&g, &carol.id(), "xfr_c")
        .await
        .unwrap()
        .unwrap();
    let late = store
        .transfer_owner(
            &read,
            true,
            &Handover {
                to: &carol.id(),
                display_name: None,
                joined_at: now(),
                transfer_id: "xfr_c",
            },
            now(),
        )
        .await;
    assert_eq!(late.unwrap(), None);
    let (s, _) = set_role(&env, &bob, &g, "carol", "owner").await;
    assert_eq!(s, StatusCode::OK);
    let row = store.member(&g, &bob.id()).await.unwrap().unwrap();
    assert_eq!(row.display_name.as_deref(), Some("B"));
}

#[tokio::test]
async fn a_transfer_respects_both_parties_limits() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let carol = local(&env, "carol").await;
    let g = open_group(&env, &alice).await;
    join(&env, &g, &bob, "member").await;
    join(&env, &g, &carol, "member").await;
    let store = &env.state.groups.store;

    // Bob owns as many groups as allowed: he may not be handed another.
    for _ in 0..MAX_GROUPS_PER_OWNER {
        open_group(&env, &bob).await;
    }
    let (s, p) = set_role(&env, &alice, &g, "bob", "owner").await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{p}");

    // Alice is in as many groups as allowed: handing this one on would
    // make it one more.
    for i in 0..MAX_MEMBERSHIPS_PER_ACTOR {
        let other = format!("grp_elsewhere{i}");
        assert!(
            store
                .add_member(&other, &alice.id(), "member", None, now())
                .await
                .unwrap()
        );
        assert!(store.activate_member(&other, &alice.id()).await.unwrap());
    }
    let (s, p) = set_role(&env, &alice, &g, "carol", "owner").await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{p}");
    assert_eq!(stored(&env, &g).await.owner, alice.id());
    assert_eq!(roster(&env, &bob, &g).await.len(), 3);
}

/// A group created before `owner_display_name` was written at creation has
/// no such field, which no filter matches: the commit then cannot guard on
/// it, and the transfer still goes through and keeps the nicknames.
#[tokio::test]
async fn a_group_older_than_the_nickname_field_still_hands_on() {
    #[derive(Deserialize)]
    struct Copied {
        doc: String,
    }
    let bob = remote("bob", "providerb.example");
    let env = env_with_remotes(&[&bob]).await;
    let alice = local(&env, "alice").await;
    let template =
        id(&create_group(&env, &alice, group_with_policy("public", "open", json!({}))).await);
    let doc = env
        .state
        .db
        .fetch::<Copied>(
            &Ql::new("Group.filter(.group_id == ")
                .str(&template)
                .raw(")"),
        )
        .await
        .unwrap()
        .remove(0)
        .data
        .doc;
    let g = "grp_legacy0000000000000000000000";
    let q = Ql::new("Group.create({ group_id: ")
        .str(g)
        .raw(", owner: ")
        .str(&alice.id().to_string())
        .raw(", name: \"legacy\", tier: \"public\", join_policy: \"open\", status: \"active\"")
        .raw(", revision: 0, doc: ")
        .str(&doc)
        .raw(", created_at: ")
        .unix_seconds(now())
        .raw(", updated_at: ")
        .unix_seconds(now())
        .raw(" })");
    env.state.db.execute(&q).await.unwrap();
    assert!(
        !env.state
            .groups
            .store
            .owner_display_name_is_null(g)
            .await
            .unwrap()
    );
    join(&env, g, &bob, "member").await;
    nickname(
        &env,
        &bob,
        g,
        &bob.actor,
        json!({"displayNameOverride": "Bobby"}),
    )
    .await;

    let (s, m) = set_role(&env, &alice, g, &bob.actor, "owner").await;
    assert_eq!(s, StatusCode::OK, "{m}");
    assert_eq!(m["displayNameOverride"], "Bobby");
    let after = stored(&env, g).await;
    assert_eq!(after.owner, bob.id());
    assert!(after.transfer.is_none(), "the transfer finished");
    let list = listed(&env, &alice, g).await;
    assert_eq!(list.len(), 2, "{list:?}");
    assert_eq!(find(&list, &alice)["role"], "admin");
}
