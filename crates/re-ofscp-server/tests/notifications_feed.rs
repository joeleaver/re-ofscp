//! Reading and marking the notification feed, and notification settings
//! (spec §10.1 *Endpoints*, §10.2; docs/decisions/0023; security
//! requirement 5), on a real rhypedb-server.

mod common;

use axum::http::StatusCode;
use common::groups::{Party, id};
use common::harness::SIGNED_AT;
use common::members::kick;
use common::messages::{call, post, text};
use common::notifications::{
    Cast, FEED, SETTINGS, all_entries, counts, entries, feed, mark, prefs, set,
};
use re_ofscp_server::notifications::settings::SettingStore;
use re_ofscp_server::notifications::store::{FEED_CAP, FeedStore, NewEntry, kind};
use re_ofscp_server::timefmt;
use serde_json::{Value, json};

fn assert_problem(status: StatusCode, body: &Value, want: StatusCode, code: &str) {
    assert_eq!(status, want, "{body}");
    assert_eq!(body["errorCode"], code, "{body}");
}

/// Post `body` in the cast's channel as `by`; its id.
async fn say(cast: &Cast, by: &Party, body: Value) -> String {
    id(&post(&cast.env, by, &cast.chan, body).await)
}

/// The ids of a feed page's entries, in order.
fn ids(page: &Value) -> Vec<String> {
    page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["id"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn pages_run_newest_first_with_a_top_level_cursor() {
    let cast = Cast::new().await;
    let env = &cast.env;
    let mut made = Vec::new();
    for i in 0..31 {
        made.push(say(&cast, &cast.alice, text(&format!("@bob {i}"))).await);
    }
    made.reverse();
    // The default page is 30, newest first.
    let first = feed(env, &cast.bob, "").await;
    let got: Vec<String> = entries(&first).into_iter().map(|(_, m)| m).collect();
    assert_eq!(got, made[..30]);
    let cursor = first["nextCursor"].as_str().unwrap();
    assert!(first.get("page").is_none(), "{first}");
    let rest = feed(env, &cast.bob, &format!("?cursor={cursor}")).await;
    assert_eq!(entries(&rest), [("mention".to_owned(), made[30].clone())]);
    assert!(rest.get("nextCursor").is_none(), "{rest}");

    // Smaller pages walk the same order; a huge limit is clamped to 100.
    let mut walked = Vec::new();
    let mut query = "?limit=7".to_owned();
    loop {
        let page = feed(env, &cast.bob, &query).await;
        walked.extend(entries(&page).into_iter().map(|(_, m)| m));
        match page["nextCursor"].as_str() {
            Some(c) => query = format!("?limit=7&cursor={c}"),
            None => break,
        }
    }
    assert_eq!(walked, made);
    assert_eq!(
        entries(&feed(env, &cast.bob, "?limit=5000").await).len(),
        31
    );

    for bad in ["t1", "n", "nope"] {
        let path = format!("{FEED}?cursor={bad}");
        let (s, b) = call(env, Some(&cast.bob), "GET", &path, None).await;
        assert_problem(s, &b, StatusCode::BAD_REQUEST, "bad_request");
    }
}

#[tokio::test]
async fn type_filters_and_counts_are_the_unseen_entries_per_type() {
    let cast = Cast::new().await;
    let env = &cast.env;
    let parent = say(&cast, &cast.bob, text("q")).await;
    set(env, &cast.bob, "channel", &cast.chan.c, "all").await;
    let mention = say(&cast, &cast.alice, text("@bob hi")).await;
    let reply = say(&cast, &cast.alice, common::messages::reply("a", &parent)).await;
    let message = say(&cast, &cast.alice, text("news")).await;

    let page = feed(env, &cast.bob, "?type=reply").await;
    assert_eq!(entries(&page), [("reply".to_owned(), reply.clone())]);
    assert_eq!(page["counts"], counts(1, 1, 1));
    // An unknown type is ignored, not an error.
    let page = feed(env, &cast.bob, "?type=bogus").await;
    assert_eq!(
        entries(&page),
        [
            ("message".to_owned(), message),
            ("reply".to_owned(), reply),
            ("mention".to_owned(), mention.clone()),
        ]
    );
    // Listing marks nothing seen.
    let page = feed(env, &cast.bob, "?type=mention").await;
    assert_eq!(page["counts"], counts(1, 1, 1));
    assert!(page["items"][0].get("seenAt").is_none(), "{page}");
}

#[tokio::test]
async fn seen_and_read_are_idempotent_and_ignore_foreign_ids() {
    let cast = Cast::new().await;
    let env = &cast.env;
    for i in 0..3 {
        say(&cast, &cast.alice, text(&format!("@bob @carol {i}"))).await;
    }
    let bobs = ids(&feed(env, &cast.bob, "").await);
    let carols = ids(&feed(env, &cast.carol, "").await);
    let at = timefmt::rfc3339(SIGNED_AT.unix_timestamp());

    // Carol's id in bob's request is ignored.
    let body = json!({"ids": [bobs[0], carols[1]]});
    let out = mark(env, &cast.bob, "seen", Some(body.clone())).await;
    assert_eq!(out, json!({"affected": 1, "counts": counts(2, 0, 0)}));
    let again = mark(env, &cast.bob, "seen", Some(body)).await;
    assert_eq!(again["affected"], 0);
    let page = feed(env, &cast.bob, "").await;
    assert_eq!(page["items"][0]["seenAt"], at.as_str());
    assert!(page["items"][0].get("readAt").is_none());
    assert_eq!(feed(env, &cast.carol, "").await["counts"], counts(3, 0, 0));

    // `read` with no ids reads everything, and sees what was unseen.
    let out = mark(env, &cast.bob, "read", None).await;
    assert_eq!(out, json!({"affected": 3, "counts": counts(0, 0, 0)}));
    assert_eq!(
        mark(env, &cast.bob, "read", Some(json!({"ids": []}))).await["affected"],
        0
    );
    for n in feed(env, &cast.bob, "").await["items"].as_array().unwrap() {
        assert_eq!(n["readAt"], at.as_str());
        assert_eq!(n["seenAt"], at.as_str());
    }
    // `seen` after `read` has nothing to do.
    assert_eq!(
        mark(env, &cast.bob, "seen", Some(json!({}))).await["affected"],
        0
    );
    assert_eq!(feed(env, &cast.carol, "").await["counts"], counts(3, 0, 0));

    let too_many: Vec<String> = (0..501).map(|i| format!("ntf_{i}")).collect();
    for body in [
        json!({"ids": too_many}),
        json!({"ids": ["not an id"]}),
        json!({"ids": "ntf_1"}),
        json!([]),
    ] {
        let path = format!("{FEED}/seen");
        let (s, b) = call(env, Some(&cast.bob), "POST", &path, Some(body)).await;
        assert_problem(s, &b, StatusCode::BAD_REQUEST, "bad_request");
    }
}

#[tokio::test]
async fn entries_vanish_from_the_feed_when_the_channel_becomes_unreadable() {
    let cast = Cast::new().await;
    let env = &cast.env;
    say(&cast, &cast.alice, text("@bob first")).await;
    assert_eq!(feed(env, &cast.bob, "").await["counts"], counts(1, 0, 0));

    assert_eq!(
        kick(env, &cast.alice, &cast.chan.g, "bob").await,
        StatusCode::NO_CONTENT
    );
    let page = feed(env, &cast.bob, "").await;
    assert_eq!(page["items"], json!([]));
    assert_eq!(page["counts"], counts(0, 0, 0));
    // Nor can they be marked.
    assert_eq!(mark(env, &cast.bob, "read", None).await["affected"], 0);

    // Back in the group, the entry is there again, still unread.
    common::groups::join(env, &cast.chan.g, &cast.bob, "member").await;
    let page = feed(env, &cast.bob, "").await;
    assert_eq!(page["counts"], counts(1, 0, 0));
    assert!(page["items"][0].get("readAt").is_none());
}

#[tokio::test]
async fn settings_are_upserted_listed_and_cleared() {
    let cast = Cast::new().await;
    let env = &cast.env;
    assert!(prefs(env, &cast.bob).await.is_empty());
    let group = set(env, &cast.bob, "group", &cast.chan.g, "none").await;
    set(env, &cast.bob, "channel", "chn_anything", "all").await;
    let channel = set(env, &cast.bob, "channel", "chn_anything", "mentions").await;
    assert_eq!(prefs(env, &cast.bob).await, [channel, group.clone()]);
    assert!(prefs(env, &cast.carol).await.is_empty());

    let clear = format!("{SETTINGS}?scopeType=channel&scopeId=chn_anything");
    for want in [true, false] {
        let (s, b) = call(env, Some(&cast.bob), "DELETE", &clear, None).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b, json!({"cleared": want}));
    }
    assert_eq!(prefs(env, &cast.bob).await, [group]);

    for body in [
        json!({"scopeType": "dm", "scopeId": "chn_1", "mode": "all"}),
        json!({"scopeType": "channel", "scopeId": "no spaces", "mode": "all"}),
        json!({"scopeType": "channel", "scopeId": "chn_1", "mode": "loud"}),
        json!({"scopeType": "channel", "scopeId": "chn_1"}),
        json!("all"),
    ] {
        let (s, b) = call(env, Some(&cast.bob), "PUT", SETTINGS, Some(body)).await;
        assert_problem(s, &b, StatusCode::BAD_REQUEST, "bad_request");
    }
    for query in [
        "",
        "?scopeType=channel",
        "?scopeId=chn_1",
        "?scopeType=dm&scopeId=chn_1",
    ] {
        let path = format!("{SETTINGS}{query}");
        let (s, b) = call(env, Some(&cast.bob), "DELETE", &path, None).await;
        assert_problem(s, &b, StatusCode::BAD_REQUEST, "bad_request");
    }
}

#[tokio::test]
async fn a_deleted_channels_entries_and_settings_are_purged_by_the_sweeper() {
    let cast = Cast::new().await;
    let env = &cast.env;
    set(env, &cast.bob, "channel", &cast.chan.c, "all").await;
    set(env, &cast.bob, "group", &cast.chan.g, "all").await;
    say(&cast, &cast.alice, text("@bob hello")).await;
    let store = FeedStore::new(env.state.db.clone());
    assert_eq!(store.entries(&cast.bob.actor).await.unwrap().len(), 1);

    let (s, _) = call(env, Some(&cast.alice), "DELETE", &cast.chan.channel(), None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(all_entries(env, &cast.bob).await.is_empty());
    env.state
        .messages
        .sweep(SIGNED_AT.unix_timestamp())
        .await
        .unwrap();
    assert!(store.entries(&cast.bob.actor).await.unwrap().is_empty());
    // The group's setting is the user's to clear; the channel's is gone.
    let left = prefs(env, &cast.bob).await;
    assert_eq!(
        left,
        [json!({"scopeType": "group", "scopeId": cast.chan.g, "mode": "all"})]
    );
}

#[tokio::test]
async fn a_scopes_all_settings_are_listed_whole_across_narrowed_ranges() {
    let cast = Cast::new().await;
    let now = SIGNED_AT.unix_timestamp();
    // Ranges of at most 3 rows: 20 matching rows need many narrowings.
    let store = SettingStore::with_scan_page(cast.env.state.db.clone(), 3);
    let mut want = Vec::new();
    for i in 0..26 {
        let owner = format!("u{i:02}@a.example");
        let mode = if i % 4 == 3 { "mentions" } else { "all" };
        store
            .put(&owner, "channel", "chn_scanned", mode, now)
            .await
            .unwrap();
        // The same owner's settings of other scopes are not listed.
        store
            .put(&owner, "group", "chn_scanned", "all", now)
            .await
            .unwrap();
        store
            .put(&owner, "channel", "chn_other", "all", now)
            .await
            .unwrap();
        if mode == "all" {
            want.push(owner);
        }
    }
    let mut got = store
        .all_mode_owners("channel", "chn_scanned")
        .await
        .unwrap();
    got.sort();
    assert_eq!(got, want);
}

#[tokio::test]
async fn a_feed_keeps_only_its_newest_entries() {
    let cast = Cast::new().await;
    let env = &cast.env;
    let store = FeedStore::new(env.state.db.clone());
    let entry = |message: &'static str, kind: &'static str| NewEntry {
        owner: &cast.bob.actor,
        kind,
        message_id: message,
        channel_id: &cast.chan.c,
        group_id: &cast.chan.g,
        author: &cast.alice.actor,
        now: SIGNED_AT.unix_timestamp(),
    };
    assert!(
        store
            .insert(&entry("msg_first", kind::MENTION))
            .await
            .unwrap()
            .is_some()
    );
    // A second entry for the same message is refused (its position, 2,
    // stays a gap).
    assert!(
        store
            .insert(&entry("msg_first", kind::REPLY))
            .await
            .unwrap()
            .is_none()
    );
    let names: Vec<String> = (0..FEED_CAP).map(|i| format!("msg_{i}")).collect();
    for name in &names {
        let mut e = entry("msg_first", kind::MENTION);
        e.message_id = name;
        assert!(store.insert(&e).await.unwrap().is_some());
    }
    // Positions 1..=502 were taken; the newest 500 (3..=502) are kept, and
    // the oldest entry, at 1, is pruned.
    let kept = store.entries(&cast.bob.actor).await.unwrap();
    assert_eq!(kept.len() as i64, FEED_CAP);
    assert_eq!(kept.iter().map(|e| e.n).min(), Some(3));
    assert!(kept.iter().all(|e| e.message_id != "msg_first"));
    let rows = env
        .state
        .db
        .fetch::<Value>(&re_ofscp_server::db::Ql::new("Notification.filter(.n > 0)"))
        .await
        .unwrap();
    assert_eq!(rows.len() as i64, FEED_CAP);
    let page = feed(env, &cast.bob, "?limit=100").await;
    assert_eq!(page["counts"], counts(FEED_CAP as u64, 0, 0));
    assert_eq!(
        page["items"][0]["sourceMessageId"],
        names[names.len() - 1].as_str()
    );
}
