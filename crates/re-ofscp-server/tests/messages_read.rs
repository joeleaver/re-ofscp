//! Reading channel messages over REST (spec §7.2): history paging,
//! replies, and reactions (§7.1 *Reactions*).

mod common;

use axum::http::StatusCode;
use common::assert_valid;
use common::groups::{Env, Party, env_with_remotes, join, local};
use common::messages::{
    Chan, assert_problem, call, group_and_channel, ids, next_cursor, page_schema, post,
    public_channel, raw, reaction_schema, reactions_page_schema, reply, text,
};
use serde_json::{Value, json};

/// alice owns a public group with a public channel; bob is a member,
/// carol an outsider.
struct Cast {
    env: Env,
    chan: Chan,
    alice: Party,
    bob: Party,
    carol: Party,
}

impl Cast {
    async fn new() -> Self {
        let env = env_with_remotes(&[]).await;
        let alice = local(&env, "alice").await;
        let bob = local(&env, "bob").await;
        let carol = local(&env, "carol").await;
        let chan = public_channel(&env, &alice).await;
        join(&env, &chan.g, &bob, "member").await;
        Self {
            env,
            chan,
            alice,
            bob,
            carol,
        }
    }

    /// GET `path` as bob: `200`, schema-checked against `messages-page.json`.
    async fn page(&self, path: &str) -> Value {
        let (s, page) = call(&self.env, Some(&self.bob), "GET", path, None).await;
        assert_eq!(s, StatusCode::OK, "{path}: {page}");
        assert_valid(&page_schema(), &page);
        page
    }
}

fn id(m: &Value) -> String {
    m["id"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn history_pages_newest_first_by_default_and_oldest_first_forward() {
    let cast = Cast::new().await;
    let (env, chan) = (&cast.env, &cast.chan);
    let mut m = Vec::new();
    for i in 0..5 {
        m.push(id(
            &post(env, &cast.alice, chan, text(&format!("m{i}"))).await
        ));
    }
    let m: Vec<&str> = m.iter().map(String::as_str).collect();
    // Edits and deletes take timeline positions that hold no message.
    let (s, _) = call(
        env,
        Some(&cast.alice),
        "PATCH",
        &chan.message(m[1]),
        Some(text("e")),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = call(env, Some(&cast.alice), "DELETE", &chan.message(m[2]), None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let base = chan.messages();

    let all = cast.page(&base).await;
    assert_eq!(ids(&all), [m[4], m[3], m[2], m[1], m[0]]);
    assert!(all["items"][2]["deletedAt"].is_string(), "{all}");
    assert!(all["items"][3]["editedAt"].is_string(), "{all}");
    assert_eq!(next_cursor(&all), None);

    // Backward, two at a time.
    let p1 = cast.page(&format!("{base}?limit=2")).await;
    assert_eq!(ids(&p1), [m[4], m[3]]);
    let c1 = next_cursor(&p1).unwrap();
    let p2 = cast.page(&format!("{base}?limit=2&cursor={c1}")).await;
    assert_eq!(ids(&p2), [m[2], m[1]]);
    let c2 = next_cursor(&p2).unwrap();
    let p3 = cast
        .page(&format!("{base}?limit=2&cursor={c2}&direction=backward"))
        .await;
    assert_eq!(ids(&p3), [m[0]]);
    assert_eq!(next_cursor(&p3), None);

    // Forward, from the oldest.
    let f1 = cast
        .page(&format!("{base}?direction=forward&limit=3"))
        .await;
    assert_eq!(ids(&f1), [m[0], m[1], m[2]]);
    let fc = next_cursor(&f1).unwrap();
    let f2 = cast
        .page(&format!("{base}?direction=forward&limit=3&cursor={fc}"))
        .await;
    assert_eq!(ids(&f2), [m[3], m[4]]);
    assert_eq!(next_cursor(&f2), None);

    // prevCursor with the opposite direction walks back (§7.2).
    let prev = p2["page"]["prevCursor"].as_str().unwrap();
    let back = cast
        .page(&format!("{base}?direction=forward&cursor={prev}"))
        .await;
    assert_eq!(ids(&back), [m[3], m[4]]);

    // An unknown direction is backward; an unusable limit is the default.
    for q in [
        "direction=sideways",
        "limit=0",
        "limit=abc",
        "limit=-3",
        "foo=1",
    ] {
        let p = cast.page(&format!("{base}?{q}")).await;
        assert_eq!(ids(&p), ids(&all), "{q}");
    }
    let p = cast.page(&format!("{base}?limit=1.9")).await;
    assert_eq!(ids(&p), [m[4]]);

    // A cursor this endpoint did not issue: 400.
    let reply_cursor = c1.replacen('t', "r", 1);
    for bad in ["zzz", "t", "t-1", reply_cursor.as_str(), "x1"] {
        let (s, p) = call(
            env,
            Some(&cast.bob),
            "GET",
            &format!("{base}?cursor={bad}"),
            None,
        )
        .await;
        assert_problem(s, StatusCode::BAD_REQUEST, &p);
    }
}

#[tokio::test]
async fn history_of_an_empty_channel_is_an_empty_page() {
    let cast = Cast::new().await;
    let page = cast.page(&cast.chan.messages()).await;
    assert_eq!(page["items"], json!([]));
    assert_eq!(next_cursor(&page), None);
}

#[tokio::test]
async fn replies_are_listed_under_their_parent_and_in_the_timeline() {
    let cast = Cast::new().await;
    let (env, chan) = (&cast.env, &cast.chan);
    let parent = id(&post(env, &cast.alice, chan, text("parent")).await);
    let other = id(&post(env, &cast.alice, chan, text("other")).await);
    let mut r = Vec::new();
    for i in 0..3 {
        let m = post(env, &cast.bob, chan, reply(&format!("r{i}"), &parent)).await;
        assert_eq!(m["reference"], json!({"type": "reply", "id": parent}));
        r.push(id(&m));
    }
    let r: Vec<&str> = r.iter().map(String::as_str).collect();
    post(env, &cast.bob, chan, reply("elsewhere", &other)).await;

    let all = cast.page(&chan.replies(&parent)).await;
    assert_eq!(ids(&all), [r[2], r[1], r[0]]);
    let f1 = cast
        .page(&format!(
            "{}?direction=forward&limit=2",
            chan.replies(&parent)
        ))
        .await;
    assert_eq!(ids(&f1), [r[0], r[1]]);
    let c = next_cursor(&f1).unwrap();
    let f2 = cast
        .page(&format!(
            "{}?direction=forward&limit=2&cursor={c}",
            chan.replies(&parent)
        ))
        .await;
    assert_eq!(ids(&f2), [r[2]]);
    assert_eq!(next_cursor(&f2), None);

    // A reply to a tombstone is allowed, and a deleted reply stays listed.
    let (s, _) = call(
        env,
        Some(&cast.alice),
        "DELETE",
        &chan.message(&parent),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = call(env, Some(&cast.bob), "DELETE", &chan.message(r[1]), None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let late = id(&post(env, &cast.bob, chan, reply("late", &parent)).await);
    let all = cast.page(&chan.replies(&parent)).await;
    assert_eq!(ids(&all), [late.as_str(), r[2], r[1], r[0]]);
    assert!(all["items"][2]["deletedAt"].is_string(), "{all}");

    // The timeline holds replies like any message.
    let timeline = cast.page(&chan.messages()).await;
    assert_eq!(ids(&timeline).len(), 7);

    // Replies of a missing message: 404; a timeline cursor: 400.
    let (s, p) = call(env, Some(&cast.bob), "GET", &chan.replies("msg_nope"), None).await;
    assert_problem(s, StatusCode::NOT_FOUND, &p);
    let (s, p) = call(
        env,
        Some(&cast.bob),
        "GET",
        &format!("{}?cursor=t1", chan.replies(&other)),
        None,
    )
    .await;
    assert_problem(s, StatusCode::BAD_REQUEST, &p);
}

#[tokio::test]
async fn a_reaction_put_is_201_then_200_and_its_body_is_optional_but_checked() {
    let cast = Cast::new().await;
    let (env, chan) = (&cast.env, &cast.chan);
    let m = id(&post(env, &cast.alice, chan, text("react to me")).await);

    let (s, up) = raw(env, Some(&cast.bob), "PUT", &chan.reaction(&m, "up"), "").await;
    assert_eq!(s, StatusCode::CREATED, "{up}");
    assert_valid(&reaction_schema(), &up);
    assert_eq!(up["author"], json!("bob@providera.com"));
    assert_eq!(up["key"], json!("up"));
    assert_eq!(up["reference"], json!({"type": "message", "id": m}));
    // Again, with any valid body: 200 with the reaction held, unchanged.
    for body in ["", "{}", r#"{"unicode": "x"}"#] {
        let (s, again) = raw(env, Some(&cast.bob), "PUT", &chan.reaction(&m, "up"), body).await;
        assert_eq!(s, StatusCode::OK, "{body}: {again}");
        assert_eq!(again, up);
    }

    let (s, heart) = raw(
        env,
        Some(&cast.bob),
        "PUT",
        &chan.reaction(&m, "heart"),
        "{}",
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{heart}");
    let body = r#"{"unicode": "👍", "image": "https://cdn.example/up.png"}"#;
    let (s, thumbs) = raw(
        env,
        Some(&cast.alice),
        "PUT",
        &chan.reaction(&m, "thumbs"),
        body,
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{thumbs}");
    assert_valid(&reaction_schema(), &thumbs);
    assert_eq!(thumbs["unicode"], json!("👍"));
    assert_eq!(thumbs["image"], json!("https://cdn.example/up.png"));
    // A percent-encoded key is the decoded key.
    let (s, spaced) = raw(
        env,
        Some(&cast.alice),
        "PUT",
        &chan.reaction(&m, "a%20b"),
        "",
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{spaced}");
    assert_eq!(spaced["key"], json!("a b"));

    for bad in [
        "[]",
        "null",
        "{",
        r#"{"unicode": null}"#,
        r#"{"unicode": 5}"#,
        r#"{"unicode": ""}"#,
        r#"{"image": "http://cdn.example/x.png"}"#,
    ] {
        let (s, p) = raw(env, Some(&cast.bob), "PUT", &chan.reaction(&m, "new"), bad).await;
        assert_problem(s, StatusCode::BAD_REQUEST, &p);
    }
    let long = "k".repeat(65);
    let (s, p) = raw(env, Some(&cast.bob), "PUT", &chan.reaction(&m, &long), "").await;
    assert_problem(s, StatusCode::BAD_REQUEST, &p);
    // Unsigned: 401; a missing message: 404.
    let (s, p) = raw(env, None, "PUT", &chan.reaction(&m, "up"), "").await;
    assert_problem(s, StatusCode::UNAUTHORIZED, &p);
    let (s, p) = raw(
        env,
        Some(&cast.bob),
        "PUT",
        &chan.reaction("msg_nope", "up"),
        "",
    )
    .await;
    assert_problem(s, StatusCode::NOT_FOUND, &p);
}

#[tokio::test]
async fn reactions_are_listed_paged_and_removing_one_is_always_204() {
    let cast = Cast::new().await;
    let (env, chan) = (&cast.env, &cast.chan);
    let m = id(&post(env, &cast.alice, chan, text("popular")).await);
    let mut reaction_ids = Vec::new();
    for (who, key) in [
        (&cast.bob, "a"),
        (&cast.alice, "a"),
        (&cast.bob, "b"),
        (&cast.carol, "c"),
    ] {
        let (s, r) = raw(env, Some(who), "PUT", &chan.reaction(&m, key), "").await;
        assert_eq!(s, StatusCode::CREATED, "{r}");
        reaction_ids.push(id(&r));
    }

    let (s, all) = call(env, None, "GET", &chan.reactions(&m), None).await;
    assert_eq!(s, StatusCode::OK, "{all}");
    assert_valid(&reactions_page_schema(), &all);
    let mut listed = ids(&all);
    listed.sort();
    let mut want = reaction_ids.clone();
    want.sort();
    assert_eq!(listed, want);

    let path = format!("{}?limit=3", chan.reactions(&m));
    let (s, p1) = call(env, None, "GET", &path, None).await;
    assert_eq!(s, StatusCode::OK, "{p1}");
    assert_eq!(ids(&p1).len(), 3);
    let c = next_cursor(&p1).unwrap();
    let (s, p2) = call(env, None, "GET", &format!("{path}&cursor={c}"), None).await;
    assert_eq!(s, StatusCode::OK, "{p2}");
    assert_valid(&reactions_page_schema(), &p2);
    let mut walked = ids(&p1);
    walked.extend(ids(&p2));
    assert_eq!(walked.len(), 4);
    assert_eq!(next_cursor(&p2), None);
    let (s, p) = call(
        env,
        None,
        "GET",
        &format!("{}?cursor=t1", chan.reactions(&m)),
        None,
    )
    .await;
    assert_problem(s, StatusCode::BAD_REQUEST, &p);

    // Removing: 204 whether held or not, and only the caller's own.
    for (who, key) in [
        (&cast.bob, "a"),
        (&cast.bob, "a"),
        (&cast.bob, "never"),
        (&cast.bob, "c"),
    ] {
        let (s, p) = raw(env, Some(who), "DELETE", &chan.reaction(&m, key), "").await;
        assert_eq!(s, StatusCode::NO_CONTENT, "{key}: {p}");
    }
    let (s, left) = call(env, None, "GET", &chan.reactions(&m), None).await;
    assert_eq!(s, StatusCode::OK, "{left}");
    let mut left: Vec<(String, String)> = left["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["author"].as_str().unwrap().to_owned(),
                r["key"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    left.sort();
    assert_eq!(
        left,
        [
            ("alice@providera.com".to_owned(), "a".to_owned()),
            ("bob@providera.com".to_owned(), "b".to_owned()),
            ("carol@providera.com".to_owned(), "c".to_owned()),
        ]
    );
    // A removed reaction can be added again, as new.
    let (s, _) = raw(env, Some(&cast.bob), "PUT", &chan.reaction(&m, "a"), "").await;
    assert_eq!(s, StatusCode::CREATED);
}

#[tokio::test]
async fn react_lists_who_may_react_and_readers_may_otherwise() {
    let env = env_with_remotes(&[]).await;
    let alice = local(&env, "alice").await;
    let bob = local(&env, "bob").await;
    let carol = local(&env, "carol").await;
    let dave = local(&env, "dave").await;
    let chan = group_and_channel(
        &env,
        &alice,
        "public",
        json!({}),
        json!({"type": "text", "tier": "public", "permissions": {"react": ["admin"]}}),
    )
    .await;
    join(&env, &chan.g, &bob, "member").await;
    join(&env, &chan.g, &dave, "admin").await;
    let m = id(&post(&env, &alice, &chan, text("admins react")).await);

    for who in [&bob, &carol] {
        let (s, p) = raw(&env, Some(who), "PUT", &chan.reaction(&m, "up"), "").await;
        assert_problem(s, StatusCode::FORBIDDEN, &p);
    }
    for who in [&alice, &dave] {
        let (s, p) = raw(&env, Some(who), "PUT", &chan.reaction(&m, "up"), "").await;
        assert_eq!(s, StatusCode::CREATED, "{p}");
    }
    // Everyone who reads the channel sees the reactions.
    let (s, page) = call(&env, None, "GET", &chan.reactions(&m), None).await;
    assert_eq!(s, StatusCode::OK, "{page}");
    assert_eq!(page["items"].as_array().unwrap().len(), 2);
}
