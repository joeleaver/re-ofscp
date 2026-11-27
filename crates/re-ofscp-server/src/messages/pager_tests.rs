//! Unit tests for the paging walker and cursors.

use std::collections::{BTreeSet, HashMap};
use std::convert::Infallible;

use super::*;

fn req(direction: Direction, cursor: Option<i64>, limit: usize) -> PageRequest {
    PageRequest {
        direction,
        cursor,
        limit,
    }
}

/// Walk a sequence `1..=last` holding items at `present`, counting the
/// queries.
async fn run(present: &BTreeSet<i64>, last: i64, r: PageRequest) -> (Vec<i64>, Page, usize) {
    let mut queries = 0;
    let walked = walk(CursorKind::Timeline, r, last, |ps: Vec<i64>| {
        queries += 1;
        let found: Vec<(i64, ())> = ps
            .into_iter()
            .rev()
            .filter(|p| present.contains(p))
            .map(|p| (p, ()))
            .collect();
        async move { Ok::<_, Infallible>(found) }
    })
    .await
    .unwrap();
    (
        walked.items.into_iter().map(|(p, _)| p).collect(),
        walked.page,
        queries,
    )
}

fn cur(p: i64) -> Option<String> {
    Some(encode_cursor(CursorKind::Timeline, p))
}

#[tokio::test]
async fn backward_pages_newest_first_and_chain_with_next_cursor() {
    let all: BTreeSet<i64> = (1..=7).collect();
    let (items, page, _) = run(&all, 7, req(Direction::Backward, None, 3)).await;
    assert_eq!(items, [7, 6, 5]);
    assert_eq!((page.next_cursor, page.prev_cursor), (cur(5), cur(7)));
    let (items, page, _) = run(&all, 7, req(Direction::Backward, Some(5), 3)).await;
    assert_eq!(items, [4, 3, 2]);
    assert_eq!(page.next_cursor, cur(2));
    let (items, page, _) = run(&all, 7, req(Direction::Backward, Some(2), 3)).await;
    assert_eq!(items, [1]);
    assert_eq!((page.next_cursor, page.prev_cursor), (None, cur(1)));
}

#[tokio::test]
async fn forward_pages_oldest_first_and_prev_cursor_walks_back() {
    let all: BTreeSet<i64> = (1..=5).collect();
    let (items, page, _) = run(&all, 5, req(Direction::Forward, None, 2)).await;
    assert_eq!(items, [1, 2]);
    assert_eq!(page.next_cursor, cur(2));
    let (items, page, _) = run(&all, 5, req(Direction::Forward, Some(2), 10)).await;
    assert_eq!(items, [3, 4, 5]);
    assert_eq!((page.next_cursor, page.prev_cursor), (None, cur(3)));
    // prevCursor with the opposite direction excludes the page's first item.
    let (items, _, _) = run(&all, 5, req(Direction::Backward, Some(3), 10)).await;
    assert_eq!(items, [2, 1]);
}

#[tokio::test]
async fn gaps_are_skipped_and_an_exact_fit_has_no_next_cursor() {
    let some: BTreeSet<i64> = [2, 5, 9].into();
    let (items, page, _) = run(&some, 10, req(Direction::Backward, None, 3)).await;
    assert_eq!(items, [9, 5, 2]);
    assert_eq!(page.next_cursor, None);
    let (items, page, _) = run(&some, 10, req(Direction::Forward, None, 2)).await;
    assert_eq!(items, [2, 5]);
    assert_eq!(page.next_cursor, cur(5));
}

#[tokio::test]
async fn empty_and_out_of_range_sequences_give_an_empty_page() {
    let none = BTreeSet::new();
    let (items, page, queries) = run(&none, 0, req(Direction::Backward, None, 50)).await;
    assert!(items.is_empty() && page == Page::default());
    assert_eq!(queries, 0);
    let all: BTreeSet<i64> = (1..=3).collect();
    // A cursor past either end is clamped, not an error.
    let (items, _, _) = run(&all, 3, req(Direction::Backward, Some(99), 50)).await;
    assert_eq!(items, [3, 2, 1]);
    let (items, _, _) = run(&all, 3, req(Direction::Forward, Some(99), 50)).await;
    assert!(items.is_empty());
}

#[tokio::test]
async fn a_long_run_of_gaps_stops_at_the_scan_budget_with_a_cursor_to_go_on() {
    let far: BTreeSet<i64> = [1].into();
    let last = MAX_SCAN + 500;
    let (items, page, queries) = run(&far, last, req(Direction::Backward, None, 50)).await;
    assert!(items.is_empty());
    assert_eq!(page.next_cursor, cur(last - MAX_SCAN + 1));
    assert!(queries as i64 <= MAX_SCAN / 51 + 2, "{queries} queries");
    let (items, page, _) = run(
        &far,
        last,
        req(Direction::Backward, Some(last - MAX_SCAN + 1), 50),
    )
    .await;
    assert_eq!(items, [1]);
    assert_eq!(page.next_cursor, None);
}

#[test]
fn query_parameters_follow_section_7_2() {
    let q = |pairs: &[(&str, &str)]| -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    };
    let parse = |pairs: &[(&str, &str)]| PageRequest::from_query(CursorKind::Timeline, &q(pairs));
    let d = parse(&[]).unwrap();
    assert_eq!(d, req(Direction::Backward, None, DEFAULT_LIMIT));
    for (raw, want) in [
        ("10", 10),
        ("10.9", 10),
        ("1000", MAX_LIMIT),
        ("1e300", MAX_LIMIT),
        ("0", DEFAULT_LIMIT),
        ("0.5", DEFAULT_LIMIT),
        ("-3", DEFAULT_LIMIT),
        ("x", DEFAULT_LIMIT),
        ("NaN", DEFAULT_LIMIT),
    ] {
        assert_eq!(parse(&[("limit", raw)]).unwrap().limit, want, "{raw}");
    }
    assert_eq!(
        parse(&[("direction", "sideways")]).unwrap().direction,
        Direction::Backward
    );
    assert_eq!(
        parse(&[("direction", "forward"), ("cursor", "t42")]).unwrap(),
        req(Direction::Forward, Some(42), DEFAULT_LIMIT)
    );
    for bad in ["", "t", "42", "r42", "t-1", "t4x", "t99999999999999999999"] {
        assert_eq!(parse(&[("cursor", bad)]), Err(BadCursor), "{bad}");
    }
}
