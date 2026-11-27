//! §7.2 paging over a list held in memory: the query parameters, opaque
//! cursors, and cutting one page out of a sorted list.
//!
//! rhypedb has no `ORDER BY`, so the lists paged here (a group's members and
//! join requests, both bounded by a provider limit) are read whole, sorted
//! by [`SortKey`] and cut (docs/decisions/0020).

use std::collections::HashMap;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use re_ofscp_types::wire::{Page, Paged};

use super::validate::Invalid;

/// Page size when the request names none, or a bad one (§7.2).
pub const DEFAULT_LIMIT: usize = 50;
/// Largest page; larger requests are clamped (§7.2).
pub const MAX_LIMIT: usize = 100;
/// Longest cursor accepted; anything longer was not issued here.
const MAX_CURSOR_LEN: usize = 512;

/// Which way a page walks (§7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Newest → oldest (the default).
    Backward,
    /// Oldest → newest.
    Forward,
}

/// Where an item sits in a list: by time, then by a unique id, so the
/// order is total and stable.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SortKey {
    /// Unix seconds (`joinedAt`, `requestedAt`).
    pub at: i64,
    /// A unique id within the list (a canonical actor, a request id).
    pub id: String,
}

/// The paging parameters of one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageQuery {
    /// The cursor sent, still opaque.
    pub cursor: Option<String>,
    /// The direction.
    pub direction: Direction,
    /// The page size, within `1..=MAX_LIMIT`.
    pub limit: usize,
}

impl PageQuery {
    /// From the query string (§7.2): any `direction` but `forward` is
    /// `backward`; a missing, non-numeric or non-positive `limit` is the
    /// default, a fractional one rounds down, a larger one is clamped.
    /// None of these are errors. An empty `cursor` is no cursor.
    pub fn from_params(params: &HashMap<String, String>) -> Self {
        Self {
            cursor: params.get("cursor").filter(|c| !c.is_empty()).cloned(),
            direction: match params.get("direction").map(String::as_str) {
                Some("forward") => Direction::Forward,
                _ => Direction::Backward,
            },
            limit: parse_limit(params.get("limit").map(String::as_str)),
        }
    }
}

/// §7.2 `limit`.
pub fn parse_limit(raw: Option<&str>) -> usize {
    let Some(n) = raw.and_then(|r| r.trim().parse::<f64>().ok()) else {
        return DEFAULT_LIMIT;
    };
    if !n.is_finite() || n < 1.0 {
        return DEFAULT_LIMIT;
    }
    if n >= MAX_LIMIT as f64 {
        return MAX_LIMIT;
    }
    // In 1..100 here, so the cast is exact after flooring.
    n.floor() as usize
}

/// The cursor naming `key` on the list `scope` (an endpoint and its
/// group): opaque to clients, and refused by any other list.
pub fn encode_cursor(scope: &str, key: &SortKey) -> String {
    B64URL.encode(format!("{scope}\n{}\n{}", key.at, key.id))
}

/// The key a cursor from [`encode_cursor`] names, if it was issued for
/// `scope`.
pub fn decode_cursor(scope: &str, cursor: &str) -> Option<SortKey> {
    if cursor.len() > MAX_CURSOR_LEN {
        return None;
    }
    let text = String::from_utf8(B64URL.decode(cursor).ok()?).ok()?;
    let mut parts = text.splitn(3, '\n');
    if parts.next()? != scope {
        return None;
    }
    let at = parts.next()?.parse().ok()?;
    let id = parts.next()?.to_owned();
    (!id.is_empty()).then_some(SortKey { at, id })
}

/// Page `query` of the list `scope`, from `items` in any order: the
/// §7.2 response body. A cursor not issued for `scope` is `400`.
pub fn page<T>(
    scope: &str,
    items: Vec<(SortKey, T)>,
    query: &PageQuery,
) -> Result<Paged<T>, Invalid> {
    let after = match query.cursor.as_deref() {
        None => None,
        Some(c) => Some(
            decode_cursor(scope, c)
                .ok_or_else(|| Invalid("`cursor` is not a cursor of this list".to_owned()))?,
        ),
    };
    let cut = cut(items, after.as_ref(), query.direction, query.limit);
    Ok(Paged {
        items: cut.items,
        page: Page {
            next_cursor: cut.next.map(|k| encode_cursor(scope, &k)),
            prev_cursor: cut.prev.map(|k| encode_cursor(scope, &k)),
        },
    })
}

/// One page cut from a list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cut<T> {
    /// The page's items, in the direction of travel.
    pub items: Vec<T>,
    /// The last item's key, when more items lie beyond it.
    pub next: Option<SortKey>,
    /// The first item's key, when items lie before it (walking the other
    /// way from it finds something).
    pub prev: Option<SortKey>,
}

/// Cut the page `after` (exclusive) a cursor key, in `direction`, of at
/// most `limit` items, from `items` in any order.
pub fn cut<T>(
    mut items: Vec<(SortKey, T)>,
    after: Option<&SortKey>,
    direction: Direction,
    limit: usize,
) -> Cut<T> {
    items.sort_by(|a, b| a.0.cmp(&b.0));
    if direction == Direction::Backward {
        items.reverse();
    }
    let beyond = |k: &SortKey| match (direction, after) {
        (_, None) => true,
        (Direction::Forward, Some(c)) => k > c,
        (Direction::Backward, Some(c)) => k < c,
    };
    // Items before the page in the direction of travel: those at or before
    // the cursor.
    let skipped = items.iter().take_while(|(k, _)| !beyond(k)).count();
    let mut rest = items.into_iter().skip(skipped);
    let page: Vec<(SortKey, T)> = rest.by_ref().take(limit).collect();
    let more = rest.next().is_some();
    let next = page.last().filter(|_| more).map(|(k, _)| k.clone());
    let prev = page.first().filter(|_| skipped > 0).map(|(k, _)| k.clone());
    Cut {
        items: page.into_iter().map(|(_, t)| t).collect(),
        next,
        prev,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(at: i64, id: &str) -> SortKey {
        SortKey {
            at,
            id: id.to_owned(),
        }
    }

    fn list() -> Vec<(SortKey, &'static str)> {
        // Deliberately unsorted; two items share a time.
        vec![
            (key(30, "c@a.com"), "c"),
            (key(10, "a@a.com"), "a"),
            (key(20, "b@b.com"), "b2"),
            (key(20, "b@a.com"), "b1"),
            (key(40, "d@a.com"), "d"),
        ]
    }

    #[test]
    fn limits_follow_the_spec() {
        assert_eq!(parse_limit(None), DEFAULT_LIMIT);
        assert_eq!(parse_limit(Some("abc")), DEFAULT_LIMIT);
        assert_eq!(parse_limit(Some("0")), DEFAULT_LIMIT);
        assert_eq!(parse_limit(Some("-4")), DEFAULT_LIMIT);
        assert_eq!(parse_limit(Some("NaN")), DEFAULT_LIMIT);
        assert_eq!(parse_limit(Some("inf")), DEFAULT_LIMIT);
        assert_eq!(parse_limit(Some("7")), 7);
        assert_eq!(parse_limit(Some("7.9")), 7);
        assert_eq!(parse_limit(Some("0.5")), DEFAULT_LIMIT);
        assert_eq!(parse_limit(Some("100")), 100);
        assert_eq!(parse_limit(Some("100000")), MAX_LIMIT);
    }

    #[test]
    fn parameters_default_to_backward() {
        let p = |pairs: &[(&str, &str)]| {
            PageQuery::from_params(
                &pairs
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                    .collect(),
            )
        };
        assert_eq!(p(&[]).direction, Direction::Backward);
        assert_eq!(
            p(&[("direction", "sideways")]).direction,
            Direction::Backward
        );
        assert_eq!(p(&[("direction", "forward")]).direction, Direction::Forward);
        assert_eq!(p(&[("cursor", "")]).cursor, None);
    }

    #[test]
    fn cursors_are_opaque_and_scoped() {
        let k = key(1_767_268_800, "alice@remote.example");
        let c = encode_cursor("members grp_1", &k);
        assert!(!c.contains("alice"));
        assert_eq!(decode_cursor("members grp_1", &c), Some(k));
        assert_eq!(decode_cursor("members grp_2", &c), None);
        assert_eq!(decode_cursor("requests grp_1", &c), None);
        for bad in ["", "!!!", "bWVtYmVycyBncnBfMQ", &"A".repeat(600)] {
            assert_eq!(decode_cursor("members grp_1", bad), None, "{bad}");
        }
    }

    #[test]
    fn backward_walks_newest_first_and_forward_oldest_first() {
        let all = cut(list(), None, Direction::Backward, 10);
        assert_eq!(all.items, ["d", "c", "b2", "b1", "a"]);
        assert_eq!((all.next, all.prev), (None, None));
        let all = cut(list(), None, Direction::Forward, 10);
        assert_eq!(all.items, ["a", "b1", "b2", "c", "d"]);
    }

    #[test]
    fn pages_chain_through_next_cursors_without_overlap() {
        let first = cut(list(), None, Direction::Backward, 2);
        assert_eq!(first.items, ["d", "c"]);
        assert_eq!(first.prev, None);
        let next = first.next.unwrap();
        assert_eq!(next, key(30, "c@a.com"));
        let second = cut(list(), Some(&next), Direction::Backward, 2);
        assert_eq!(second.items, ["b2", "b1"]);
        assert_eq!(second.prev, Some(key(20, "b@b.com")));
        let third = cut(list(), second.next.as_ref(), Direction::Backward, 2);
        assert_eq!(third.items, ["a"]);
        assert_eq!(third.next, None);
        // Walking back the other way from a page's prevCursor finds what
        // came before it, exclusive of its first item.
        let back = cut(list(), second.prev.as_ref(), Direction::Forward, 10);
        assert_eq!(back.items, ["c", "d"]);
    }

    #[test]
    fn a_page_carries_opaque_cursors_and_refuses_foreign_ones() {
        let first = PageQuery {
            cursor: None,
            direction: Direction::Backward,
            limit: 2,
        };
        let p = page("members g", list(), &first).unwrap();
        assert_eq!(p.items, ["d", "c"]);
        assert!(p.page.prev_cursor.is_none());
        let next = PageQuery {
            cursor: p.page.next_cursor.clone(),
            ..first.clone()
        };
        let p2 = page("members g", list(), &next).unwrap();
        assert_eq!(p2.items, ["b2", "b1"]);
        assert!(p2.page.prev_cursor.is_some());
        assert!(page("requests g", list(), &next).is_err());
    }

    #[test]
    fn a_cursor_past_the_end_gives_an_empty_page() {
        let end = cut(list(), Some(&key(0, "x")), Direction::Backward, 5);
        assert!(end.items.is_empty());
        assert_eq!((end.next, end.prev), (None, None));
    }
}
