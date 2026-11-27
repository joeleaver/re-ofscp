//! Paging over a sparse sequence of positions (§7.2 paging parameters).
//!
//! History, replies and reactions all live at integer positions 1, 2, 3…
//! (a channel's timeline, a message's replies, a message's reactions; see
//! `schema.rhype`). Some positions hold nothing: an edit's or delete's
//! timeline position holds no message, a write that failed after taking
//! its position left a gap, and a removed reaction left one too. A page is
//! read by asking for batches of exact positions, nearest the cursor
//! first, until it is full, the sequence ends, or [`MAX_SCAN`] positions
//! have been looked at.
//!
//! Cursors are opaque strings (§7.2): a one-letter tag naming the endpoint
//! kind, then the position. A cursor with another endpoint's tag is
//! refused, as cursors are "only valid on the endpoint that issued them".

use std::collections::HashMap;
use std::future::Future;

use ofscp_core::wire::Page;

/// `limit` when absent or unusable (§7.2).
pub const DEFAULT_LIMIT: usize = 50;
/// The largest `limit`; larger values are clamped (§7.2).
pub const MAX_LIMIT: usize = 100;
/// Most positions one page looks at. A page cut short by it still carries
/// `nextCursor`, so the client walks on past a long run of gaps.
pub const MAX_SCAN: i64 = 2000;
/// Most positions asked for in one query.
const BATCH: i64 = 100;

/// Which endpoint a cursor belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CursorKind {
    /// A channel timeline (`…/messages`, and live events' `cursor`).
    Timeline,
    /// A message's replies (`…/replies`).
    Replies,
    /// A message's reactions (`…/reactions`).
    Reactions,
}

impl CursorKind {
    fn tag(self) -> char {
        match self {
            CursorKind::Timeline => 't',
            CursorKind::Replies => 'r',
            CursorKind::Reactions => 'x',
        }
    }
}

/// The cursor for position `pos` of `kind`.
pub fn encode_cursor(kind: CursorKind, pos: i64) -> String {
    format!("{}{pos}", kind.tag())
}

/// The position a cursor of `kind` names, or `None` if it is not one.
pub fn decode_cursor(kind: CursorKind, cursor: &str) -> Option<i64> {
    let digits = cursor.strip_prefix(kind.tag())?;
    if digits.is_empty() || digits.len() > 18 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// The direction of travel (§7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Newest first (the default).
    Backward,
    /// Oldest first.
    Forward,
}

/// A request for one page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageRequest {
    /// The direction of travel.
    pub direction: Direction,
    /// The exclusive starting position, if the client sent a cursor.
    pub cursor: Option<i64>,
    /// How many items at most.
    pub limit: usize,
}

/// A cursor that is not one of this endpoint's (`400`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("cursor is not one this endpoint issued")]
pub struct BadCursor;

impl PageRequest {
    /// The paging parameters of a query string (§7.2): an unknown
    /// `direction` is `backward`, and an absent, non-numeric or
    /// non-positive `limit` is the default; neither is an error. Only a
    /// cursor this endpoint could not have issued is refused.
    pub fn from_query(kind: CursorKind, q: &HashMap<String, String>) -> Result<Self, BadCursor> {
        let direction = match q.get("direction").map(String::as_str) {
            Some("forward") => Direction::Forward,
            _ => Direction::Backward,
        };
        let cursor = match q.get("cursor") {
            None => None,
            Some(c) => Some(decode_cursor(kind, c).ok_or(BadCursor)?),
        };
        Ok(Self {
            direction,
            cursor,
            limit: parse_limit(q.get("limit").map(String::as_str)),
        })
    }
}

/// §7.2 `limit`: fractional values round down, larger ones clamp to
/// [`MAX_LIMIT`], anything else unusable means [`DEFAULT_LIMIT`].
fn parse_limit(raw: Option<&str>) -> usize {
    let Some(v) = raw.and_then(|s| s.trim().parse::<f64>().ok()) else {
        return DEFAULT_LIMIT;
    };
    if !v.is_finite() || v < 1.0 {
        return DEFAULT_LIMIT;
    }
    // Clamp before converting, so a huge value cannot overflow.
    v.min(MAX_LIMIT as f64).floor() as usize
}

/// One page: the items in the direction of travel, each with its
/// position, and the page's cursors.
#[derive(Debug, Clone, PartialEq)]
pub struct Walked<T> {
    /// The items, with their positions.
    pub items: Vec<(i64, T)>,
    /// `nextCursor` and `prevCursor`.
    pub page: Page,
}

/// Read one page of a sequence whose last position is `last`. `fetch`
/// returns the items found at the positions it is given (any order, gaps
/// left out).
pub async fn walk<T, E, F, Fut>(
    kind: CursorKind,
    req: PageRequest,
    last: i64,
    mut fetch: F,
) -> Result<Walked<T>, E>
where
    F: FnMut(Vec<i64>) -> Fut,
    Fut: Future<Output = Result<Vec<(i64, T)>, E>>,
{
    let (step, mut next) = match req.direction {
        Direction::Backward => (-1, req.cursor.map_or(last, |c| c.min(last + 1) - 1)),
        Direction::Forward => (1, req.cursor.map_or(1, |c| c.max(0) + 1)),
    };
    let in_range = |p: i64| (1..=last).contains(&p);
    let mut items: Vec<(i64, T)> = Vec::new();
    let mut scanned = 0;
    let mut last_scanned = None;
    while items.len() <= req.limit && in_range(next) && scanned < MAX_SCAN {
        let want = (req.limit + 1 - items.len()) as i64;
        let size = want.clamp(1, BATCH).min(MAX_SCAN - scanned);
        let positions: Vec<i64> = (0..size)
            .map(|i| next + i * step)
            .take_while(|p| in_range(*p))
            .collect();
        let Some(&end) = positions.last() else {
            break;
        };
        scanned += positions.len() as i64;
        last_scanned = Some(end);
        next = end + step;
        let mut found = fetch(positions).await?;
        found.sort_by_key(|(p, _)| p * step);
        items.extend(found);
    }
    let more_left = in_range(next) && last_scanned.is_some();
    let next_cursor = if items.len() > req.limit {
        items.truncate(req.limit);
        items.last().map(|(p, _)| *p)
    } else if more_left {
        // Cut short by the scan budget: there may be more past the gaps.
        last_scanned
    } else {
        None
    };
    Ok(Walked {
        page: Page {
            next_cursor: next_cursor.map(|p| encode_cursor(kind, p)),
            prev_cursor: items.first().map(|(p, _)| encode_cursor(kind, *p)),
        },
        items,
    })
}

#[cfg(test)]
#[path = "pager_tests.rs"]
mod tests;
