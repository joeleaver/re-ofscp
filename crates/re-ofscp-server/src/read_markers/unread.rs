//! Counting unread messages (spec §7.7): the messages in a channel newer
//! than the reader's marker that the reader did not write.
//!
//! rhypedb has no count aggregate and no ordered range scan, so a count
//! reads the timeline positions after the marker in batches of exact
//! position lookups (as paging does, `messages::pager`). The work is
//! bounded: counting stops past [`UNREAD_COUNT_MAX`] messages or after
//! [`UNREAD_SCAN_MAX`] positions, and the scope is then reported as
//! *at least* that many, flagged `unreadCountCapped` (docs/decisions/0021).
//!
//! A tombstone keeps its position and counts, as it stays in history.

use re_ofscp_types::Actor;

use crate::db::DbError;
use crate::messages::store::MessageStore;

/// The largest count reported exactly. Past it a scope reports this many
/// and is flagged as capped.
pub const UNREAD_COUNT_MAX: u64 = 100;
/// Most timeline positions one count reads. Positions also hold edits and
/// deletes, so this leaves room for many of those per message.
pub const UNREAD_SCAN_MAX: i64 = 1_000;
/// Positions asked for per query.
const BATCH: i64 = 100;

/// An unread count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unread {
    /// Messages counted, at most [`UNREAD_COUNT_MAX`].
    pub count: u64,
    /// Whether there may be more than `count`.
    pub capped: bool,
}

/// The messages `reader` did not write at positions `after + 1 ..= last`
/// of `channel_id`'s timeline.
pub async fn count(
    store: &MessageStore,
    channel_id: &str,
    after: i64,
    last: i64,
    reader: &Actor,
) -> Result<Unread, DbError> {
    let reader = reader.to_string();
    let scan_end = last.min(after.saturating_add(UNREAD_SCAN_MAX));
    let mut count: u64 = 0;
    let mut from = after.saturating_add(1);
    while from <= scan_end {
        let to = scan_end.min(from + BATCH - 1);
        let positions: Vec<i64> = (from..=to).collect();
        let found = store.authors_at(channel_id, &positions).await?;
        count += found.iter().filter(|(_, author)| *author != reader).count() as u64;
        if count > UNREAD_COUNT_MAX {
            return Ok(Unread {
                count: UNREAD_COUNT_MAX,
                capped: true,
            });
        }
        from = to + 1;
    }
    Ok(Unread {
        count,
        capped: scan_end < last,
    })
}
