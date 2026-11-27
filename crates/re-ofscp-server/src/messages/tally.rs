//! How many messages each author has in each channel (`MessageTally` in
//! `schema.rhype`; §7.7 unread counts, docs/decisions/0021). One row per
//! (channel, author), keyed `@unique` by `"{channel} {author}"`: neither a
//! channel's local id nor a canonical actor holds a space.
//!
//! A create takes its author's next ordinal (`Message.author_n`) here by a
//! compare-and-set on `count`, while it is pending on the channel's log
//! (`log::take_create`); a create that fails gives it back.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::db::lookup::lookup;
use crate::db::{Db, DbError, Ql};

/// How often a tally is retried while other writers keep winning.
const ATTEMPTS: usize = 32;

#[derive(Deserialize)]
struct TallyRow {
    key: String,
    channel_id: String,
    count: i64,
}

fn key(channel_id: &str, author: &str) -> String {
    format!("{channel_id} {author}")
}

fn by_key(channel_id: &str, author: &str) -> Ql {
    Ql::new("MessageTally.filter(.key == ").str(&key(channel_id, author))
}

/// `author`'s tally in `channel_id`: `0` when they have no messages there.
pub async fn get(db: &Db, channel_id: &str, author: &str) -> Result<i64, DbError> {
    let q = by_key(channel_id, author).raw(")");
    Ok(db
        .fetch::<TallyRow>(&q)
        .await?
        .into_iter()
        .next()
        .map_or(0, |r| r.data.count))
}

/// `author`'s tally in each of `channel_ids`, by channel id, in a batch of
/// point lookups. A channel where they have no messages is left out.
pub async fn for_author(
    db: &Db,
    channel_ids: &[String],
    author: &str,
) -> Result<BTreeMap<String, i64>, DbError> {
    let keys: Vec<String> = channel_ids.iter().map(|c| key(c, author)).collect();
    let rows: Vec<TallyRow> = lookup(db, "MessageTally.filter(", ".key == ", &keys).await?;
    Ok(rows
        .into_iter()
        // A lookup returns only the keys asked for; checked all the same.
        .filter(|r| r.key == key(&r.channel_id, author))
        .map(|r| (r.channel_id, r.count))
        .collect())
}

/// Take `author`'s next ordinal in `channel_id`: their tally plus one,
/// which the tally then holds.
pub async fn take(db: &Db, channel_id: &str, author: &str) -> Result<i64, DbError> {
    for _ in 0..ATTEMPTS {
        let q = by_key(channel_id, author).raw(")");
        let current = db.fetch::<TallyRow>(&q).await?.into_iter().next();
        match current {
            None => {
                let q = Ql::new("MessageTally.create({ key: ")
                    .str(&key(channel_id, author))
                    .raw(", channel_id: ")
                    .str(channel_id)
                    .raw(", count: 1 })");
                match db.execute(&q).await {
                    Ok(()) => return Ok(1),
                    // Another writer created it first: take from theirs.
                    Err(DbError::Conflict(_) | DbError::Contended(_)) => {}
                    Err(e) => return Err(e),
                }
            }
            Some(row) => {
                let count = row.data.count;
                if set_from(db, channel_id, author, count, count.saturating_add(1)).await? {
                    return Ok(count.saturating_add(1));
                }
            }
        }
    }
    Err(DbError::Contended(format!(
        "message tally {channel_id}: kept moving"
    )))
}

/// Give back `author`'s ordinal `n` in `channel_id`, if it is still the
/// last one taken. Returns whether it was.
pub async fn give_back(db: &Db, channel_id: &str, author: &str, n: i64) -> Result<bool, DbError> {
    if n < 1 {
        return Ok(false);
    }
    set_from(db, channel_id, author, n, n - 1).await
}

/// Set `author`'s tally in `channel_id` to `count`, whatever it was:
/// numbering a channel's existing messages (`ordinals.rs`). Idempotent.
pub async fn set(db: &Db, channel_id: &str, author: &str, count: i64) -> Result<(), DbError> {
    for _ in 0..ATTEMPTS {
        let q = by_key(channel_id, author).raw(")");
        match db.fetch::<TallyRow>(&q).await?.into_iter().next() {
            Some(row) if row.data.count == count => return Ok(()),
            Some(row) => {
                if set_from(db, channel_id, author, row.data.count, count).await? {
                    return Ok(());
                }
            }
            None => {
                let q = Ql::new("MessageTally.create({ key: ")
                    .str(&key(channel_id, author))
                    .raw(", channel_id: ")
                    .str(channel_id)
                    .raw(", count: ")
                    .int(count)
                    .raw(" })");
                match db.execute(&q).await {
                    Ok(()) => return Ok(()),
                    Err(DbError::Conflict(_) | DbError::Contended(_)) => {}
                    Err(e) => return Err(e),
                }
            }
        }
    }
    Err(DbError::Contended(format!(
        "message tally {channel_id}: kept moving"
    )))
}

/// Compare-and-set `author`'s tally in `channel_id` from `from` to `to`.
async fn set_from(
    db: &Db,
    channel_id: &str,
    author: &str,
    from: i64,
    to: i64,
) -> Result<bool, DbError> {
    let q = by_key(channel_id, author)
        .raw(" && .count == ")
        .int(from)
        .raw(").update({ count: ")
        .int(to)
        .raw(" })");
    Ok(!db.write_one_object(&q).await?.into_objects().is_empty())
}
