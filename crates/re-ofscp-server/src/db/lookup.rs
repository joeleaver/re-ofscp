//! Fetching many rows by one `@unique` field in as few queries as fit.

use serde::de::DeserializeOwned;

use super::{Db, DbError, Ql};

/// The longest a lookup's query text may grow before it is split (rhypedb
/// takes at most 16 KiB of query).
pub const MAX_LOOKUP_TEXT: usize = 12 * 1024;

/// Run `{head}{field}k1 || {field}k2 …)` over `keys`, for example
/// `head = "Message.filter("` and `field = ".pos == "`, split so that no
/// query grows past [`MAX_LOOKUP_TEXT`]. A top-level disjunction of
/// `@unique` equalities is a union of point lookups in rhypedb's planner.
/// Returns the rows found, in no particular order.
pub async fn lookup<R: DeserializeOwned>(
    db: &Db,
    head: &'static str,
    field: &'static str,
    keys: &[String],
) -> Result<Vec<R>, DbError> {
    let mut out = Vec::new();
    let mut rest = keys;
    while !rest.is_empty() {
        let mut q = Ql::new(head);
        let mut taken = 0;
        for (i, k) in rest.iter().enumerate() {
            // A key's text, escaped, is at most twice its length.
            if i > 0 && q.as_str().len() + 2 * k.len() + field.len() + 8 > MAX_LOOKUP_TEXT {
                break;
            }
            q = q.raw(if i == 0 { "" } else { " || " }).raw(field).str(k);
            taken += 1;
        }
        q = q.raw(")");
        out.extend(db.fetch::<R>(&q).await?.into_iter().map(|r| r.data));
        rest = &rest[taken..];
    }
    Ok(out)
}
