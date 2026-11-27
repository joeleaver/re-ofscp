//! Reading every row a filter matches, when there may be more than one
//! query should return, without relying on an order rhypedb does not
//! promise.
//!
//! rhypedb has no `.order`, and the order of a filter's results is
//! unspecified (its `queries.md`), so offset paging can skip or repeat
//! rows. Instead the rows are split by a key that is unique among them, in
//! ranges `(after, through]` of that key: a range is read whole in one
//! query, so it is one snapshot, and a range that comes back fuller than a
//! page is narrowed at the middle key read and read again. A row whose key
//! does not change lies in exactly one range, so it is read exactly once,
//! whatever else changes while the ranges are read. (The same walk as
//! `Messages::number_all` over open channel logs.)

use std::future::Future;

use super::DbError;

/// Every row `read` finds, reading at most `page + 1` rows a query.
///
/// `read(after, through, limit)` must return up to `limit` of the rows
/// whose key is greater than `after` and, when `through` is `Some`, at most
/// `through` (in any order); `key` gives a row's key, which must be unique
/// among the rows read and never the empty string. `page` must be at least
/// 2, so a narrowed range always shrinks.
pub async fn read_all<R, K, F, Fut>(page: usize, key: K, mut read: F) -> Result<Vec<R>, DbError>
where
    K: Fn(&R) -> &str,
    F: FnMut(String, Option<String>, u64) -> Fut,
    Fut: Future<Output = Result<Vec<R>, DbError>>,
{
    let page = page.max(2);
    let mut out = Vec::new();
    let mut after = String::new();
    let mut through: Option<String> = None;
    // Upper bounds narrowed away, the innermost last; `None` is no bound.
    let mut bounds: Vec<Option<String>> = Vec::new();
    loop {
        let rows = read(after.clone(), through.clone(), page as u64 + 1).await?;
        if rows.len() > page {
            let mut keys: Vec<&str> = rows.iter().map(&key).collect();
            keys.sort_unstable();
            // At least half of what was read lies above the new bound, and
            // at least one key at or below it, so both halves shrink.
            let middle = keys[keys.len() / 2 - 1].to_owned();
            bounds.push(through.replace(middle));
            continue;
        }
        out.extend(rows);
        match through {
            None => return Ok(out),
            Some(read_through) => {
                after = read_through;
                through = bounds.pop().flatten();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeSet;

    use super::*;

    /// A fake table answering in a scrambled order, as rhypedb may.
    fn reader(
        rows: &RefCell<BTreeSet<String>>,
        queries: &RefCell<usize>,
    ) -> impl FnMut(String, Option<String>, u64) -> std::future::Ready<Result<Vec<String>, DbError>>
    {
        move |after, through, limit| {
            *queries.borrow_mut() += 1;
            let mut found: Vec<String> = rows
                .borrow()
                .iter()
                .filter(|k| **k > after && through.as_ref().is_none_or(|t| *k <= t))
                .cloned()
                .collect();
            // Reverse, then interleave: anything but key order.
            found.reverse();
            let (even, odd): (Vec<_>, Vec<_>) =
                found.into_iter().enumerate().partition(|(i, _)| i % 2 == 0);
            let mut scrambled: Vec<String> = odd.into_iter().chain(even).map(|(_, k)| k).collect();
            scrambled.truncate(limit as usize);
            std::future::ready(Ok(scrambled))
        }
    }

    fn run<T>(f: impl Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(f)
    }

    #[test]
    fn every_row_is_read_exactly_once_across_many_pages() {
        let keys: BTreeSet<String> = (0..537).map(|i| format!("user{i:04}")).collect();
        let rows = RefCell::new(keys.clone());
        let queries = RefCell::new(0);
        let got = run(read_all(
            10,
            |k: &String| k.as_str(),
            reader(&rows, &queries),
        ))
        .unwrap();
        assert_eq!(got.len(), keys.len());
        assert_eq!(got.into_iter().collect::<BTreeSet<_>>(), keys);
        // Narrowing halves a range each time: far fewer than one query per row.
        assert!(*queries.borrow() < 300, "{} queries", queries.borrow());
    }

    #[test]
    fn a_page_or_less_is_one_query() {
        for n in [0, 1, 10] {
            let rows = RefCell::new((0..n).map(|i| format!("k{i:02}")).collect());
            let queries = RefCell::new(0);
            let got = run(read_all(
                10,
                |k: &String| k.as_str(),
                reader(&rows, &queries),
            ))
            .unwrap();
            assert_eq!(got.len(), n);
            assert_eq!(*queries.borrow(), 1);
        }
    }

    #[test]
    fn rows_that_stay_put_are_read_despite_others_changing_meanwhile() {
        let rows = RefCell::new(
            (0..100)
                .map(|i| format!("k{i:03}"))
                .collect::<BTreeSet<_>>(),
        );
        let queries = RefCell::new(0);
        let mut inner = reader(&rows, &queries);
        let mut calls = 0;
        // Between queries, a low row goes and a new one arrives: an offset
        // walk would shift the bystanders across a page boundary.
        let churn = |after: String, through: Option<String>, limit: u64| {
            calls += 1;
            {
                let mut r = rows.borrow_mut();
                r.remove(&format!("k{calls:03}"));
                r.insert(format!("a{calls:03}"));
            }
            inner(after, through, limit)
        };
        let got: BTreeSet<String> = run(read_all(7, |k: &String| k.as_str(), churn))
            .unwrap()
            .into_iter()
            .collect();
        // Every row that was there throughout was read.
        for i in (calls + 1)..100 {
            assert!(got.contains(&format!("k{i:03}")), "k{i:03} missing");
        }
    }
}
