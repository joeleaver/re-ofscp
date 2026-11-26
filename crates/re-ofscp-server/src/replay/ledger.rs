//! The persistent side of the replay store (spec §4.5 "Restarts": a provider
//! SHOULD persist the store).
//!
//! Every nonce the in-memory store records is also written to the ledger
//! *before* the request is accepted, under a `@unique` key, and every live
//! nonce is read back at startup. With the ledger restored, a restart
//! forgets nothing, so the warm-up (`503` for one skew window) is skipped.
//! If the ledger cannot be read at startup, the warm-up applies as before.
//!
//! A nonce the ledger cannot write fails closed with `503`: the in-memory
//! entry stays (the nonce remains burned) and the client re-signs and
//! retries, as §4.5 requires for any `503`.
//!
//! The ledger does not depend on a guarded write: rows are created under a
//! `@unique` key and deleted, never updated. (Since rhypedb #59, in
//! 7b78190, a filtered `update`/`delete` is compare-and-set per object, but
//! this design predates it, needs no more, and a `@unique` create also
//! covers the persisted clock's multi-row logic; decision 0012.) A filter
//! over the rows is exact, and every outcome below holds however many
//! writers race, in this process or another.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde::Deserialize;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::{NonceUse, SignerKind};
use crate::db::{Db, DbError, Ql};

/// A nonce as the ledger stores it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredNonce {
    /// Actor or provider.
    pub kind: SignerKind,
    /// Canonical signer identity.
    pub signer: String,
    /// The signer's home authority.
    pub domain: String,
    /// Key id.
    pub key_id: String,
    /// Nonce.
    pub nonce: String,
    /// The signature's timestamp (unix seconds).
    pub signed_at: i64,
    /// When the entry expires (unix seconds).
    pub expires: i64,
}

impl StoredNonce {
    /// From a use the in-memory store just recorded.
    pub fn from_use(u: &NonceUse<'_>, expires: i64) -> Self {
        Self {
            kind: u.kind,
            signer: u.signer.to_owned(),
            domain: u.domain.to_owned(),
            key_id: u.key_id.to_owned(),
            nonce: u.nonce.to_owned(),
            signed_at: u.signed_at,
            expires,
        }
    }

    /// As a use, for the in-memory store.
    pub fn as_use(&self) -> NonceUse<'_> {
        NonceUse {
            kind: self.kind,
            signer: &self.signer,
            domain: &self.domain,
            key_id: &self.key_id,
            nonce: &self.nonce,
            signed_at: self.signed_at,
        }
    }

    /// The ledger's unique key: SHA-256 over the replay identity *(kind, key
    /// id, nonce)*, length-prefixed so no two identities share an encoding.
    pub fn ledger_key(&self) -> String {
        let mut h = Sha256::new();
        h.update(kind_str(self.kind).as_bytes());
        h.update(b"\n");
        h.update(self.key_id.len().to_string().as_bytes());
        h.update(b"\n");
        h.update(self.key_id.as_bytes());
        h.update(b"\n");
        h.update(self.nonce.as_bytes());
        h.finalize().iter().map(|b| format!("{b:02x}")).collect()
    }
}

fn kind_str(kind: SignerKind) -> &'static str {
    match kind {
        SignerKind::Actor => "actor",
        SignerKind::Provider => "provider",
    }
}

fn parse_kind(s: &str) -> Option<SignerKind> {
    match s {
        "actor" => Some(SignerKind::Actor),
        "provider" => Some(SignerKind::Provider),
        _ => None,
    }
}

/// Why the ledger refused or failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LedgerError {
    /// The nonce is already in the ledger: a replay.
    #[error("nonce already recorded")]
    Duplicate,
    /// The ledger could not be reached or read.
    #[error("replay ledger unavailable: {0}")]
    Unavailable(String),
    /// This ledger does not persist anything (warm-up stays in force).
    #[error("replay ledger does not persist")]
    NotPersistent,
}

/// Boxed future returned by ledger methods.
pub type LedgerFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, LedgerError>> + Send + 'a>>;

/// What the ledger held at startup.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Restored {
    /// Every nonce still live.
    pub nonces: Vec<StoredNonce>,
    /// The replay clock the previous process persisted, if any.
    pub clock: Option<i64>,
}

/// Durable storage for recorded nonces.
pub trait NonceLedger: Send + Sync {
    /// Durably record `n`. A row with the same identity that already
    /// expired by `now` is replaced; a live one is
    /// [`LedgerError::Duplicate`].
    fn persist<'a>(&'a self, n: &'a StoredNonce, now: i64) -> LedgerFuture<'a, ()>;
    /// Every nonce still live at `now`, and the persisted replay clock.
    fn load(&self, now: i64) -> LedgerFuture<'_, Restored>;
    /// Persist the replay clock as at least `clock`, then delete nonces
    /// expired by it. Pass the store's clock ([`super::ReplayStore::clock`]),
    /// never a raw wall-clock reading: what is deleted must stay expired
    /// after a restart, which the persisted clock guarantees.
    fn purge(&self, clock: i64) -> LedgerFuture<'_, ()>;
}

/// A ledger that persists nothing: the in-memory store alone, with the
/// restart warm-up. For tests, and as a deliberate opt-out.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoLedger;

impl NonceLedger for NoLedger {
    fn persist<'a>(&'a self, _n: &'a StoredNonce, _now: i64) -> LedgerFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
    fn load(&self, _now: i64) -> LedgerFuture<'_, Restored> {
        Box::pin(async { Err(LedgerError::NotPersistent) })
    }
    fn purge(&self, _clock: i64) -> LedgerFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
}

/// The rhypedb-backed ledger (`ReplayNonce` and `ReplayClock` in
/// `schema.rhype`).
#[derive(Debug, Clone)]
pub struct RhypeLedger {
    db: Arc<Db>,
    page: u64,
    clock_page: u64,
}

/// Rows read per page when restoring.
const LOAD_PAGE: u64 = 5_000;

/// Rows deleted per purge statement, and statements per purge run, so one
/// purge never becomes a single unbounded delete (each statement stays well
/// inside the query timeout; a backlog drains over successive runs).
const PURGE_BATCH: u64 = 1_000;
const PURGE_MAX_BATCHES: usize = 100;

/// Clock rows read per statement (pruning keeps one or two, so a full page
/// is logged as pruning lagging).
const CLOCK_PAGE: u64 = 1_000;

#[derive(Deserialize)]
struct NonceRow {
    kind: String,
    signer: String,
    domain: String,
    key_id: String,
    nonce: String,
    signed_at: String,
    expires_at: String,
}

#[derive(Deserialize)]
struct ClockRow {
    high_water: String,
}

#[derive(Deserialize)]
struct ExpiryRow {
    expires_at: String,
}

/// Any row (only its existence matters).
#[derive(Deserialize)]
struct Exists {}

fn unix(rfc3339: &str) -> Result<i64, LedgerError> {
    OffsetDateTime::parse(rfc3339, &Rfc3339)
        .map(OffsetDateTime::unix_timestamp)
        .map_err(|e| LedgerError::Unavailable(format!("bad DateTime {rfc3339:?}: {e}")))
}

fn unavailable(e: DbError) -> LedgerError {
    LedgerError::Unavailable(e.to_string())
}

impl RhypeLedger {
    /// A ledger over `db`.
    pub fn new(db: Arc<Db>) -> Self {
        Self::with_page_size(db, LOAD_PAGE)
    }

    /// As [`RhypeLedger::new`], reading `page` rows per query when restoring
    /// nonces and clock rows (tests use small pages to exercise paging).
    pub fn with_page_size(db: Arc<Db>, page: u64) -> Self {
        let page = page.max(1);
        Self {
            db,
            page,
            clock_page: page.min(CLOCK_PAGE),
        }
    }

    async fn create(&self, n: &StoredNonce, key: &str) -> Result<(), DbError> {
        let q = Ql::new("ReplayNonce.create({ key: ")
            .str(key)
            .raw(", kind: ")
            .str(kind_str(n.kind))
            .raw(", signer: ")
            .str(&n.signer)
            .raw(", domain: ")
            .str(&n.domain)
            .raw(", key_id: ")
            .str(&n.key_id)
            .raw(", nonce: ")
            .str(&n.nonce)
            .raw(", signed_at: ")
            .unix_seconds(n.signed_at)
            .raw(", expires_at: ")
            .unix_seconds(n.expires)
            .raw(" })");
        self.db.execute(&q).await
    }

    /// The persisted replay clock, if any: the highest `ReplayClock` row.
    ///
    /// rhypedb has no sort, so the maximum is found by raising a floor
    /// rather than by paging with `offset`: a prune deleting rows between
    /// two `offset` pages shifts the rest down, and the highest row could
    /// fall into a page already read. Each statement reads one snapshot,
    /// and every snapshot holds the highest row (a prune deletes only rows
    /// below a value whose row exists). So a page that is not full holds
    /// every row above the floor, and its maximum is the clock; a full page
    /// raises the floor to its maximum and the next statement reads only
    /// rows above it. The floor only rises, so this ends.
    async fn read_clock(&self) -> Result<Option<i64>, LedgerError> {
        let mut clock: Option<i64> = None;
        let mut warned = false;
        loop {
            let q = match clock {
                None => Ql::new("ReplayClock.limit("),
                Some(floor) => Ql::new("ReplayClock.filter(.high_water > ")
                    .unix_seconds(floor)
                    .raw(").limit("),
            }
            .uint(self.clock_page)
            .raw(")");
            let rows = self.db.fetch::<ClockRow>(&q).await.map_err(unavailable)?;
            let full = rows.len() as u64 >= self.clock_page;
            for r in rows {
                let t = unix(&r.data.high_water)?;
                clock = Some(clock.map_or(t, |c| c.max(t)));
            }
            if !full {
                return Ok(clock);
            }
            if !warned {
                // Pruning keeps one or two rows; a full page means it lags.
                tracing::warn!(
                    page = self.clock_page,
                    "replay clock has a page or more of rows; pruning lags"
                );
                warned = true;
            }
        }
    }

    /// Persist the replay clock as at least `clock`. A new row is created
    /// for each value and rows below it are deleted afterwards, so the
    /// highest row only ever rises: no update can lower it, and a delete
    /// removes only rows below a value whose row exists.
    async fn advance_clock(&self, clock: i64) -> Result<(), LedgerError> {
        if self.read_clock().await?.is_some_and(|c| c >= clock) {
            return Ok(());
        }
        let q = Ql::new("ReplayClock.create({ name: ")
            .str(&format!("replay@{clock}"))
            .raw(", high_water: ")
            .unix_seconds(clock)
            .raw(" })");
        match self.db.execute(&q).await {
            // Created concurrently with the same value: equally persisted.
            Ok(()) | Err(DbError::Conflict(_)) => {}
            // Aborted by a concurrent create (nothing written): once more.
            Err(DbError::Contended(_)) => match self.db.execute(&q).await {
                Ok(()) | Err(DbError::Conflict(_)) => {}
                Err(e) => return Err(unavailable(e)),
            },
            Err(e) => return Err(unavailable(e)),
        }
        // Tidying only: the clock is persisted. Rows are never updated, so
        // this deletes exactly rows below `clock`, never the highest.
        let prune = Ql::new("ReplayClock.filter(.high_water < ")
            .unix_seconds(clock)
            .raw(").delete()");
        match self.db.execute(&prune).await {
            // A concurrent prune deleted a row first.
            Ok(()) | Err(DbError::Vanished(_) | DbError::Contended(_)) => {}
            Err(e) => tracing::warn!(error = %e, "pruning old replay clock rows failed"),
        }
        Ok(())
    }
}

impl NonceLedger for RhypeLedger {
    fn persist<'a>(&'a self, n: &'a StoredNonce, now: i64) -> LedgerFuture<'a, ()> {
        Box::pin(async move {
            let key = n.ledger_key();
            match self.create(n, &key).await {
                Ok(()) => return Ok(()),
                // A concurrent create of the same identity may abort ours
                // (`Contended`, nothing written); either way, look.
                Err(DbError::Conflict(_) | DbError::Contended(_)) => {}
                Err(e) => return Err(unavailable(e)),
            }
            // Same identity already stored. Live: a replay. Expired but not
            // yet purged (a client reusing a nonce after its window, which
            // §4.5 permits): delete that row and create ours.
            //
            // - Persisting the clock (at least `now`, so at least the row's
            //   expiry) first keeps the earlier use expired after a restart
            //   even if a crash lost the row before our create, exactly as a
            //   purge does. Our own use is not accepted until our create
            //   succeeds, so it needs no cover before then.
            // - The row is deleted by id. Rows are never updated, so that id
            //   is exactly the expired row: a purge or a concurrent reuser
            //   deleting it too changes nothing, and no live row is touched.
            // - Concurrent reusers (in other processes; this one's in-memory
            //   store lets only one through) all compete in the `@unique`
            //   create: one wins, and the others find its live row.
            for _ in 0..3 {
                let q = Ql::new("ReplayNonce.filter(.key == ").str(&key).raw(")");
                let rows = self.db.fetch::<ExpiryRow>(&q).await.map_err(unavailable)?;
                if let Some(row) = rows.first() {
                    if unix(&row.data.expires_at)? > now {
                        return Err(LedgerError::Duplicate);
                    }
                    self.advance_clock(now).await?;
                    let q = Ql::new("ReplayNonce.get(").uint(row.id).raw(").delete()");
                    match self.db.execute(&q).await {
                        // Deleted (or being deleted) by a purge or a concurrent reuser.
                        Ok(()) | Err(DbError::Vanished(_) | DbError::Contended(_)) => {}
                        Err(e) => return Err(unavailable(e)),
                    }
                }
                match self.create(n, &key).await {
                    Ok(()) => return Ok(()),
                    // Recreated concurrently, or aborted by a concurrent
                    // create (nothing written): look again.
                    Err(DbError::Conflict(_) | DbError::Contended(_)) => continue,
                    Err(e) => return Err(unavailable(e)),
                }
            }
            Err(LedgerError::Unavailable(
                "replay ledger row kept changing; retry".to_owned(),
            ))
        })
    }

    fn load(&self, now: i64) -> LedgerFuture<'_, Restored> {
        Box::pin(async move {
            let clock = self.read_clock().await?;
            // Live by the later of our clock and the persisted one.
            let cutoff = clock.map_or(now, |c| c.max(now));
            let mut nonces = Vec::new();
            let mut offset = 0u64;
            loop {
                let q = Ql::new("ReplayNonce.filter(.expires_at > ")
                    .unix_seconds(cutoff)
                    .raw(").offset(")
                    .uint(offset)
                    .raw(").limit(")
                    .uint(self.page)
                    .raw(")");
                let rows = self.db.fetch::<NonceRow>(&q).await.map_err(unavailable)?;
                let n = rows.len();
                for r in rows {
                    let r = r.data;
                    let kind = parse_kind(&r.kind).ok_or_else(|| {
                        LedgerError::Unavailable(format!("bad signer kind {:?}", r.kind))
                    })?;
                    nonces.push(StoredNonce {
                        kind,
                        signer: r.signer,
                        domain: r.domain,
                        key_id: r.key_id,
                        nonce: r.nonce,
                        signed_at: unix(&r.signed_at)?,
                        expires: unix(&r.expires_at)?,
                    });
                }
                if (n as u64) < self.page {
                    return Ok(Restored { nonces, clock });
                }
                offset += self.page;
            }
        })
    }

    fn purge(&self, clock: i64) -> LedgerFuture<'_, ()> {
        Box::pin(async move {
            // The clock first: if it cannot be saved, delete nothing.
            self.advance_clock(clock).await?;
            // Rows are never updated, so the filter's snapshot is exact: a
            // row it selects stays expired until deleted.
            for _ in 0..PURGE_MAX_BATCHES {
                let q = Ql::new("ReplayNonce.filter(.expires_at <= ")
                    .unix_seconds(clock)
                    .raw(").limit(")
                    .uint(PURGE_BATCH)
                    .raw(").delete()");
                match self.db.execute(&q).await {
                    // A row it selected was deleted meanwhile (by a reuse):
                    // the statement stopped there; the next batch goes on.
                    Ok(()) | Err(DbError::Vanished(_) | DbError::Contended(_)) => {}
                    Err(e) => return Err(unavailable(e)),
                }
                let probe = Ql::new("ReplayNonce.filter(.expires_at <= ")
                    .unix_seconds(clock)
                    .raw(").limit(1)");
                if self
                    .db
                    .fetch::<Exists>(&probe)
                    .await
                    .map_err(unavailable)?
                    .is_empty()
                {
                    break;
                }
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(key_id: &str, nonce: &str) -> StoredNonce {
        StoredNonce {
            kind: SignerKind::Actor,
            signer: "a@b.example".into(),
            domain: "b.example".into(),
            key_id: key_id.into(),
            nonce: nonce.into(),
            signed_at: 0,
            expires: 301,
        }
    }

    #[test]
    fn ledger_keys_are_unambiguous() {
        // Same concatenation, different split: different keys.
        assert_ne!(n("ab", "c").ledger_key(), n("a", "bc").ledger_key());
        assert_ne!(n("a\n1", "x").ledger_key(), n("a", "1\nx").ledger_key());
        let mut p = n("ab", "c");
        p.kind = SignerKind::Provider;
        assert_ne!(p.ledger_key(), n("ab", "c").ledger_key());
        // The signer is not part of the identity (§4.5 keys by kind, key id,
        // nonce).
        let mut other = n("ab", "c");
        other.signer = "z@b.example".into();
        assert_eq!(other.ledger_key(), n("ab", "c").ledger_key());
        assert_eq!(n("ab", "c").ledger_key().len(), 64);
    }
}
