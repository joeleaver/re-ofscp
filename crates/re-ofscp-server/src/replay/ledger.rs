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
}

/// Rows read per page when restoring.
const LOAD_PAGE: u64 = 5_000;

/// Rows deleted per purge statement, and statements per purge run, so one
/// purge never becomes a single unbounded delete (each statement stays well
/// inside the query timeout; a backlog drains over successive runs).
const PURGE_BATCH: u64 = 1_000;
const PURGE_MAX_BATCHES: usize = 100;

/// The `ReplayClock` row's name.
const CLOCK_NAME: &str = "replay";

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
    /// (tests use small pages to exercise paging).
    pub fn with_page_size(db: Arc<Db>, page: u64) -> Self {
        Self {
            db,
            page: page.max(1),
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

    /// The persisted replay clock, if any.
    async fn read_clock(&self) -> Result<Option<(u64, i64)>, LedgerError> {
        let q = Ql::new("ReplayClock.filter(.name == ")
            .str(CLOCK_NAME)
            .raw(")");
        let rows = self.db.fetch::<ClockRow>(&q).await.map_err(unavailable)?;
        match rows.first() {
            Some(r) => Ok(Some((r.id, unix(&r.data.high_water)?))),
            None => Ok(None),
        }
    }

    /// Persist the replay clock as at least `clock` (never lowering it).
    async fn advance_clock(&self, clock: i64) -> Result<(), LedgerError> {
        // Two attempts: if the row is created concurrently between our read
        // and our create, the second pass raises that row instead.
        for _ in 0..2 {
            match self.read_clock().await? {
                Some((_, saved)) if saved >= clock => return Ok(()),
                Some((id, _)) => {
                    let q = Ql::new("ReplayClock.get(")
                        .uint(id)
                        .raw(").update({ high_water: ")
                        .unix_seconds(clock)
                        .raw(" })");
                    return self.db.execute(&q).await.map_err(unavailable);
                }
                None => {
                    let q = Ql::new("ReplayClock.create({ name: ")
                        .str(CLOCK_NAME)
                        .raw(", high_water: ")
                        .unix_seconds(clock)
                        .raw(" })");
                    match self.db.execute(&q).await {
                        Ok(()) => return Ok(()),
                        Err(DbError::Conflict(_)) => continue,
                        Err(e) => return Err(unavailable(e)),
                    }
                }
            }
        }
        Err(LedgerError::Unavailable(
            "replay clock row could not be created or raised".to_owned(),
        ))
    }
}

impl NonceLedger for RhypeLedger {
    fn persist<'a>(&'a self, n: &'a StoredNonce, now: i64) -> LedgerFuture<'a, ()> {
        Box::pin(async move {
            let key = n.ledger_key();
            match self.create(n, &key).await {
                Ok(()) => return Ok(()),
                Err(DbError::Conflict(_)) => {}
                Err(e) => return Err(unavailable(e)),
            }
            // Same identity already stored. Live: a replay. Expired but not
            // yet purged (a client reusing a nonce after its window, which
            // §4.5 permits): replace it.
            let q = Ql::new("ReplayNonce.filter(.key == ").str(&key).raw(")");
            let rows = self.db.fetch::<ExpiryRow>(&q).await.map_err(unavailable)?;
            let expired = match rows.first() {
                Some(r) => unix(&r.data.expires_at)? <= now,
                // Purged between the two queries: try again below.
                None => true,
            };
            if !expired {
                return Err(LedgerError::Duplicate);
            }
            let q = Ql::new("ReplayNonce.filter(.key == ")
                .str(&key)
                .raw(" && .expires_at <= ")
                .unix_seconds(now)
                .raw(").delete()");
            self.db.execute(&q).await.map_err(unavailable)?;
            match self.create(n, &key).await {
                Ok(()) => Ok(()),
                Err(DbError::Conflict(_)) => Err(LedgerError::Duplicate),
                Err(e) => Err(unavailable(e)),
            }
        })
    }

    fn load(&self, now: i64) -> LedgerFuture<'_, Restored> {
        Box::pin(async move {
            let clock = self.read_clock().await?.map(|(_, c)| c);
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
            for _ in 0..PURGE_MAX_BATCHES {
                let q = Ql::new("ReplayNonce.filter(.expires_at <= ")
                    .unix_seconds(clock)
                    .raw(").limit(")
                    .uint(PURGE_BATCH)
                    .raw(").delete()");
                self.db.execute(&q).await.map_err(unavailable)?;
                let probe = Ql::new("ReplayNonce.filter(.expires_at <= ")
                    .unix_seconds(clock)
                    .raw(").limit(1)");
                if self
                    .db
                    .fetch::<ExpiryRow>(&probe)
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
