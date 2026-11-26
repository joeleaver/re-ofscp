//! The rhypedb data layer.
//!
//! [`Db`] holds a small pool of binary-protocol connections to the managed
//! rhypedb (on jkbase, `127.0.0.1:4201`), reconnecting lazily after any I/O
//! failure. Queries are built with [`Ql`], which makes injection impossible
//! by construction (see [`ql`]).
//!
//! When one connection breaks, every pooled connection is discarded: the
//! usual cause is a database restart, which leaves all of them stale.
//! Reads ([`Db::fetch`], [`Db::one`], [`Db::ping`]) are retried once on a
//! fresh connection. Writes ([`Db::execute`], [`Db::write_one`],
//! [`Db::write_rows`]) are not retried after a failure mid-exchange: their
//! outcome is unknown, and the caller decides what is safe. A connection
//! found *already* closed (nothing was sent on it) is replaced and the query
//! sent once more, for writes too. Every round trip runs in its own task, so
//! a cancelled caller cannot poison a connection.

pub mod ql;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use rhypedb_client::{AsyncClient, ClientConfig, Error as ClientError, QueryResult, Row};
use serde::de::DeserializeOwned;
use tokio::sync::Mutex;

pub use ql::Ql;

/// How rhypedb begins the message for a violated `@unique` constraint.
const UNIQUE_VIOLATION_PREFIX: &str = "engine error: unique constraint violated: ";

/// How rhypedb begins the message for a write naming an object id that does
/// not exist (`T.get(id).delete()` after someone else deleted it).
const NOT_FOUND_PREFIX: &str = "engine error: object not found: ";

/// How rhypedb reports a write-write conflict under snapshot isolation:
/// a concurrent transaction committed a write to the same key first, and
/// the losing transaction was aborted.
///
/// rhypedb runs each object's write in its own transaction (a filtered
/// `update` evaluates the filter on a snapshot, then updates each matching
/// object separately), so a statement that touches one object is aborted
/// whole and may be run again, but one that touches several may have
/// applied to some before the conflict. Retrying is therefore the
/// caller's decision (see [`DbError::Contended`]).
const WRITE_CONFLICT_MESSAGE: &str = "engine error: write conflict";

/// A data-layer failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DbError {
    /// The database could not be reached, or the connection broke mid-query.
    /// The outcome of a write is unknown.
    #[error("database unavailable: {0}")]
    Unavailable(String),
    /// A `@unique` constraint rejected the write.
    #[error("unique constraint violated: {0}")]
    Conflict(String),
    /// A concurrent write to the same object won, and this one was aborted.
    /// For a statement that writes one object, nothing was written and it
    /// may be run again; for one that writes several, those before the
    /// conflicting object may have been written.
    #[error("write conflict: {0}")]
    Contended(String),
    /// The query named an object id that does not exist (deleted
    /// meanwhile). Nothing was written.
    #[error("object not found: {0}")]
    NotFound(String),
    /// The server rejected the query (a bug in this code, or a schema
    /// mismatch).
    #[error("query rejected: {0}")]
    Query(String),
    /// The result did not have the expected shape or field types.
    #[error("unexpected result: {0}")]
    Decode(String),
}

impl DbError {
    fn from_client(e: ClientError) -> Self {
        match e {
            ClientError::Connect(e) | ClientError::Io(e) => Self::Unavailable(e.to_string()),
            ClientError::Closed => Self::Unavailable("connection closed".to_owned()),
            ClientError::Server(msg) => {
                // rhypedb reports a violated `@unique` as
                // "engine error: unique constraint violated: Type.field = value".
                // Match the prefix only: the tail echoes stored values.
                // `tests/db.rs` pins this against a real server.
                if msg.starts_with(UNIQUE_VIOLATION_PREFIX) {
                    Self::Conflict(msg)
                } else if msg.starts_with(NOT_FOUND_PREFIX) {
                    Self::NotFound(msg)
                } else if msg == WRITE_CONFLICT_MESSAGE {
                    Self::Contended(msg)
                } else {
                    Self::Query(msg)
                }
            }
            ClientError::Deserialize(m) => Self::Decode(m),
            ClientError::UnexpectedShape(s) => {
                Self::Decode(format!("expected one object, got {s}"))
            }
            other => Self::Query(other.to_string()),
        }
    }

    /// Whether the connection should be discarded.
    fn breaks_connection(&self) -> bool {
        matches!(self, Self::Unavailable(_))
    }
}

/// Connection settings.
#[derive(Debug, Clone)]
pub struct DbConfig {
    /// `host:port` of rhypedb's binary protocol.
    pub addr: String,
    /// Connections in the pool (each serializes its own queries).
    pub pool_size: usize,
    /// Bound on connecting.
    pub connect_timeout: Duration,
    /// Bound on each query round-trip.
    pub query_timeout: Duration,
    /// A pooled connection idle at least this long is pinged before reuse,
    /// so a database restart while the app was quiet does not cost the next
    /// query (which, for a write, is not retried).
    pub liveness_after: Duration,
}

impl DbConfig {
    /// Defaults for `addr`: 4 connections, 2 s connect, 10 s per query,
    /// liveness ping after 5 s idle.
    pub fn new(addr: impl Into<String>) -> Self {
        Self {
            addr: addr.into(),
            pool_size: 4,
            connect_timeout: Duration::from_secs(2),
            query_timeout: Duration::from_secs(10),
            liveness_after: Duration::from_secs(5),
        }
    }
}

/// A pooled connection and when it was last handed out.
struct Pooled {
    client: Arc<AsyncClient>,
    last_used: Instant,
}

/// A pooled rhypedb client.
pub struct Db {
    config: DbConfig,
    slots: Vec<Mutex<Option<Pooled>>>,
    next: AtomicUsize,
}

impl std::fmt::Debug for Db {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Db")
            .field("addr", &self.config.addr)
            .finish()
    }
}

impl Db {
    /// A pool for `config`. Connects lazily, on first use.
    pub fn new(config: DbConfig) -> Self {
        let slots = (0..config.pool_size.max(1))
            .map(|_| Mutex::new(None))
            .collect();
        Self {
            config,
            slots,
            next: AtomicUsize::new(0),
        }
    }

    /// A connection from the next slot: reused if fresh (pinged first if it
    /// sat idle), else newly connected. A failed connect or liveness ping
    /// clears the whole pool, since the database is down or restarted.
    async fn client(&self) -> Result<(usize, Arc<AsyncClient>), DbError> {
        let slot = self.next.fetch_add(1, Ordering::Relaxed) % self.slots.len();
        self.client_at(slot).await
    }

    /// As [`Db::client`], for a given slot.
    async fn client_at(&self, slot: usize) -> Result<(usize, Arc<AsyncClient>), DbError> {
        let mut guard = self.slots[slot].lock().await;
        if let Some(p) = guard.as_mut() {
            let idle = p.last_used.elapsed() >= self.config.liveness_after;
            p.last_used = Instant::now();
            let client = p.client.clone();
            if !idle {
                return Ok((slot, client));
            }
            // The liveness ping runs in its own task too, so a cancelled
            // caller cannot leave this connection half-way through it.
            let pinger = client.clone();
            let alive = tokio::spawn(async move { pinger.ping().await })
                .await
                .is_ok_and(|r| r.is_ok());
            if alive {
                return Ok((slot, client));
            }
            *guard = None;
            // Never hold two slot locks at once (no lock-order deadlock).
            drop(guard);
            self.clear_others(slot).await;
            guard = self.slots[slot].lock().await;
            if let Some(p) = guard.as_ref() {
                // Another task reconnected this slot meanwhile.
                return Ok((slot, p.client.clone()));
            }
        }
        let cfg = ClientConfig {
            connect_timeout: Some(self.config.connect_timeout),
            read_timeout: Some(self.config.query_timeout),
            write_timeout: Some(self.config.query_timeout),
        };
        match AsyncClient::connect_with(self.config.addr.as_str(), &cfg).await {
            Ok(client) => {
                let client = Arc::new(client);
                *guard = Some(Pooled {
                    client: client.clone(),
                    last_used: Instant::now(),
                });
                Ok((slot, client))
            }
            Err(e) => {
                drop(guard);
                self.clear_others(slot).await;
                Err(DbError::from_client(e))
            }
        }
    }

    /// Forget every pooled connection except slot `slot`'s.
    async fn clear_others(&self, slot: usize) {
        for (i, s) in self.slots.iter().enumerate() {
            if i != slot {
                *s.lock().await = None;
            }
        }
    }

    /// A connection broke: forget it, and every other pooled connection (a
    /// database restart leaves them all stale). In `client`'s own slot, only
    /// `client` itself is forgotten, so a replacement another task already
    /// opened there survives.
    async fn discard_all(&self, slot: usize, client: &Arc<AsyncClient>) {
        self.discard_slot(slot, client).await;
        self.clear_others(slot).await;
    }

    /// Send `q` once. The round trip runs in its own task, so a caller that
    /// is cancelled (a timeout, a disconnected HTTP client) cannot abandon a
    /// half-finished exchange and poison the connection for the next query.
    /// A connection found already closed is replaced and the query sent
    /// once more, even for a write: nothing was sent on it.
    async fn query_once(&self, q: &Ql) -> Result<QueryResult, DbError> {
        let (mut slot, mut client) = self.client().await?;
        for attempt in 0..2 {
            if attempt > 0 {
                // Reconnect the same slot (just discarded), not the next one,
                // which might be latched closed too.
                (slot, client) = self.client_at(slot).await?;
            }
            let text = q.as_str().to_owned();
            let task_client = client.clone();
            let outcome = tokio::spawn(async move { task_client.query(&text).await }).await;
            let result = match outcome {
                Ok(r) => r,
                Err(join) => {
                    return Err(DbError::Unavailable(format!("query task failed: {join}")));
                }
            };
            match result {
                Ok(r) => return Ok(r),
                Err(ClientError::Closed) => {
                    self.discard_slot(slot, &client).await;
                }
                Err(e) => {
                    let e = DbError::from_client(e);
                    if e.breaks_connection() {
                        self.discard_all(slot, &client).await;
                    }
                    return Err(e);
                }
            }
        }
        Err(DbError::Unavailable("connection closed".to_owned()))
    }

    /// Forget slot `slot`'s connection if it is still `client` (the others
    /// are healthy: this one was closed by a cancelled exchange).
    async fn discard_slot(&self, slot: usize, client: &Arc<AsyncClient>) {
        let mut guard = self.slots[slot].lock().await;
        if guard
            .as_ref()
            .is_some_and(|p| Arc::ptr_eq(&p.client, client))
        {
            *guard = None;
        }
    }

    /// Run a read, retrying once on a fresh connection if the first broke.
    async fn read(&self, q: &Ql) -> Result<QueryResult, DbError> {
        match self.query_once(q).await {
            Err(e) if e.breaks_connection() => self.query_once(q).await,
            other => other,
        }
    }

    /// Run `q` and decode every returned object into `T`. A read: retried
    /// once if the connection broke.
    pub async fn fetch<T: DeserializeOwned>(&self, q: &Ql) -> Result<Vec<Row<T>>, DbError> {
        self.read(q)
            .await?
            .into_objects()
            .iter()
            .map(|o| Row::from_object(o).map_err(DbError::from_client))
            .collect()
    }

    /// Run a read that must return exactly one object (a `get`), and decode
    /// it into `T`. Retried once if the connection broke.
    pub async fn one<T: DeserializeOwned>(&self, q: &Ql) -> Result<Row<T>, DbError> {
        let mut rows = self.fetch::<T>(q).await?;
        Self::single(rows.pop(), rows.len())
    }

    /// Run a write that returns exactly one object (`create`, `update`) and
    /// decode it into `T`. Never retried.
    pub async fn write_one<T: DeserializeOwned>(&self, q: &Ql) -> Result<Row<T>, DbError> {
        let mut rows = self.write_many::<T>(q).await?;
        Self::single(rows.pop(), rows.len())
    }

    /// Run a write and decode every object it returned (an `update`
    /// returns the objects it changed) into `T`. Never retried.
    pub async fn write_many<T: DeserializeOwned>(&self, q: &Ql) -> Result<Vec<Row<T>>, DbError> {
        self.query_once(q)
            .await?
            .into_objects()
            .iter()
            .map(|o| Row::from_object(o).map_err(DbError::from_client))
            .collect()
    }

    fn single<T>(last: Option<Row<T>>, rest: usize) -> Result<Row<T>, DbError> {
        match (last, rest) {
            (Some(row), 0) => Ok(row),
            (None, _) => Err(DbError::Decode("expected one object, got 0".to_owned())),
            (Some(_), n) => Err(DbError::Decode(format!(
                "expected one object, got {}",
                n + 1
            ))),
        }
    }

    /// Run a write (`create`, `update`, `delete`, `link`). Not retried
    /// after a failure mid-exchange.
    pub async fn execute(&self, q: &Ql) -> Result<(), DbError> {
        self.query_once(q).await.map(|_| ())
    }

    /// Run a write and return what it returned (an `update` returns the
    /// objects it changed, so an empty result means nothing matched). Not
    /// retried after a failure mid-exchange.
    pub async fn write_rows(&self, q: &Ql) -> Result<QueryResult, DbError> {
        self.query_once(q).await
    }

    /// Whether the database answers a ping (retried once, like a read).
    /// Like queries, the ping runs in its own task, so a caller's timeout
    /// cannot poison the connection.
    pub async fn ping(&self) -> bool {
        for _ in 0..2 {
            match self.client().await {
                Ok((slot, client)) => {
                    let task_client = client.clone();
                    let ok = tokio::spawn(async move { task_client.ping().await })
                        .await
                        .is_ok_and(|r| r.is_ok());
                    if ok {
                        return true;
                    }
                    self.discard_all(slot, &client).await;
                }
                Err(_) => return false,
            }
        }
        false
    }
}
