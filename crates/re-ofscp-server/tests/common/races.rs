//! Helpers for racing concurrent writers against a real rhypedb-server.

use std::future::Future;
use std::sync::Arc;

use re_ofscp_server::db::{Db, DbConfig};
use serde::Deserialize;

use super::rhypedb::RhypeServer;

/// Concurrent attempts per race.
pub const RACERS: usize = 32;

/// A client over `server`.
pub fn db(server: &RhypeServer) -> Arc<Db> {
    Arc::new(Db::new(DbConfig::new(server.tcp_addr())))
}

/// Run `f(0..RACERS)` as concurrent tasks; their results, in order.
pub async fn race<T, Fut>(f: impl Fn(usize) -> Fut) -> Vec<T>
where
    Fut: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let tasks: Vec<_> = (0..RACERS).map(|i| tokio::spawn(f(i))).collect();
    let mut out = Vec::with_capacity(RACERS);
    for t in tasks {
        out.push(t.await.unwrap());
    }
    out
}

/// How many of `results` won.
pub fn winners(results: &[bool]) -> usize {
    results.iter().filter(|w| **w).count()
}

/// Any row (only its existence matters).
#[derive(Deserialize)]
pub struct Any {}
