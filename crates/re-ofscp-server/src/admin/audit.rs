//! The admin audit log (`AdminAudit` in `schema.rhype`).
//!
//! Every admin action is recorded, naming the admin. An action that
//! changes something is written *before* it runs, with outcome
//! [`outcome::PENDING`], and completed afterwards: if the log cannot be
//! written the action is refused, so nothing happens unrecorded. If the
//! completion fails, the entry stays `pending` and the outcome is still in
//! the structured log. Every entry is also emitted to the `audit` tracing
//! target.
//!
//! Entries are kept indefinitely. Listing reads one time window, sorted
//! here (rhypedb has no ordering step), and refuses windows holding more
//! than [`MAX_LISTED`] entries rather than returning an arbitrary subset.

use std::sync::Arc;

use re_ofscp_types::admin::AuditEntry;
use serde::Deserialize;

use crate::db::{Db, DbError, Ql};
use crate::timefmt;

/// Outcome values.
pub mod outcome {
    /// Written before the action; replaced when it finishes.
    pub const PENDING: &str = "pending";
    /// The action succeeded.
    pub const OK: &str = "ok";
    /// The admin was not allowed to do it.
    pub const DENIED: &str = "denied";
    /// It was attempted and failed (invalid input, conflict, fault).
    pub const FAILED: &str = "failed";
}

/// Most entries one listing returns.
pub const MAX_LISTED: usize = 5000;

/// Longest `detail` stored, in characters.
const MAX_DETAIL_CHARS: usize = 500;

/// One entry to record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The admin (or, for a failed sign-in, the username tried).
    pub admin: String,
    /// What, e.g. `"account.disable"`.
    pub action: &'static str,
    /// To what; empty when nothing.
    pub target: String,
    /// The client address.
    pub source: String,
    /// Context; never a secret.
    pub detail: String,
}

/// Which entries to list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    /// Unix seconds, inclusive.
    pub since: i64,
    /// Unix seconds, exclusive.
    pub until: i64,
    /// Only this admin's entries.
    pub admin: Option<String>,
}

/// Why a listing failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ListError {
    /// The window holds more than [`MAX_LISTED`] entries.
    #[error("more than {MAX_LISTED} entries in that window; narrow it")]
    TooMany,
    /// The database failed.
    #[error(transparent)]
    Db(#[from] DbError),
}

#[derive(Deserialize)]
struct AuditRow {
    at: String,
    admin: String,
    action: String,
    target: String,
    outcome: String,
    source: String,
    detail: String,
}

fn clip(s: &str) -> String {
    s.chars().take(MAX_DETAIL_CHARS).collect()
}

/// The audit log.
#[derive(Debug, Clone)]
pub struct AuditLog {
    db: Arc<Db>,
}

impl AuditLog {
    /// A log over `db`.
    pub fn new(db: Arc<Db>) -> Self {
        Self { db }
    }

    async fn write(&self, r: &Record, outcome: &str, now: i64) -> Result<u64, DbError> {
        tracing::info!(
            target: "audit",
            admin = %r.admin,
            action = r.action,
            object = %r.target,
            outcome,
            source = %r.source,
            detail = %r.detail,
            "admin action"
        );
        let q = Ql::new("AdminAudit.create({ at: ")
            .unix_seconds(now)
            .raw(", admin: ")
            .str(&r.admin)
            .raw(", action: ")
            .str(r.action)
            .raw(", target: ")
            .str(&r.target)
            .raw(", outcome: ")
            .str(outcome)
            .raw(", source: ")
            .str(&r.source)
            .raw(", detail: ")
            .str(&clip(&r.detail))
            .raw(" })");
        Ok(self.db.write_one::<AuditRow>(&q).await?.id)
    }

    /// Record an action that is about to run. Returns the entry's id for
    /// [`AuditLog::finish`].
    pub async fn begin(&self, r: &Record, now: i64) -> Result<u64, DbError> {
        self.write(r, outcome::PENDING, now).await
    }

    /// Record how the action begun as `id` ended. A failure is logged, not
    /// returned: the action has already happened.
    pub async fn finish(&self, id: u64, r: &Record, outcome: &str, detail: &str) {
        tracing::info!(
            target: "audit",
            admin = %r.admin,
            action = r.action,
            object = %r.target,
            outcome,
            detail,
            "admin action finished"
        );
        let q = Ql::new("AdminAudit.get(")
            .uint(id)
            .raw(").update({ outcome: ")
            .str(outcome)
            .raw(", detail: ")
            .str(&clip(detail))
            .raw(" })");
        if let Err(e) = self.db.execute(&q).await {
            tracing::error!(
                target: "audit",
                error = %e,
                entry = id,
                outcome,
                "could not record an admin action's outcome; the entry stays pending"
            );
        }
    }

    /// Record a finished event (a sign-in, a refusal) in one write.
    pub async fn record(&self, r: &Record, outcome: &str, now: i64) -> Result<(), DbError> {
        self.write(r, outcome, now).await.map(|_| ())
    }

    /// Entries in the window, newest first.
    pub async fn list(&self, query: &Query) -> Result<Vec<AuditEntry>, ListError> {
        let q = Ql::new("AdminAudit.filter(.at >= ")
            .unix_seconds(query.since)
            .raw(" && .at < ")
            .unix_seconds(query.until);
        let q = match &query.admin {
            Some(a) => q.raw(" && .admin == ").str(a),
            None => q,
        };
        let q = q.raw(").limit(").uint(MAX_LISTED as u64 + 1).raw(")");
        let rows = self.db.fetch::<AuditRow>(&q).await?;
        if rows.len() > MAX_LISTED {
            return Err(ListError::TooMany);
        }
        let mut rows: Vec<(i64, u64, AuditRow)> = rows
            .into_iter()
            .map(|r| (timefmt::unix(&r.data.at).unwrap_or(0), r.id, r.data))
            .collect();
        // Newest first; ids increase monotonically, so they order entries
        // within one second.
        rows.sort_by_key(|r| std::cmp::Reverse((r.0, r.1)));
        Ok(rows
            .into_iter()
            .map(|(_, _, r)| AuditEntry {
                at: r.at,
                admin: r.admin,
                action: r.action,
                target: r.target,
                outcome: r.outcome,
                source: r.source,
                detail: r.detail,
            })
            .collect())
    }
}
