//! The stored federation policy (`FederationSetting` and `FederationRule`
//! in `schema.rhype`) and the admin changes to it (docs/decisions/0008).
//!
//! Every change is written to rhypedb first and then applied to the policy
//! in force, under one lock, so the in-memory policy is always the stored
//! one. A change whose write fails changes nothing in memory either.
//! Like the replay ledger (decision 0001), one process owns the policy:
//! another process writing the same database would not be seen until its
//! next restart.

use std::sync::Arc;
use std::time::Duration;

use re_ofscp_types::Authority;
use re_ofscp_types::federation::{
    AddFederationRule, FederationMode, MAX_RULE_NOTE_LEN, MAX_RULES_PER_LIST, RuleList, RuleScope,
    canonical_rule_value,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use super::FederationPolicy;
use super::rules::{Rule, Snapshot};
use crate::db::{Db, DbError, Ql};
use crate::registrable::is_icann_public_suffix;
use crate::timefmt::unix;

/// The `FederationSetting` row's name.
const SETTING_NAME: &str = "federation";

/// How long [`PolicyStore::load_until_loaded`] waits between attempts.
pub const LOAD_RETRY: Duration = Duration::from_secs(2);

/// Why a policy change was refused or failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    /// The request is not a valid change.
    #[error("{0}")]
    Invalid(String),
    /// The same rule is already on that list.
    #[error("that rule is already on the list")]
    Duplicate,
    /// No rule has that id.
    #[error("no such rule")]
    NotFound,
    /// The list is full.
    #[error("a list holds at most {MAX_RULES_PER_LIST} rules")]
    TooMany,
    /// The stored policy has not been read yet.
    #[error("the federation policy is still loading")]
    NotLoaded,
    /// The database failed.
    #[error(transparent)]
    Db(#[from] DbError),
}

#[derive(Deserialize)]
struct SettingRow {
    mode: String,
    updated_by: String,
    updated_at: String,
}

#[derive(Deserialize)]
struct RuleRow {
    rule_id: String,
    list: String,
    scope: String,
    value: String,
    #[serde(default)]
    note: String,
    created_by: String,
    created_at: String,
}

impl RuleRow {
    fn into_rule(self) -> Result<Rule, DbError> {
        let bad =
            |what: &str| DbError::Decode(format!("FederationRule {}: bad {what}", self.rule_id));
        Ok(Rule {
            list: RuleList::parse(&self.list).ok_or_else(|| bad("list"))?,
            scope: RuleScope::parse(&self.scope).ok_or_else(|| bad("scope"))?,
            created_at: unix(&self.created_at).ok_or_else(|| bad("created_at"))?,
            id: self.rule_id,
            value: self.value,
            note: self.note,
            created_by: self.created_by,
        })
    }
}

/// The id of the rule on `list` with `scope` and canonical `value`: the
/// same rule always has the same id, so `@unique` refuses duplicates.
pub fn rule_id(list: RuleList, scope: RuleScope, value: &str) -> String {
    let digest = Sha256::digest(format!("{}\n{}\n{value}", list.as_str(), scope.as_str()));
    format!(
        "fr_{}",
        digest[..16]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}

/// Reads and changes the stored policy, keeping `policy` in step.
#[derive(Debug)]
pub struct PolicyStore {
    db: Arc<Db>,
    policy: Arc<FederationPolicy>,
    /// This provider's authority, which no rule may name.
    own: Authority,
    /// Serializes loads and changes.
    write: Mutex<()>,
}

impl PolicyStore {
    /// A store over `db` feeding `policy`, for the provider `own`.
    pub fn new(db: Arc<Db>, policy: Arc<FederationPolicy>, own: Authority) -> Self {
        Self {
            db,
            policy,
            own,
            write: Mutex::new(()),
        }
    }

    /// The policy in force.
    pub fn policy(&self) -> &Arc<FederationPolicy> {
        &self.policy
    }

    /// Read the stored policy and put it in force. On error the policy in
    /// force is unchanged (unknown, before the first load).
    pub async fn load(&self) -> Result<(), DbError> {
        let _write = self.write.lock().await;
        let snapshot = self.read().await?;
        self.policy.install(snapshot);
        Ok(())
    }

    /// [`load`](Self::load), retrying every [`LOAD_RETRY`] until it
    /// succeeds. Run at startup when the first attempt failed.
    pub async fn load_until_loaded(self: Arc<Self>) {
        loop {
            match self.load().await {
                Ok(()) => {
                    tracing::info!("federation policy loaded");
                    return;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "federation policy unavailable; federation refused until it loads");
                    tokio::time::sleep(LOAD_RETRY).await;
                }
            }
        }
    }

    async fn read(&self) -> Result<Snapshot, DbError> {
        let q = Ql::new("FederationSetting.filter(.name == ")
            .str(SETTING_NAME)
            .raw(")");
        let setting = self.db.fetch::<SettingRow>(&q).await?.into_iter().next();
        let mut snapshot = Snapshot::default();
        if let Some(row) = setting {
            let row = row.data;
            snapshot.mode = FederationMode::parse(&row.mode).ok_or_else(|| {
                DbError::Decode(format!("FederationSetting: bad mode {:?}", row.mode))
            })?;
            let at = unix(&row.updated_at)
                .ok_or_else(|| DbError::Decode("FederationSetting: bad updated_at".to_owned()))?;
            snapshot.mode_set = Some((row.updated_by, at));
        }
        // Both lists are capped, so one more than both caps means the
        // table holds rules this code never wrote: refuse rather than
        // silently drop some.
        let cap = 2 * MAX_RULES_PER_LIST as u64;
        let q = Ql::new("FederationRule.limit(").uint(cap + 1).raw(")");
        let rows = self.db.fetch::<RuleRow>(&q).await?;
        if rows.len() as u64 > cap {
            return Err(DbError::Decode(
                "FederationRule holds too many rules".to_owned(),
            ));
        }
        for row in rows {
            let rule = row.data.into_rule()?;
            snapshot.list_mut(rule.list).insert(rule);
        }
        Ok(snapshot)
    }

    fn loaded(&self) -> Result<Snapshot, PolicyError> {
        self.policy
            .snapshot()
            .map(|s| (*s).clone())
            .ok_or(PolicyError::NotLoaded)
    }

    /// Set the mode. Returns the mode it replaced.
    pub async fn set_mode(
        &self,
        mode: FederationMode,
        by: &str,
        now: i64,
    ) -> Result<FederationMode, PolicyError> {
        let _write = self.write.lock().await;
        let mut snapshot = self.loaded()?;
        let previous = snapshot.mode;
        let update = Ql::new("FederationSetting.filter(.name == ")
            .str(SETTING_NAME)
            .raw(").update({ mode: ")
            .str(mode.as_str())
            .raw(", updated_by: ")
            .str(by)
            .raw(", updated_at: ")
            .unix_seconds(now)
            .raw(" })");
        if self.db.write_rows(&update).await?.into_objects().is_empty() {
            let create = Ql::new("FederationSetting.create({ name: ")
                .str(SETTING_NAME)
                .raw(", mode: ")
                .str(mode.as_str())
                .raw(", updated_by: ")
                .str(by)
                .raw(", updated_at: ")
                .unix_seconds(now)
                .raw(" })");
            self.db.write_one::<SettingRow>(&create).await?;
        }
        snapshot.mode = mode;
        snapshot.mode_set = Some((by.to_owned(), now));
        self.policy.install(snapshot);
        Ok(previous)
    }

    /// Validate `add` and store it as a rule by `by`.
    pub async fn add_rule(
        &self,
        add: &AddFederationRule,
        by: &str,
        now: i64,
    ) -> Result<Rule, PolicyError> {
        let value = self.validate(add)?;
        let note = add.note.as_deref().map(str::trim).unwrap_or("");
        if note.len() > MAX_RULE_NOTE_LEN {
            return Err(PolicyError::Invalid(format!(
                "a note is at most {MAX_RULE_NOTE_LEN} bytes"
            )));
        }
        let _write = self.write.lock().await;
        let mut snapshot = self.loaded()?;
        let list = snapshot.list(add.list);
        if list.get(add.scope, &value).is_some() {
            return Err(PolicyError::Duplicate);
        }
        if list.len() >= MAX_RULES_PER_LIST {
            return Err(PolicyError::TooMany);
        }
        let rule = Rule {
            id: rule_id(add.list, add.scope, &value),
            list: add.list,
            scope: add.scope,
            value,
            note: note.to_owned(),
            created_by: by.to_owned(),
            created_at: now,
        };
        let q = Ql::new("FederationRule.create({ rule_id: ")
            .str(&rule.id)
            .raw(", list: ")
            .str(rule.list.as_str())
            .raw(", scope: ")
            .str(rule.scope.as_str())
            .raw(", value: ")
            .str(&rule.value)
            .raw(", note: ")
            .str(&rule.note)
            .raw(", created_by: ")
            .str(&rule.created_by)
            .raw(", created_at: ")
            .unix_seconds(now)
            .raw(" })");
        match self.db.write_one::<RuleRow>(&q).await {
            Ok(_) => {}
            Err(DbError::Conflict(_)) => return Err(PolicyError::Duplicate),
            Err(e) => return Err(e.into()),
        }
        snapshot.list_mut(rule.list).insert(rule.clone());
        self.policy.install(snapshot);
        Ok(rule)
    }

    /// Remove the rule with `id`, returning it.
    pub async fn remove_rule(&self, id: &str) -> Result<Rule, PolicyError> {
        let _write = self.write.lock().await;
        let mut snapshot = self.loaded()?;
        let rule = snapshot.find(id).cloned().ok_or(PolicyError::NotFound)?;
        let q = Ql::new("FederationRule.filter(.rule_id == ")
            .str(&rule.id)
            .raw(").delete()");
        self.db.execute(&q).await?;
        snapshot.list_mut(rule.list).remove(&rule.id);
        self.policy.install(snapshot);
        Ok(rule)
    }

    /// The canonical value of `add`, if it is an acceptable rule.
    fn validate(&self, add: &AddFederationRule) -> Result<String, PolicyError> {
        let value = canonical_rule_value(add.scope, &add.value)
            .map_err(|e| PolicyError::Invalid(e.to_string()))?;
        match add.scope {
            RuleScope::Authority if value == self.own.as_str() => Err(PolicyError::Invalid(
                "this provider is not subject to its own federation policy".to_owned(),
            )),
            RuleScope::Domain if is_icann_public_suffix(&value) => Err(PolicyError::Invalid(
                format!("{value} is a public suffix; a domain rule must be under one"),
            )),
            _ => Ok(value),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_ids_are_stable_and_distinct() {
        let a = rule_id(RuleList::Deny, RuleScope::Domain, "evil.example");
        assert_eq!(
            a,
            rule_id(RuleList::Deny, RuleScope::Domain, "evil.example")
        );
        assert!(a.starts_with("fr_") && a.len() == 3 + 32);
        assert_ne!(
            a,
            rule_id(RuleList::Allow, RuleScope::Domain, "evil.example")
        );
        assert_ne!(
            a,
            rule_id(RuleList::Deny, RuleScope::Authority, "evil.example")
        );
        assert_ne!(
            a,
            rule_id(RuleList::Deny, RuleScope::Domain, "evil.example2")
        );
    }
}
