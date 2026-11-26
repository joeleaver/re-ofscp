//! A loaded federation policy and how it judges a provider (spec §8
//! *Authorization*; docs/decisions/0008).
//!
//! Matching is by canonical authority (§2.4), never by registrable domain:
//! registrable grouping (`registrable.rs`) is how this provider charges
//! rate limits, and denying one `*.github.io` provider must not deny all
//! of them. A [`RuleScope::Domain`] rule covers a name and every name under
//! it, label by label; a [`RuleScope::Authority`] rule exactly one
//! provider.

use std::collections::HashMap;

use re_ofscp_types::Authority;
use re_ofscp_types::federation::{FederationMode, RuleList, RuleScope};

use crate::registrable::host_of;

/// One stored rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// Its id.
    pub id: String,
    /// Its list.
    pub list: RuleList,
    /// What it matches.
    pub scope: RuleScope,
    /// The canonical authority or domain.
    pub value: String,
    /// The admin's note.
    pub note: String,
    /// The admin who added it.
    pub created_by: String,
    /// Unix seconds.
    pub created_at: i64,
}

/// The rules of one list, indexed for matching.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleSet {
    /// Authority rules by value.
    authorities: HashMap<String, Rule>,
    /// Domain rules by value.
    domains: HashMap<String, Rule>,
}

impl RuleSet {
    /// Add `rule`, replacing one with the same scope and value.
    pub fn insert(&mut self, rule: Rule) {
        let table = match rule.scope {
            RuleScope::Authority => &mut self.authorities,
            RuleScope::Domain => &mut self.domains,
        };
        table.insert(rule.value.clone(), rule);
    }

    /// Remove the rule with `id`, returning it.
    pub fn remove(&mut self, id: &str) -> Option<Rule> {
        for table in [&mut self.authorities, &mut self.domains] {
            if let Some(value) = table.values().find(|r| r.id == id).map(|r| r.value.clone()) {
                return table.remove(&value);
            }
        }
        None
    }

    /// The rule of this list with `scope` and `value`, if any.
    pub fn get(&self, scope: RuleScope, value: &str) -> Option<&Rule> {
        match scope {
            RuleScope::Authority => self.authorities.get(value),
            RuleScope::Domain => self.domains.get(value),
        }
    }

    /// How many rules.
    pub fn len(&self) -> usize {
        self.authorities.len() + self.domains.len()
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Every rule, sorted by value then scope.
    pub fn sorted(&self) -> Vec<&Rule> {
        let mut all: Vec<&Rule> = self
            .authorities
            .values()
            .chain(self.domains.values())
            .collect();
        all.sort_by(|a, b| {
            (a.value.as_str(), a.scope.as_str()).cmp(&(b.value.as_str(), b.scope.as_str()))
        });
        all
    }

    /// Whether a rule matches `authority`: an authority rule naming it, or
    /// a domain rule naming its host or a name its host is under. An IP
    /// literal is matched by authority rules only (domain rules are never
    /// addresses).
    pub fn matches(&self, authority: &Authority) -> bool {
        if self.authorities.contains_key(authority.as_str()) {
            return true;
        }
        if self.domains.is_empty() {
            return false;
        }
        let host = host_of(authority.as_str());
        if host.parse::<std::net::Ipv4Addr>().is_ok() {
            return false;
        }
        // `a.b.example.com`, `b.example.com`, `example.com`, `com`: each
        // tail starts at a label boundary.
        let mut tail = host;
        loop {
            if self.domains.contains_key(tail) {
                return true;
            }
            match tail.split_once('.') {
                Some((_, rest)) => tail = rest,
                None => return false,
            }
        }
    }
}

/// A complete, loaded policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    /// The mode in force.
    pub mode: FederationMode,
    /// Who set it and when (unix seconds); `None` while never set.
    pub mode_set: Option<(String, i64)>,
    /// The allow list.
    pub allow: RuleSet,
    /// The deny list.
    pub deny: RuleSet,
}

impl Snapshot {
    /// Whether federation with `authority` (a remote provider) is
    /// permitted.
    pub fn permits(&self, authority: &Authority) -> bool {
        match self.mode {
            FederationMode::Open => true,
            FederationMode::Allowlist => self.allow.matches(authority),
            FederationMode::Denylist => !self.deny.matches(authority),
        }
    }

    /// The rules of `list`.
    pub fn list(&self, list: RuleList) -> &RuleSet {
        match list {
            RuleList::Allow => &self.allow,
            RuleList::Deny => &self.deny,
        }
    }

    /// The rules of `list`, mutably.
    pub fn list_mut(&mut self, list: RuleList) -> &mut RuleSet {
        match list {
            RuleList::Allow => &mut self.allow,
            RuleList::Deny => &mut self.deny,
        }
    }

    /// The rule with `id` on either list.
    pub fn find(&self, id: &str) -> Option<&Rule> {
        self.allow
            .sorted()
            .into_iter()
            .chain(self.deny.sorted())
            .find(|r| r.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(list: RuleList, scope: RuleScope, value: &str) -> Rule {
        Rule {
            id: format!("{}-{}-{value}", list.as_str(), scope.as_str()),
            list,
            scope,
            value: value.to_owned(),
            note: String::new(),
            created_by: "owner".to_owned(),
            created_at: 0,
        }
    }

    fn a(s: &str) -> Authority {
        Authority::parse_canonical(s).unwrap()
    }

    fn set(rules: &[(RuleScope, &str)]) -> RuleSet {
        let mut set = RuleSet::default();
        for (scope, value) in rules {
            set.insert(rule(RuleList::Deny, *scope, value));
        }
        set
    }

    #[test]
    fn authority_rules_match_exactly_one_provider() {
        let s = set(&[(RuleScope::Authority, "evil.example")]);
        assert!(s.matches(&a("evil.example")));
        assert!(!s.matches(&a("evil.example:8443")));
        assert!(!s.matches(&a("a.evil.example")));
        let s = set(&[(RuleScope::Authority, "evil.example:8443")]);
        assert!(s.matches(&a("evil.example:8443")));
        assert!(!s.matches(&a("evil.example")));
        let s = set(&[(RuleScope::Authority, "203.0.113.7")]);
        assert!(s.matches(&a("203.0.113.7")));
        assert!(!s.matches(&a("203.0.113.7:8443")));
    }

    #[test]
    fn domain_rules_match_the_name_and_below_on_any_port() {
        let s = set(&[(RuleScope::Domain, "evil.example")]);
        for yes in [
            "evil.example",
            "evil.example:8443",
            "a.evil.example",
            "a.b.evil.example:1",
        ] {
            assert!(s.matches(&a(yes)), "{yes}");
        }
        for no in [
            "notevil.example",
            "example",
            "evil.example.org",
            "x-evil.example",
        ] {
            assert!(!s.matches(&a(no)), "{no}");
        }
    }

    #[test]
    fn domain_rules_ignore_registrable_grouping() {
        // `alice.github.io` and `bob.github.io` share a rate-limit group
        // (`github.io`) but are different providers.
        let s = set(&[(RuleScope::Domain, "alice.github.io")]);
        assert!(s.matches(&a("alice.github.io")));
        assert!(!s.matches(&a("bob.github.io")));
    }

    #[test]
    fn ip_literals_are_matched_by_authority_rules_only() {
        // `0.1` cannot be a stored domain rule (the wire syntax refuses
        // it), but matching must not depend on that.
        let s = set(&[(RuleScope::Domain, "0.1")]);
        assert!(!s.matches(&a("10.0.0.1")));
    }

    #[test]
    fn modes_select_the_list_in_force() {
        let mut snap = Snapshot::default();
        snap.allow
            .insert(rule(RuleList::Allow, RuleScope::Domain, "friend.example"));
        snap.deny
            .insert(rule(RuleList::Deny, RuleScope::Domain, "evil.example"));
        let (friend, evil, other) = (a("x.friend.example"), a("evil.example"), a("other.example"));

        assert!(snap.permits(&friend) && snap.permits(&evil) && snap.permits(&other));
        snap.mode = FederationMode::Denylist;
        assert!(snap.permits(&friend) && !snap.permits(&evil) && snap.permits(&other));
        snap.mode = FederationMode::Allowlist;
        assert!(snap.permits(&friend) && !snap.permits(&evil) && !snap.permits(&other));
    }

    #[test]
    fn rules_are_found_removed_and_listed_in_order() {
        let mut snap = Snapshot::default();
        snap.deny
            .insert(rule(RuleList::Deny, RuleScope::Domain, "b.example"));
        snap.deny
            .insert(rule(RuleList::Deny, RuleScope::Authority, "a.example"));
        snap.deny
            .insert(rule(RuleList::Deny, RuleScope::Domain, "a.example"));
        let values: Vec<_> = snap
            .deny
            .sorted()
            .iter()
            .map(|r| format!("{} {}", r.value, r.scope.as_str()))
            .collect();
        assert_eq!(
            values,
            [
                "a.example authority",
                "a.example domain",
                "b.example domain"
            ]
        );
        assert!(snap.find("deny-domain-b.example").is_some());
        assert!(snap.deny.get(RuleScope::Domain, "a.example").is_some());
        let removed = snap
            .list_mut(RuleList::Deny)
            .remove("deny-domain-b.example");
        assert_eq!(removed.unwrap().value, "b.example");
        assert_eq!(snap.deny.len(), 2);
        assert!(snap.list_mut(RuleList::Deny).remove("nope").is_none());
    }
}
