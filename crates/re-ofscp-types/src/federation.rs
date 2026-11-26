//! The federation allow/deny policy (spec §8 *Authorization*;
//! docs/decisions/0008): its wire form for the admin API
//! (`/api/admin/federation*`) and the syntax of its rules.
//!
//! The policy is provider-wide. Its [`FederationMode`] says which list, if
//! any, is in force; both lists are kept whatever the mode, so an operator
//! can prepare an allowlist before switching to it. A [`RuleScope`] says
//! what one rule matches. Like the rest of this provider's admin JSON, the
//! payloads are camelCase.

use serde::{Deserialize, Serialize};

use crate::Authority;

/// Most rules on one list.
pub const MAX_RULES_PER_LIST: usize = 1000;

/// Longest rule note, in bytes.
pub const MAX_RULE_NOTE_LEN: usize = 200;

/// Which list governs federation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FederationMode {
    /// Federate with every provider (the default).
    #[default]
    Open,
    /// Federate only with providers an allow rule matches.
    Allowlist,
    /// Federate with every provider except those a deny rule matches.
    Denylist,
}

impl FederationMode {
    /// The stored and wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Allowlist => "allowlist",
            Self::Denylist => "denylist",
        }
    }

    /// Parse the stored spelling.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "open" => Some(Self::Open),
            "allowlist" => Some(Self::Allowlist),
            "denylist" => Some(Self::Denylist),
            _ => None,
        }
    }

    /// The list this mode puts in force, if any.
    pub fn active_list(self) -> Option<RuleList> {
        match self {
            Self::Open => None,
            Self::Allowlist => Some(RuleList::Allow),
            Self::Denylist => Some(RuleList::Deny),
        }
    }
}

/// The list a rule belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleList {
    /// Used in [`FederationMode::Allowlist`].
    Allow,
    /// Used in [`FederationMode::Denylist`].
    Deny,
}

impl RuleList {
    /// The stored and wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }

    /// Parse the stored spelling.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "allow" => Some(Self::Allow),
            "deny" => Some(Self::Deny),
            _ => None,
        }
    }
}

/// What a rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleScope {
    /// Exactly one provider: a canonical authority (§2.4), `host` or
    /// `host:port`. `example.com` does not match `example.com:8443` or
    /// `a.example.com`.
    Authority,
    /// A DNS name and every name under it, on any port: `example.com`
    /// matches `example.com`, `a.example.com` and `example.com:8443`, but
    /// not `notexample.com`.
    Domain,
}

impl RuleScope {
    /// The stored and wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Authority => "authority",
            Self::Domain => "domain",
        }
    }

    /// Parse the stored spelling.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "authority" => Some(Self::Authority),
            "domain" => Some(Self::Domain),
            _ => None,
        }
    }
}

/// Why a rule value was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleValueError {
    /// Not a provider authority (§2.4).
    NotAnAuthority,
    /// A domain rule names a port, or is not a DNS name.
    NotADomain,
    /// A domain rule of a single label or a numeric last label would cover
    /// a whole top-level domain, or IP addresses.
    TooBroad,
}

impl std::fmt::Display for RuleValueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotAnAuthority => "not a provider authority (host or host:port)",
            Self::NotADomain => "a domain rule is a DNS name without a port",
            Self::TooBroad => {
                "a domain rule must have at least two labels and must not be an IP address"
            }
        })
    }
}

impl std::error::Error for RuleValueError {}

/// The canonical value of a rule of `scope` written as `input`
/// (surrounding whitespace ignored, case folded, a trailing dot and the
/// default port dropped). The server refuses more than this checks: a
/// domain rule that is itself a public suffix (`co.uk`) and an authority
/// rule naming this provider.
pub fn canonical_rule_value(scope: RuleScope, input: &str) -> Result<String, RuleValueError> {
    let input = input.trim();
    match scope {
        RuleScope::Authority => Authority::canonicalize(input)
            .map(|a| a.as_str().to_owned())
            .map_err(|_| RuleValueError::NotAnAuthority),
        RuleScope::Domain => {
            let authority =
                Authority::canonicalize(input).map_err(|_| RuleValueError::NotADomain)?;
            let host = authority.as_str();
            if host.contains(':') {
                return Err(RuleValueError::NotADomain);
            }
            match host.rsplit_once('.') {
                // A numeric last label is an IPv4 address (or a part of
                // one), never a top-level domain.
                Some((_, tld)) if !tld.bytes().all(|b| b.is_ascii_digit()) => Ok(host.to_owned()),
                _ => Err(RuleValueError::TooBroad),
            }
        }
    }
}

/// One rule, as the admin API shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FederationRuleView {
    /// The rule's id (for removal).
    pub id: String,
    /// Its list.
    pub list: RuleList,
    /// What it matches.
    pub scope: RuleScope,
    /// The canonical authority or domain.
    pub value: String,
    /// The note the admin left, possibly empty.
    pub note: String,
    /// The admin who added it.
    pub created_by: String,
    /// RFC 3339.
    pub created_at: String,
}

/// `GET /api/admin/federation`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FederationPolicyView {
    /// The mode in force.
    pub mode: FederationMode,
    /// Who last set the mode; absent while it was never set (open).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode_set_by: Option<String>,
    /// When (RFC 3339); absent while it was never set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode_set_at: Option<String>,
    /// The allow rules, by value.
    pub allow: Vec<FederationRuleView>,
    /// The deny rules, by value.
    pub deny: Vec<FederationRuleView>,
}

/// `PUT /api/admin/federation/mode` (owner).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SetFederationMode {
    /// The new mode.
    pub mode: FederationMode,
}

/// `POST /api/admin/federation/rules` (operator).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AddFederationRule {
    /// The list to add it to.
    pub list: RuleList,
    /// What it matches.
    pub scope: RuleScope,
    /// The authority or domain ([`canonical_rule_value`] applies).
    pub value: String,
    /// An optional note (at most [`MAX_RULE_NOTE_LEN`] bytes).
    #[serde(default)]
    pub note: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spellings_round_trip() {
        for m in [
            FederationMode::Open,
            FederationMode::Allowlist,
            FederationMode::Denylist,
        ] {
            assert_eq!(FederationMode::parse(m.as_str()), Some(m));
            assert_eq!(
                serde_json::to_string(&m).unwrap(),
                format!("\"{}\"", m.as_str())
            );
        }
        for l in [RuleList::Allow, RuleList::Deny] {
            assert_eq!(RuleList::parse(l.as_str()), Some(l));
        }
        for s in [RuleScope::Authority, RuleScope::Domain] {
            assert_eq!(RuleScope::parse(s.as_str()), Some(s));
        }
        assert_eq!(FederationMode::parse("closed"), None);
        assert_eq!(FederationMode::default(), FederationMode::Open);
        assert_eq!(FederationMode::Open.active_list(), None);
        assert_eq!(FederationMode::Denylist.active_list(), Some(RuleList::Deny));
    }

    #[test]
    fn authority_rules_are_canonical_authorities() {
        let v = |s| canonical_rule_value(RuleScope::Authority, s);
        assert_eq!(v(" Evil.Example. ").unwrap(), "evil.example");
        assert_eq!(v("evil.example:443").unwrap(), "evil.example");
        assert_eq!(v("evil.example:8443").unwrap(), "evil.example:8443");
        assert_eq!(v("localhost:8080").unwrap(), "localhost:8080");
        assert_eq!(v("203.0.113.7").unwrap(), "203.0.113.7");
        for bad in [
            "",
            "https://evil.example",
            "evil.example/x",
            "a b",
            "évil.example",
        ] {
            assert_eq!(v(bad), Err(RuleValueError::NotAnAuthority), "{bad}");
        }
    }

    #[test]
    fn domain_rules_are_multi_label_names_without_ports() {
        let v = |s| canonical_rule_value(RuleScope::Domain, s);
        assert_eq!(v("Evil.Example").unwrap(), "evil.example");
        assert_eq!(v("a.b.evil.example.").unwrap(), "a.b.evil.example");
        assert_eq!(v("evil.example:443").unwrap(), "evil.example");
        assert_eq!(v("evil.example:8443"), Err(RuleValueError::NotADomain));
        assert_eq!(v("x/y"), Err(RuleValueError::NotADomain));
        for broad in ["com", "localhost", "203.0.113.7", "0.1"] {
            assert_eq!(v(broad), Err(RuleValueError::TooBroad), "{broad}");
        }
    }

    #[test]
    fn payloads_are_camel_case_and_strict() {
        let add: AddFederationRule = serde_json::from_str(
            r#"{"list":"deny","scope":"domain","value":"evil.example","note":"spam"}"#,
        )
        .unwrap();
        assert_eq!(add.list, RuleList::Deny);
        assert!(
            serde_json::from_str::<AddFederationRule>(
                r#"{"list":"deny","scope":"domain","value":"x.example","extra":1}"#
            )
            .is_err()
        );
        let view = FederationPolicyView {
            mode: FederationMode::Open,
            mode_set_by: None,
            mode_set_at: None,
            allow: vec![],
            deny: vec![],
        };
        assert_eq!(
            serde_json::to_string(&view).unwrap(),
            r#"{"mode":"open","allow":[],"deny":[]}"#
        );
    }
}
