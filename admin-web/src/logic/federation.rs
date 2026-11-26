//! The federation policy screen's logic (docs/decisions/0008): the mode
//! as people read it, and the add-rule form. The server checks again, and
//! more (it also refuses public suffixes and this provider's own
//! authority); this catches typing mistakes before a request is sent.

use re_ofscp_types::federation::{
    AddFederationRule, FederationMode, MAX_RULE_NOTE_LEN, RuleList, RuleScope, canonical_rule_value,
};

use super::Invalid;

/// Every mode, in the picker's order.
pub const MODES: [FederationMode; 3] = [
    FederationMode::Open,
    FederationMode::Denylist,
    FederationMode::Allowlist,
];

/// A mode as people read it.
pub fn mode_label(mode: FederationMode) -> &'static str {
    match mode {
        FederationMode::Open => "Open",
        FederationMode::Allowlist => "Allowlist",
        FederationMode::Denylist => "Denylist",
    }
}

/// What a mode does, in one sentence.
pub fn mode_effect(mode: FederationMode) -> &'static str {
    match mode {
        FederationMode::Open => "Federate with every provider. Neither list is in force.",
        FederationMode::Allowlist => {
            "Federate only with providers on the allowlist. Everyone else is refused."
        }
        FederationMode::Denylist => "Federate with every provider except those on the denylist.",
    }
}

/// What switching from `from` to `to` will do, for the confirmation.
pub fn switch_warning(from: FederationMode, to: FederationMode, allowed: usize) -> String {
    let effect = mode_effect(to);
    match (from, to) {
        (_, FederationMode::Allowlist) if allowed == 0 => format!(
            "{effect} The allowlist is empty, so federation with every other provider stops at once."
        ),
        (_, FederationMode::Allowlist) => format!(
            "{effect} Signed requests from unlisted providers will get 403, and nothing will be sent to them."
        ),
        _ => effect.to_owned(),
    }
}

/// A list as people read it.
pub fn list_label(list: RuleList) -> &'static str {
    match list {
        RuleList::Allow => "Allowlist",
        RuleList::Deny => "Denylist",
    }
}

/// A scope as people read it.
pub fn scope_label(scope: RuleScope) -> &'static str {
    match scope {
        RuleScope::Authority => "Host (port optional)",
        RuleScope::Domain => "Domain and subdomains",
    }
}

/// Whether `list` is the one `mode` puts in force.
pub fn in_force(mode: FederationMode, list: RuleList) -> bool {
    mode.active_list() == Some(list)
}

/// The add-rule form as a request: `list` and `scope` are the pickers'
/// values (`allow`/`deny`, `authority`/`domain`).
pub fn add_rule(
    list: &str,
    scope: &str,
    value: &str,
    note: &str,
) -> Result<AddFederationRule, Invalid> {
    let list = RuleList::parse(list).ok_or_else(|| Invalid::new("Choose a list."))?;
    let scope =
        RuleScope::parse(scope).ok_or_else(|| Invalid::new("Choose what the rule matches."))?;
    if value.trim().is_empty() {
        return Err(Invalid::new("Enter a provider or domain."));
    }
    let value = canonical_rule_value(scope, value)
        .map_err(|e| Invalid::new(format!("Not a valid rule value: {e}.")))?;
    let note = note.trim();
    if note.len() > MAX_RULE_NOTE_LEN {
        return Err(Invalid::new(format!(
            "A note is at most {MAX_RULE_NOTE_LEN} characters."
        )));
    }
    Ok(AddFederationRule {
        list,
        scope,
        value,
        note: (!note.is_empty()).then(|| note.to_owned()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rule_is_canonicalized_before_it_is_sent() {
        let r = add_rule("deny", "domain", "  Evil.Example. ", " spam wave ").unwrap();
        assert_eq!(r.list, RuleList::Deny);
        assert_eq!(r.scope, RuleScope::Domain);
        assert_eq!(r.value, "evil.example");
        assert_eq!(r.note.as_deref(), Some("spam wave"));
        let r = add_rule("allow", "authority", "Peer.Example:443", "").unwrap();
        assert_eq!(r.value, "peer.example");
        assert_eq!(r.note, None);
        assert_eq!(
            add_rule("allow", "authority", "peer.example:8443", "")
                .unwrap()
                .value,
            "peer.example:8443"
        );
    }

    #[test]
    fn bad_rules_are_caught_with_a_message() {
        for (list, scope, value, note) in [
            ("", "domain", "a.example", ""),
            ("deny", "", "a.example", ""),
            ("deny", "domain", "   ", ""),
            ("deny", "domain", "a.example:8443", ""),
            ("deny", "domain", "com", ""),
            ("deny", "authority", "https://a.example", ""),
        ] {
            let e = add_rule(list, scope, value, note).unwrap_err();
            assert!(!e.0.is_empty(), "{value}");
        }
        let long = "x".repeat(MAX_RULE_NOTE_LEN + 1);
        assert!(add_rule("deny", "domain", "a.example", &long).is_err());
        let fits = "x".repeat(MAX_RULE_NOTE_LEN);
        assert!(add_rule("deny", "domain", "a.example", &fits).is_ok());
    }

    #[test]
    fn the_list_in_force_follows_the_mode() {
        assert!(!in_force(FederationMode::Open, RuleList::Allow));
        assert!(!in_force(FederationMode::Open, RuleList::Deny));
        assert!(in_force(FederationMode::Allowlist, RuleList::Allow));
        assert!(in_force(FederationMode::Denylist, RuleList::Deny));
        assert!(!in_force(FederationMode::Denylist, RuleList::Allow));
    }

    #[test]
    fn switching_to_an_empty_allowlist_is_spelled_out() {
        let w = switch_warning(FederationMode::Open, FederationMode::Allowlist, 0);
        assert!(w.contains("empty"), "{w}");
        let w = switch_warning(FederationMode::Open, FederationMode::Allowlist, 3);
        assert!(w.contains("403"), "{w}");
        assert_eq!(
            switch_warning(FederationMode::Allowlist, FederationMode::Open, 3),
            mode_effect(FederationMode::Open)
        );
    }
}
