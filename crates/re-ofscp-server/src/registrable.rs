//! Grouping remote authorities by registrable domain, so that quotas and
//! rate limits cannot be dodged by naming fresh subdomains (wildcard DNS
//! makes them free) or fresh ports of one host.
//!
//! The registrable domain is taken against the **ICANN section** of the
//! Public Suffix List only. The private section lists suffixes such as
//! `workers.dev`, `vercel.app` or `github.io` under which anyone can get a
//! name for free, often thousands of them; reading those as public suffixes
//! would make every such name a group of its own, and a crowd of free
//! groups can push a real peer's entries out of every table bounded per
//! group. So all of `*.workers.dev` is the one group `workers.dev`
//! (docs/decisions/0006, "Target groups").
//!
//! Used by the replay store's per-domain quotas and by the outbound limits
//! (docs/decisions/0001, 0006). [`has_unknown_suffix`] lets the remote key
//! resolver refuse hosts under a suffix the ICANN section does not know,
//! whose implicit `*` rule would otherwise make every name its own group.

use psl::Type;

/// The host of an authority, port dropped. A bracketed IPv6 literal is kept
/// whole, brackets included (its own colons are not a port separator).
pub fn host_of(authority: &str) -> &str {
    if let Some(end) = authority.strip_prefix('[').and_then(|rest| rest.find(']')) {
        return &authority[..end + 2];
    }
    authority
        .rsplit_once(':')
        .map_or(authority, |(host, _port)| host)
}

/// Whether `host` (no port) is an IP literal.
fn is_ip_literal(host: &str) -> bool {
    host.starts_with('[') || host.parse::<std::net::Ipv4Addr>().is_ok()
}

/// The public suffix of `host` (a name, no port) by the ICANN section of
/// the PSL alone, as a tail of `host`; `None` when the ICANN section has
/// no rule for it (an unlisted TLD).
///
/// The `psl` crate answers with the longest matching rule of either
/// section. When that is a private rule, every ICANN rule matching `host`
/// is shorter than it, so is a suffix of the private suffix minus its
/// first label: look that tail up again, until an ICANN rule answers.
/// Each round drops at least one label, so this ends.
fn icann_suffix(host: &str) -> Option<&str> {
    let mut tail = host;
    loop {
        let suffix = psl::suffix(tail.as_bytes())?;
        let len = suffix.as_bytes().len();
        match suffix.typ() {
            Some(Type::Icann) => return host.get(host.len() - len..),
            Some(Type::Private) => {
                let private = tail.get(tail.len() - len..)?;
                tail = private.split_once('.')?.1;
            }
            None => return None,
        }
    }
}

/// The group of a remote authority: its registrable domain (eTLD+1 by the
/// ICANN section of the Public Suffix List; private-section suffixes are
/// ignored), port ignored. Under a TLD the list does not know, the PSL's
/// default `*` rule applies: the TLD is the suffix, so `a.n1.zzqq` groups
/// as `n1.zzqq` (such hosts reach us only when an operator allows them).
/// IP literals, and hosts without a registrable domain (`localhost`, a
/// bare public suffix), group by host.
pub fn registrable_group(authority: &str) -> String {
    let host = host_of(authority);
    // The PSL would read `10.0.0.1` as a name under the suffix `1`.
    if is_ip_literal(host) {
        return host.to_owned();
    }
    let suffix =
        icann_suffix(host).unwrap_or_else(|| host.rsplit_once('.').map_or(host, |(_, tld)| tld));
    // The label just left of the suffix, with the suffix: `a.b.example.com`
    // -> `example.com`. A host that is the suffix itself groups by host.
    let Some(rest) = host
        .len()
        .checked_sub(suffix.len() + 1)
        .and_then(|end| host.get(..end))
    else {
        return host.to_owned();
    };
    let start = rest.rfind('.').map_or(0, |dot| dot + 1);
    host.get(start..).unwrap_or(host).to_owned()
}

/// Whether `authority`'s host is a name whose public suffix the ICANN
/// section of the PSL does not list (`n1.zzqq`, `localhost`, `peer.test`).
/// The PSL's implicit `*` rule treats any unlisted TLD as a suffix, so
/// every `{n}.zzqq` would be a registrable domain, and so a group, of its
/// own. A name under a private-section suffix is known exactly when that
/// suffix sits under a known ICANN suffix (`x.workers.dev` is, under
/// `dev`): it groups under the ICANN registrable domain like any other
/// name. IP literals have no suffix and are never "unknown": the address
/// rule judges them.
pub fn has_unknown_suffix(authority: &str) -> bool {
    let host = host_of(authority);
    !is_ip_literal(host) && icann_suffix(host).is_none()
}

/// Whether `host` (a name, no port) is itself a public suffix by the
/// ICANN section of the PSL (`com`, `co.uk`), so a rule covering it and
/// every name under it would cover a whole registry. Private-section
/// suffixes (`github.io`) are not: they are one operator's names. Used to
/// refuse such federation-policy rules (docs/decisions/0008).
pub fn is_icann_public_suffix(host: &str) -> bool {
    !is_ip_literal(host) && icann_suffix(host) == Some(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icann_public_suffixes_are_recognised() {
        for yes in ["com", "co.uk", "app", "dev"] {
            assert!(is_icann_public_suffix(yes), "{yes}");
        }
        for no in [
            "example.com",
            "foo.co.uk",
            "github.io",
            "alice.github.io",
            "10.0.0.1",
            "zzqq",
        ] {
            assert!(!is_icann_public_suffix(no), "{no}");
        }
    }

    #[test]
    fn registrable_groups_ignore_subdomains_and_ports() {
        assert_eq!(registrable_group("evil.example.com"), "example.com");
        assert_eq!(
            registrable_group("a.b.evil.example.com:8443"),
            "example.com"
        );
        assert_eq!(registrable_group("x.foo.co.uk"), "foo.co.uk");
        // Hosts without a registrable domain group by host.
        assert_eq!(registrable_group("localhost:8080"), "localhost");
        assert_eq!(registrable_group("10.0.0.1"), "10.0.0.1");
        assert_eq!(registrable_group("10.0.0.1:8443"), "10.0.0.1");
        assert_eq!(registrable_group("com"), "com");
        assert_eq!(registrable_group("n1.zzqq"), "n1.zzqq");
        // An unlisted TLD falls back to the PSL's default `*` rule.
        assert_eq!(registrable_group("a.n1.zzqq:8443"), "n1.zzqq");
        assert_eq!(registrable_group("x.peer.test"), "peer.test");
    }

    #[test]
    fn private_section_suffixes_collapse_into_their_icann_group() {
        for (host, group) in [
            ("x1.workers.dev", "workers.dev"),
            ("x2.workers.dev:8443", "workers.dev"),
            ("a.b.x3.workers.dev", "workers.dev"),
            ("workers.dev", "workers.dev"),
            ("x.vercel.app", "vercel.app"),
            ("alice.github.io", "github.io"),
            ("bob.duckdns.org", "duckdns.org"),
            ("user.blogspot.com", "blogspot.com"),
            // A private wildcard rule several labels deep.
            ("a.b.c.compute.amazonaws.com", "amazonaws.com"),
            // ICANN multi-label suffixes are kept.
            ("x.foo.co.uk", "foo.co.uk"),
        ] {
            assert_eq!(registrable_group(host), group, "{host}");
        }
        // Two thousand free subdomains are one group.
        let groups: std::collections::HashSet<String> = (0..2000)
            .map(|i| registrable_group(&format!("s{i}.workers.dev")))
            .collect();
        assert_eq!(groups.len(), 1);
    }

    #[test]
    fn the_icann_suffix_skips_private_rules() {
        assert_eq!(icann_suffix("x1.workers.dev"), Some("dev"));
        assert_eq!(icann_suffix("workers.dev"), Some("dev"));
        assert_eq!(icann_suffix("x.foo.co.uk"), Some("co.uk"));
        assert_eq!(icann_suffix("a.b.compute.amazonaws.com"), Some("com"));
        assert_eq!(icann_suffix("com"), Some("com"));
        assert_eq!(icann_suffix("n1.zzqq"), None);
        assert_eq!(icann_suffix("localhost"), None);
    }

    #[test]
    fn hosts_under_unlisted_suffixes_are_unknown() {
        for unknown in [
            "n1.zzqq",
            "n2.zzqq:8443",
            "zzqq",
            "localhost",
            "localhost:8080",
            "peer.test",
            "victim.example",
        ] {
            assert!(has_unknown_suffix(unknown), "{unknown}");
        }
        for known in [
            "example.com",
            "a.b.example.com:8443",
            "x.foo.co.uk",
            "com",
            "user.github.io",
            "x1.workers.dev",
            "workers.dev:8443",
            "10.0.0.1",
            "10.0.0.1:8443",
            "[2001:db8::1]:8443",
        ] {
            assert!(!has_unknown_suffix(known), "{known}");
        }
    }

    #[test]
    fn hosts_drop_the_port_but_keep_ipv6_literals_whole() {
        assert_eq!(host_of("peer.test:8443"), "peer.test");
        assert_eq!(host_of("peer.test"), "peer.test");
        assert_eq!(host_of("[2001:db8::1]:8443"), "[2001:db8::1]");
        assert_eq!(host_of("[2001:db8::1]"), "[2001:db8::1]");
    }

    #[test]
    fn ipv6_literals_group_by_address() {
        assert_eq!(registrable_group("[2001:db8::1]"), "[2001:db8::1]");
        assert_eq!(registrable_group("[2001:db8::1]:8443"), "[2001:db8::1]");
        assert_ne!(
            registrable_group("[2001:db8::1]"),
            registrable_group("[2001:db8::2]")
        );
    }
}
