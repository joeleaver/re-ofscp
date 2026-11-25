//! Grouping remote authorities by registrable domain, so that quotas and
//! rate limits cannot be dodged by naming fresh subdomains (wildcard DNS
//! makes them free) or fresh ports of one host.
//!
//! Used by the replay store's per-domain quotas and by the outbound limits
//! (docs/decisions/0006). [`has_unknown_suffix`] lets the remote key
//! resolver refuse hosts under a suffix the PSL does not know, whose
//! implicit `*` rule would otherwise make every name its own group.

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

/// The group of a remote authority: its registrable domain (eTLD+1 by the
/// Public Suffix List), port ignored. IP literals, and hosts without a
/// registrable domain (`localhost`, a bare public suffix), group by host.
pub fn registrable_group(authority: &str) -> String {
    let host = host_of(authority);
    // The PSL would read `10.0.0.1` as a name under the suffix `1`.
    if is_ip_literal(host) {
        return host.to_owned();
    }
    psl::domain_str(host).unwrap_or(host).to_owned()
}

/// Whether `authority`'s host is a name whose public suffix the PSL does
/// not list (`n1.zzqq`, `localhost`, `peer.test`). The PSL's implicit `*`
/// rule treats any unlisted TLD as a suffix, so every `{n}.zzqq` would be a
/// registrable domain, and so a group, of its own. IP literals have no
/// suffix and are never "unknown": the address rule judges them.
pub fn has_unknown_suffix(authority: &str) -> bool {
    let host = host_of(authority);
    !is_ip_literal(host) && !psl::suffix(host.as_bytes()).is_some_and(|s| s.is_known())
}

#[cfg(test)]
mod tests {
    use super::*;

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
