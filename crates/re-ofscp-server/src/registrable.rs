//! Grouping remote authorities by registrable domain, so that quotas and
//! rate limits cannot be dodged by naming fresh subdomains (wildcard DNS
//! makes them free) or fresh ports of one host.
//!
//! Used by the replay store's per-domain quotas and by the outbound limits
//! (docs/decisions/0006).

/// The group of a remote authority: its registrable domain (eTLD+1 by the
/// Public Suffix List), port ignored. IP literals, and hosts without a
/// registrable domain (`localhost`, a bare public suffix), group by host.
pub fn registrable_group(authority: &str) -> String {
    // A bracketed IPv6 literal, with or without a port: the address itself
    // (its own colons must not be read as a port separator).
    if let Some(end) = authority.strip_prefix('[').and_then(|rest| rest.find(']')) {
        return authority[..end + 2].to_owned();
    }
    let host = authority
        .rsplit_once(':')
        .map_or(authority, |(host, _port)| host);
    // The PSL would read `10.0.0.1` as a name under the suffix `1`.
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        return host.to_owned();
    }
    psl::domain_str(host).unwrap_or(host).to_owned()
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
    fn ipv6_literals_group_by_address() {
        assert_eq!(registrable_group("[2001:db8::1]"), "[2001:db8::1]");
        assert_eq!(registrable_group("[2001:db8::1]:8443"), "[2001:db8::1]");
        assert_ne!(
            registrable_group("[2001:db8::1]"),
            registrable_group("[2001:db8::2]")
        );
    }
}
