//! Which IP addresses an outbound request may reach (spec §8 "Outbound
//! requests", docs/decisions/0006).
//!
//! Only publicly routable unicast addresses pass. The lists below are the
//! IANA special-purpose registries' non-global entries plus every range the
//! spec names. IPv6 forms that embed an IPv4 address are judged by the
//! embedded address, so `::ffff:127.0.0.1` is as loopback as `127.0.0.1`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Whether `ip` is a publicly routable unicast address.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

/// IPv4 ranges that are never a public peer: `(network, prefix length)`.
const REFUSED_V4: &[([u8; 4], u8)] = &[
    ([0, 0, 0, 0], 8),       // "this network", including unspecified
    ([10, 0, 0, 0], 8),      // private
    ([100, 64, 0, 0], 10),   // shared address space (carrier-grade NAT)
    ([127, 0, 0, 0], 8),     // loopback
    ([169, 254, 0, 0], 16),  // link-local (and cloud metadata services)
    ([172, 16, 0, 0], 12),   // private
    ([192, 0, 0, 0], 24),    // IETF protocol assignments
    ([192, 0, 2, 0], 24),    // documentation (TEST-NET-1)
    ([192, 168, 0, 0], 16),  // private
    ([198, 18, 0, 0], 15),   // benchmarking
    ([198, 51, 100, 0], 24), // documentation (TEST-NET-2)
    ([203, 0, 113, 0], 24),  // documentation (TEST-NET-3)
    ([224, 0, 0, 0], 4),     // multicast
    ([240, 0, 0, 0], 4),     // reserved, including broadcast
];

fn in_v4(ip: Ipv4Addr, net: [u8; 4], len: u8) -> bool {
    let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
    u32::from(ip) & mask == u32::from(Ipv4Addr::from(net)) & mask
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    !REFUSED_V4.iter().any(|&(net, len)| in_v4(ip, net, len))
}

fn in_v6(ip: Ipv6Addr, net: [u16; 8], len: u8) -> bool {
    let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
    u128::from(ip) & mask == u128::from(Ipv6Addr::from(net)) & mask
}

/// IPv6 ranges inside `2000::/3` that are not public peers.
const REFUSED_GLOBAL_V6: &[([u16; 8], u8)] = &[
    // IETF protocol assignments: Teredo (2001::/32), benchmarking
    // (2001:2::/48), ORCHID and ORCHIDv2 (2001:10::/28, 2001:20::/28), ...
    ([0x2001, 0, 0, 0, 0, 0, 0, 0], 23),
    ([0x2001, 0x0db8, 0, 0, 0, 0, 0, 0], 32), // documentation
    ([0x2002, 0, 0, 0, 0, 0, 0, 0], 16),      // 6to4
    ([0x3fff, 0, 0, 0, 0, 0, 0, 0], 20),      // documentation (RFC 9637)
];

fn is_public_v6(ip: Ipv6Addr) -> bool {
    let seg = ip.segments();
    // IPv4-mapped (::ffff:0:0/96) and IPv4-compatible (::/96, which also
    // holds :: and ::1, judged as 0.0.0.0 and 0.0.0.1: both refused).
    if seg[..5] == [0; 5] && (seg[5] == 0 || seg[5] == 0xffff) {
        return is_public_v4(embedded_v4(ip));
    }
    // Well-known NAT64 prefix (RFC 6052): the address is the IPv4 one.
    if in_v6(ip, [0x64, 0xff9b, 0, 0, 0, 0, 0, 0], 96) {
        return is_public_v4(embedded_v4(ip));
    }
    // Everything else outside 2000::/3 is not global unicast: discard
    // (100::/64), local-use NAT64 (64:ff9b:1::/48, whose IPv4 position
    // depends on the operator's prefix length, so it is refused outright),
    // unique-local (fc00::/7), link-local (fe80::/10), site-local
    // (fec0::/10), multicast (ff00::/8) and unassigned space.
    in_v6(ip, [0x2000, 0, 0, 0, 0, 0, 0, 0], 3)
        && !REFUSED_GLOBAL_V6
            .iter()
            .any(|&(net, len)| in_v6(ip, net, len))
}

/// The IPv4 address in the low 32 bits.
fn embedded_v4(ip: Ipv6Addr) -> Ipv4Addr {
    let [.., a, b, c, d] = ip.octets();
    Ipv4Addr::new(a, b, c, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> bool {
        is_public(IpAddr::V4(s.parse().unwrap()))
    }

    fn v6(s: &str) -> bool {
        is_public(IpAddr::V6(s.parse().unwrap()))
    }

    /// First, last and one inner address of each refused IPv4 range, plus
    /// the public neighbours just outside it.
    #[test]
    fn ipv4_refused_ranges_and_their_edges() {
        let cases: &[(&str, &str, &str, &[&str])] = &[
            ("0.0.0.0", "0.1.2.3", "0.255.255.255", &["1.0.0.0"]),
            (
                "10.0.0.0",
                "10.20.30.40",
                "10.255.255.255",
                &["9.255.255.255", "11.0.0.0"],
            ),
            (
                "100.64.0.0",
                "100.100.1.1",
                "100.127.255.255",
                &["100.63.255.255", "100.128.0.0"],
            ),
            (
                "127.0.0.0",
                "127.0.0.1",
                "127.255.255.255",
                &["126.255.255.255", "128.0.0.0"],
            ),
            (
                "169.254.0.0",
                "169.254.169.254",
                "169.254.255.255",
                &["169.253.255.255", "169.255.0.0"],
            ),
            (
                "172.16.0.0",
                "172.20.1.1",
                "172.31.255.255",
                &["172.15.255.255", "172.32.0.0"],
            ),
            ("192.0.0.0", "192.0.0.8", "192.0.0.255", &["192.0.1.0"]),
            ("192.0.2.0", "192.0.2.1", "192.0.2.255", &["192.0.3.0"]),
            (
                "192.168.0.0",
                "192.168.1.1",
                "192.168.255.255",
                &["192.167.255.255", "192.169.0.0"],
            ),
            (
                "198.18.0.0",
                "198.19.1.1",
                "198.19.255.255",
                &["198.17.255.255", "198.20.0.0"],
            ),
            (
                "198.51.100.0",
                "198.51.100.7",
                "198.51.100.255",
                &["198.51.99.255", "198.51.101.0"],
            ),
            (
                "203.0.113.0",
                "203.0.113.9",
                "203.0.113.255",
                &["203.0.112.255", "203.0.114.0"],
            ),
            (
                "224.0.0.0",
                "239.1.2.3",
                "239.255.255.255",
                &["223.255.255.255"],
            ),
            ("240.0.0.0", "250.1.2.3", "255.255.255.255", &[]),
        ];
        for (first, inner, last, public) in cases {
            for refused in [first, inner, last] {
                assert!(!v4(refused), "{refused} must be refused");
            }
            for ok in *public {
                assert!(v4(ok), "{ok} must be public");
            }
        }
    }

    #[test]
    fn ipv4_public_addresses_pass() {
        for ok in [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "151.101.1.1",
            "223.255.255.255",
        ] {
            assert!(v4(ok), "{ok}");
        }
    }

    #[test]
    fn ipv6_special_ranges_are_refused() {
        for refused in [
            "::",    // unspecified
            "::1",   // loopback
            "100::", // discard
            "100::ffff:ffff:ffff:ffff",
            "fc00::", // unique-local
            "fdff:ffff::1",
            "fe80::1", // link-local
            "febf:ffff::1",
            "fec0::1", // site-local
            "feff::1",
            "ff02::1", // multicast
            "ff0e::1",
            "2001::1", // Teredo
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",
            "2001:2::1",        // benchmarking
            "2001:10::1",       // ORCHID
            "2001:20::1",       // ORCHIDv2
            "2001:1ff:ffff::1", // end of 2001::/23
            "2001:db8::1",      // documentation
            "2001:db8:ffff::1",
            "3fff::1", // documentation (RFC 9637)
            "3fff:fff::1",
            "2002::1", // 6to4
            "2002:808:808::1",
            "64:ff9b:1::1", // local-use NAT64
            "64:ff9b:1:ffff::808:808",
            "1::1", // unassigned, outside 2000::/3
            "4000::1",
            "5f00::1",
        ] {
            assert!(!v6(refused), "{refused} must be refused");
        }
    }

    #[test]
    fn ipv6_embedding_ipv4_is_judged_by_the_ipv4_address() {
        for refused in [
            "::ffff:127.0.0.1", // IPv4-mapped
            "::ffff:10.1.2.3",
            "::ffff:169.254.169.254",
            "::ffff:0.0.0.0",
            "::127.0.0.1", // IPv4-compatible
            "::10.0.0.1",
            "::192.168.1.1",
            "64:ff9b::127.0.0.1", // NAT64
            "64:ff9b::a00:1",
            "64:ff9b::192.168.0.1",
            "64:ff9b::100.64.0.1",
        ] {
            assert!(!v6(refused), "{refused} must be refused");
        }
        for ok in [
            "::ffff:8.8.8.8",
            "::8.8.8.8",
            "64:ff9b::8.8.8.8",
            "64:ff9b::1.1.1.1",
        ] {
            assert!(v6(ok), "{ok} must be public");
        }
    }

    #[test]
    fn ipv6_global_unicast_passes() {
        for ok in [
            "2000::1",
            "2001:200::1",          // just past 2001::/23
            "2001:4860:4860::8888", // Google DNS
            "2606:4700:4700::1111", // Cloudflare DNS
            "2a00:1450:4001:80b::200e",
            "2001:db7:ffff::1", // just below documentation
            "2001:db9::1",      // just above
            "2003::1",          // just past 6to4
            "3ffe:ffff::1",     // just below 3fff::/20
            "3fff:1000::1",     // just past it
        ] {
            assert!(v6(ok), "{ok} must be public");
        }
    }
}
