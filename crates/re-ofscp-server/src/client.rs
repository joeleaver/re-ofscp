//! The client's address, for rate limiting and the admin audit log.

use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::HeaderMap;
use axum::http::request::Parts;

use crate::Config;

/// The TCP peer address, when the server was started with connect info
/// (tests calling the router directly have none).
pub struct Peer(Option<SocketAddr>);

impl Peer {
    /// The peer recorded in `parts`, if any.
    pub fn from_parts(parts: &Parts) -> Self {
        Self(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|c| c.0),
        )
    }
}

impl<S: Send + Sync> FromRequestParts<S> for Peer {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self::from_parts(parts))
    }
}

/// The client's address for rate limiting.
///
/// With `CLIENT_IP_HEADER` configured, the header's **last** entry: the one
/// our trusted proxy added (earlier `X-Forwarded-For` entries are whatever
/// the client sent). Otherwise the TCP peer. IPv6 addresses are grouped by
/// /64, the usual unit one subscriber controls, so a client cannot mint
/// fresh rate-limit keys by cycling through its own prefix.
pub fn client_key(config: &Config, headers: &HeaderMap, peer: &Peer) -> String {
    let Some(name) = config.client_ip_header.as_ref() else {
        return peer
            .0
            .map_or_else(|| "unknown".to_owned(), |a| rate_key(a.ip()));
    };
    let last = headers
        .get(name.as_str())
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.rsplit(',').next())
        .map(str::trim)
        .filter(|v| !v.is_empty());
    let Some(last) = last else {
        // The trusted proxy always sets it; without it every client would
        // share the proxy's address as one bucket.
        tracing::error!(header = %name, "client address header missing; keying by TCP peer");
        return peer
            .0
            .map_or_else(|| "unknown".to_owned(), |a| rate_key(a.ip()));
    };
    match parse_client_addr(last) {
        Some(ip) => rate_key(ip),
        None => {
            // Appended by the trusted proxy, so still one client's value:
            // key by it rather than collapse everyone into one bucket.
            tracing::error!(header = %name, "client address header is not an IP address");
            format!("raw:{}", last.chars().take(64).collect::<String>())
        }
    }
}

/// An address as proxies write it: `203.0.113.7`, `2001:db8::1`,
/// `203.0.113.7:4711` or `[2001:db8::1]:4711`.
fn parse_client_addr(v: &str) -> Option<IpAddr> {
    v.parse::<IpAddr>()
        .ok()
        .or_else(|| v.parse::<SocketAddr>().ok().map(|a| a.ip()))
}

/// IPv4 as is (and IPv4-mapped IPv6 as IPv4); other IPv6 by its /64.
fn rate_key(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let s = v6.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_addresses_parse_with_or_without_a_port() {
        let ip = |s: &str| parse_client_addr(s).map(|a| a.to_string());
        assert_eq!(ip("203.0.113.7").as_deref(), Some("203.0.113.7"));
        assert_eq!(ip("203.0.113.7:4711").as_deref(), Some("203.0.113.7"));
        assert_eq!(ip("[2001:db8::1]:4711").as_deref(), Some("2001:db8::1"));
        assert_eq!(ip("2001:db8::1").as_deref(), Some("2001:db8::1"));
        assert_eq!(ip("for=203.0.113.7"), None);
    }

    #[test]
    fn rate_keys_group_ipv6_by_64() {
        let k = |s: &str| rate_key(s.parse().unwrap());
        assert_eq!(k("203.0.113.7"), "203.0.113.7");
        assert_eq!(k("::ffff:203.0.113.7"), "203.0.113.7");
        assert_eq!(k("2001:db8:1:2:aaaa::1"), "2001:db8:1:2::/64");
        assert_eq!(k("2001:db8:1:2:bbbb::9"), k("2001:db8:1:2:aaaa::1"));
        assert_ne!(k("2001:db8:1:3::1"), k("2001:db8:1:2::1"));
    }
}
