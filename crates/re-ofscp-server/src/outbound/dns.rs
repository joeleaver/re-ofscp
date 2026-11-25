//! Name resolution for outbound requests.
//!
//! The client is given this resolver, so it connects only to addresses
//! resolved *and vetted* here: there is no second lookup between the check
//! and the connection for a rebinding name to exploit.

use std::net::SocketAddr;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

use super::addr::is_public;

/// A name resolved to an address our outbound rules forbid. Found in a
/// request error's source chain, it marks the failure as a policy refusal
/// rather than a network error.
#[derive(Debug, thiserror::Error)]
#[error("{host} resolves to non-public address {addr}")]
pub struct RefusedAddress {
    /// The name looked up.
    pub host: String,
    /// The first offending address.
    pub addr: std::net::IpAddr,
}

/// Resolves names with the system resolver. When `public_only`, refuses a
/// name if **any** of its addresses is not publicly routable unicast.
#[derive(Debug, Clone, Copy)]
pub struct VettingResolver {
    /// Apply the public-address rule (off only for operator-allowed hosts).
    pub public_only: bool,
}

impl Resolve for VettingResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let public_only = self.public_only;
        let host = name.as_str().to_owned();
        Box::pin(async move {
            // A failed lookup (NXDOMAIN, SERVFAIL, timeout) is an ordinary
            // network error: the caller treats it as a fetch failure, not a
            // policy refusal (spec §4.6, lost-conn/ofscp#20).
            let addrs: Vec<SocketAddr> =
                tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
            if public_only && let Some(bad) = addrs.iter().find(|a| !is_public(a.ip())) {
                return Err(Box::new(RefusedAddress {
                    host,
                    addr: bad.ip(),
                })
                    as Box<dyn std::error::Error + Send + Sync>);
            }
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}
