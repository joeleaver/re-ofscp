//! The one HTTP client for requests to hosts someone else chose (spec §8
//! "Outbound requests", docs/decisions/0006).
//!
//! * `https` only: URLs are built from a canonical [`Authority`] and a path;
//!   there is no way to ask for anything else.
//! * Public addresses only: an IP-literal host is checked directly (after
//!   URL parsing, which also turns WHATWG numeric hosts such as
//!   `2130706433` into IPv4), and a name is checked by the resolver
//!   ([`dns::VettingResolver`]) the client connects through.
//! * No redirects (a `3xx` is a failure), no proxy, bounded time and body,
//!   a process-wide cap on requests in flight, and a per-target one
//!   ([`inflight`]) so that a few stalling hosts cannot take every slot.
//! * TLS through rustls with the bundled Mozilla roots.
//!
//! Hosts in `OUTBOUND_ALLOW_HOSTS` skip only the address rule.

pub mod addr;
pub mod dns;
pub mod inflight;

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use axum::http::{HeaderMap, StatusCode, header};
use re_ofscp_types::Authority;
use tokio::sync::Semaphore;
use url::{Host, Url};

use self::dns::{RefusedAddress, VettingResolver};
use self::inflight::PerTarget;
use crate::registrable::registrable_group;

/// Limits and trust settings for an [`OutboundClient`].
#[derive(Debug, Clone)]
pub struct OutboundConfig {
    /// Authorities whose addresses are not checked (development, private
    /// peerings). Every other rule still applies.
    pub allow_hosts: Vec<Authority>,
    /// Extra trust anchors (DER) beside the Mozilla roots. Production uses
    /// none; tests add the root of a local certificate authority.
    pub extra_roots: Vec<Vec<u8>>,
    /// Whole-request deadline, including waiting for a slot and reading
    /// the body.
    pub timeout: Duration,
    /// TCP connect deadline.
    pub connect_timeout: Duration,
    /// Largest response body read; a larger one fails the request.
    pub max_body: usize,
    /// Most requests in flight at once, process-wide.
    pub max_in_flight: usize,
    /// Most requests in flight at once to one target, grouped by
    /// registrable domain (ports and subdomains share it). Past it a
    /// request fails at once with [`OutboundError::Busy`].
    pub max_in_flight_per_target: usize,
}

impl OutboundConfig {
    /// The defaults of docs/decisions/0006 (10 s, 5 s connect, 64 KiB, 64
    /// in flight, 4 per target), allowing `allow_hosts` to be internal.
    pub fn new(allow_hosts: Vec<Authority>) -> Self {
        Self {
            allow_hosts,
            extra_roots: Vec::new(),
            timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(5),
            max_body: 64 * 1024,
            max_in_flight: 64,
            max_in_flight_per_target: 4,
        }
    }
}

/// Why an outbound request did not produce a response.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OutboundError {
    /// Our outbound rules forbid contacting this target (a non-public
    /// address, or a URL we will not build). Deterministic: retrying
    /// cannot help.
    #[error("outbound request refused: {0}")]
    Refused(String),
    /// The peer answered with a redirect, which is never followed.
    #[error("peer answered with redirect {0}")]
    Redirect(u16),
    /// Too many requests to this target are already in flight. Not
    /// queued: a target that stalls must not make requests to it pile up.
    #[error("too many requests in flight to {0}")]
    Busy(String),
    /// The response body exceeded the cap.
    #[error("response body larger than {0} bytes")]
    TooLarge(usize),
    /// The request did not finish in time.
    #[error("outbound request timed out")]
    Timeout,
    /// Anything else on the network or TLS level, including a name that
    /// does not resolve.
    #[error("outbound request failed: {0}")]
    Network(String),
}

/// A response that was read completely.
#[derive(Debug, Clone)]
pub struct OutboundResponse {
    /// Status (never `3xx`).
    pub status: StatusCode,
    /// Headers.
    pub headers: HeaderMap,
    /// The whole body, at most `max_body` bytes.
    pub body: Vec<u8>,
}

/// Could not build the client (TLS setup).
#[derive(Debug, thiserror::Error)]
#[error("cannot build the outbound HTTP client: {0}")]
pub struct BuildError(String);

/// The SSRF-safe outbound client.
pub struct OutboundClient {
    /// Vets every resolved address.
    strict: reqwest::Client,
    /// For operator-allowed authorities only.
    allowed: reqwest::Client,
    allow_hosts: HashSet<Authority>,
    slots: Arc<Semaphore>,
    per_target: PerTarget,
    timeout: Duration,
    max_body: usize,
}

impl std::fmt::Debug for OutboundClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundClient")
            .field("allow_hosts", &self.allow_hosts)
            .finish_non_exhaustive()
    }
}

impl OutboundClient {
    /// Build a client.
    pub fn new(config: &OutboundConfig) -> Result<Self, BuildError> {
        let tls = tls_config(&config.extra_roots)?;
        let build = |public_only: bool| {
            reqwest::Client::builder()
                .tls_backend_preconfigured(tls.clone())
                .https_only(true)
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .dns_resolver(Arc::new(VettingResolver { public_only }))
                .timeout(config.timeout)
                .connect_timeout(config.connect_timeout)
                .user_agent(concat!("re-ofscp/", env!("CARGO_PKG_VERSION")))
                .build()
                .map_err(|e| BuildError(e.to_string()))
        };
        Ok(Self {
            strict: build(true)?,
            allowed: build(false)?,
            allow_hosts: config.allow_hosts.iter().cloned().collect(),
            slots: Arc::new(Semaphore::new(config.max_in_flight.max(1))),
            per_target: PerTarget::new(config.max_in_flight_per_target),
            timeout: config.timeout,
            max_body: config.max_body,
        })
    }

    /// Check a target without contacting it: the URL `https://{authority}{path}`
    /// and, for an IP-literal host, the address rule. Names are checked when
    /// they are resolved.
    pub fn target(&self, authority: &Authority, path: &str) -> Result<Url, OutboundError> {
        if !path.starts_with('/') {
            return Err(OutboundError::Refused(format!(
                "path {path:?} is not absolute"
            )));
        }
        let url = Url::parse(&format!("https://{authority}{path}"))
            .map_err(|e| OutboundError::Refused(format!("{authority}: {e}")))?;
        if self.allow_hosts.contains(authority) {
            return Ok(url);
        }
        let ip = match url.host() {
            Some(Host::Domain(_)) => return Ok(url),
            Some(Host::Ipv4(ip)) => ip.into(),
            Some(Host::Ipv6(ip)) => ip.into(),
            None => {
                return Err(OutboundError::Refused(format!("{authority} has no host")));
            }
        };
        if addr::is_public(ip) {
            Ok(url)
        } else {
            Err(OutboundError::Refused(format!(
                "{authority} is the non-public address {ip}"
            )))
        }
    }

    /// `GET https://{authority}{path}`, reading the whole (capped) body.
    pub async fn get(
        &self,
        authority: &Authority,
        path: &str,
    ) -> Result<OutboundResponse, OutboundError> {
        let url = self.target(authority, path)?;
        let group = registrable_group(authority.as_str());
        let Some(_target_slot) = self.per_target.try_acquire(group.clone()) else {
            return Err(OutboundError::Busy(group));
        };
        let client = if self.allow_hosts.contains(authority) {
            &self.allowed
        } else {
            &self.strict
        };
        tokio::time::timeout(self.timeout, self.send(client, url))
            .await
            .map_err(|_| OutboundError::Timeout)?
    }

    async fn send(
        &self,
        client: &reqwest::Client,
        url: Url,
    ) -> Result<OutboundResponse, OutboundError> {
        let _slot = self
            .slots
            .acquire()
            .await
            .map_err(|_| OutboundError::Network("client shut down".to_owned()))?;
        let mut res = client
            .get(url)
            .header(header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(classify)?;
        let status = res.status();
        if status.is_redirection() {
            return Err(OutboundError::Redirect(status.as_u16()));
        }
        if res
            .content_length()
            .is_some_and(|n| n > self.max_body as u64)
        {
            return Err(OutboundError::TooLarge(self.max_body));
        }
        let headers = std::mem::take(res.headers_mut());
        let mut body = Vec::new();
        while let Some(chunk) = res.chunk().await.map_err(classify)? {
            if body.len() + chunk.len() > self.max_body {
                return Err(OutboundError::TooLarge(self.max_body));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(OutboundResponse {
            status,
            headers,
            body,
        })
    }
}

/// A policy refusal from the resolver, a timeout, or a network error.
fn classify(e: reqwest::Error) -> OutboundError {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&e);
    while let Some(err) = source {
        if let Some(refused) = err.downcast_ref::<RefusedAddress>() {
            return OutboundError::Refused(refused.to_string());
        }
        source = err.source();
    }
    if e.is_timeout() {
        return OutboundError::Timeout;
    }
    // The full chain: reqwest's own message is often just "error sending
    // request".
    let mut msg = e.to_string();
    let mut source = std::error::Error::source(&e);
    while let Some(err) = source {
        msg.push_str(": ");
        msg.push_str(&err.to_string());
        source = err.source();
    }
    OutboundError::Network(msg)
}

/// rustls with the bundled Mozilla roots plus `extra_roots`, HTTP/1.1.
fn tls_config(extra_roots: &[Vec<u8>]) -> Result<rustls::ClientConfig, BuildError> {
    let mut roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    for der in extra_roots {
        roots
            .add(rustls::pki_types::CertificateDer::from(der.clone()))
            .map_err(|e| BuildError(format!("extra root certificate: {e}")))?;
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| BuildError(e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}
