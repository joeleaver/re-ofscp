//! Runtime configuration, read from the environment.
//!
//! On jkbase the runtime clears the environment, so every variable here is
//! supplied as a project secret (`jkbase secret set KEY=value`).

use std::net::SocketAddr;

use re_ofscp_types::Authority;
use re_ofscp_types::auth::RegistrationMode;

use crate::provider_key::ProviderKey;
use crate::replay::ReplayLimits;

/// Server configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// The public provider domain — the OFSCP authority every signature binds
    /// to (spec §4.4.2). MUST equal the host clients use. Required; a
    /// non-canonical spelling (`Social.Example`, `:443`) is normalised.
    pub domain: Authority,
    /// Address to listen on (`BIND`, default `0.0.0.0:8080`; jkbase routes to `port = 8080`).
    pub bind: SocketAddr,
    /// rhypedb binary-protocol address (`RHYPEDB_ADDR`, default `127.0.0.1:4201`,
    /// where jkbase's managed `[database]` listens inside the app VM).
    pub rhypedb_addr: String,
    /// A request header carrying the client's address, set by a trusted
    /// reverse proxy (`CLIENT_IP_HEADER`, e.g. `x-forwarded-for`; its
    /// **last** entry, the one the proxy appended, is used). Unset: the TCP
    /// peer address. Only set this when every request passes through that
    /// proxy, or clients can choose their own rate-limit key.
    pub client_ip_header: Option<String>,
    /// Who may register (`REGISTRATION`, §4.1.1): `invite` (default) or
    /// `closed`. `open` is refused: this provider's accounts are created by
    /// admins and invitations only (docs/decisions/0004).
    pub registration: RegistrationMode,
    /// Replay-store bounds (spec §4.5):
    /// * `REPLAY_LOCAL_TOTAL` / `REPLAY_REMOTE_TOTAL`: live nonces from local
    ///   and from remote signers (default 250 000 each; full → `503` for that
    ///   side only);
    /// * `REPLAY_PER_SIGNER`: per signer (default 6 000, about 10 signed
    ///   requests/s sustained; over → `429`);
    /// * `REPLAY_PER_REMOTE_DOMAIN`: per remote registrable domain (default
    ///   25 000; over → `429`).
    pub replay: ReplayLimits,
    /// Seals admin TOTP secrets at rest (`ADMIN_SECRET_KEY`: 32 random
    /// bytes, base64). Unset: the admin API is off (docs/decisions/0005).
    pub admin_secret_key: Option<Redacted<[u8; 32]>>,
    /// One-time token for creating the first admin (`ADMIN_SETUP_TOKEN`, at
    /// least 32 characters). Useless once an admin exists; remove it then.
    pub admin_setup_token: Option<Redacted<String>>,
    /// Local development only (`ADMIN_LOOPBACK_HTTP=true`, default off):
    /// the admin console also accepts requests from `http://{DOMAIN}`, so
    /// it can be served without TLS on a developer's machine. Refused
    /// unless `DOMAIN` is `localhost` or a `*.localhost` name, which
    /// always resolve to loopback (RFC 6761 §6.3), so a public deployment
    /// cannot turn it on (docs/decisions/0005).
    pub admin_loopback_http: bool,
    /// Peers the outbound-request address rule does not apply to
    /// (`OUTBOUND_ALLOW_HOSTS`: comma-separated authorities, e.g.
    /// `peer.internal,localhost:8443`; default none). Every other outbound
    /// rule (https only, no redirects, time and size bounds) still applies.
    /// For development and private peerings only: a listed host may be on
    /// loopback or an internal network (spec §8 "Outbound requests",
    /// docs/decisions/0006). Each entry is matched as a whole authority,
    /// port included.
    pub outbound_allow_hosts: Vec<Authority>,
    /// The provider signing key (`PROVIDER_SIGNING_KEY`: a 32-byte Ed25519
    /// seed, base64, e.g. `openssl rand -base64 32`). Required: every
    /// provider publishes one in discovery (§8.1, docs/decisions/0007).
    /// Changing it rotates the key and its id.
    pub provider_key: ProviderKey,
    /// How to reach the operator, published in discovery as
    /// `provider.contact` (`PROVIDER_CONTACT`, e.g. `mailto:ops@example.com`
    /// or an `https:` URL). Default: `mailto:admin@{host}`, the host of
    /// `DOMAIN` without its port.
    pub contact: String,
}

/// A secret configuration value: `Debug` never prints it.
#[derive(Clone, PartialEq, Eq)]
pub struct Redacted<T>(pub T);

impl<T> std::fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Shortest accepted `ADMIN_SETUP_TOKEN`.
pub const MIN_SETUP_TOKEN_LEN: usize = 32;

/// A configuration error.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("missing required environment variable {0}")]
    Missing(&'static str),
    #[error("invalid value for {name}: {reason}")]
    Invalid { name: &'static str, reason: String },
}

impl Config {
    /// Read the configuration from the process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Read the configuration through `get` (testable without touching the real env).
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let domain = get("DOMAIN")
            .filter(|d| !d.trim().is_empty())
            .ok_or(ConfigError::Missing("DOMAIN"))?;
        let domain = Authority::canonicalize(domain.trim()).map_err(|e| ConfigError::Invalid {
            name: "DOMAIN",
            reason: e.to_string(),
        })?;
        let bind = get("BIND")
            .unwrap_or_else(|| "0.0.0.0:8080".to_owned())
            .parse()
            .map_err(|e: std::net::AddrParseError| ConfigError::Invalid {
                name: "BIND",
                reason: e.to_string(),
            })?;
        let rhypedb_addr = get("RHYPEDB_ADDR").unwrap_or_else(|| "127.0.0.1:4201".to_owned());
        let replay = ReplayLimits {
            local_total: positive(&get, "REPLAY_LOCAL_TOTAL", 250_000)?,
            remote_total: positive(&get, "REPLAY_REMOTE_TOTAL", 250_000)?,
            per_signer: positive(&get, "REPLAY_PER_SIGNER", 6_000)?,
            per_remote_domain: positive(&get, "REPLAY_PER_REMOTE_DOMAIN", 25_000)?,
        };
        let client_ip_header = get("CLIENT_IP_HEADER")
            .map(|h| h.trim().to_ascii_lowercase())
            .filter(|h| !h.is_empty());
        if let Some(h) = &client_ip_header
            && axum::http::HeaderName::from_bytes(h.as_bytes()).is_err()
        {
            return Err(ConfigError::Invalid {
                name: "CLIENT_IP_HEADER",
                reason: "not a valid header name".to_owned(),
            });
        }
        let registration = match get("REGISTRATION").as_deref().map(str::trim) {
            None | Some("invite") => RegistrationMode::Invite,
            Some("closed") => RegistrationMode::Closed,
            Some(other) => {
                return Err(ConfigError::Invalid {
                    name: "REGISTRATION",
                    reason: format!(
                        "{other:?} is not supported: use \"invite\" or \"closed\" \
                         (open self-registration is not offered)"
                    ),
                });
            }
        };
        let admin_secret_key = match get("ADMIN_SECRET_KEY").map(|v| v.trim().to_owned()) {
            None => None,
            Some(v) => Some(Redacted(decode_key(&v).ok_or(ConfigError::Invalid {
                name: "ADMIN_SECRET_KEY",
                reason: "must be 32 bytes, base64 (e.g. `openssl rand -base64 32`)".to_owned(),
            })?)),
        };
        let admin_setup_token = match get("ADMIN_SETUP_TOKEN").map(|v| v.trim().to_owned()) {
            None => None,
            Some(v) if v.len() >= MIN_SETUP_TOKEN_LEN => Some(Redacted(v)),
            Some(_) => {
                return Err(ConfigError::Invalid {
                    name: "ADMIN_SETUP_TOKEN",
                    reason: format!("must be at least {MIN_SETUP_TOKEN_LEN} characters"),
                });
            }
        };
        let admin_loopback_http = match get("ADMIN_LOOPBACK_HTTP").as_deref().map(str::trim) {
            None | Some("false") => false,
            Some("true") if is_loopback_name(&domain) => true,
            Some("true") => {
                return Err(ConfigError::Invalid {
                    name: "ADMIN_LOOPBACK_HTTP",
                    reason: "only allowed when DOMAIN is localhost or a *.localhost name"
                        .to_owned(),
                });
            }
            Some(other) => {
                return Err(ConfigError::Invalid {
                    name: "ADMIN_LOOPBACK_HTTP",
                    reason: format!("{other:?} is not \"true\" or \"false\""),
                });
            }
        };
        let outbound_allow_hosts = match get("OUTBOUND_ALLOW_HOSTS") {
            None => Vec::new(),
            Some(v) => v
                .split(',')
                .map(str::trim)
                .filter(|h| !h.is_empty())
                .map(|h| {
                    Authority::canonicalize(h).map_err(|e| ConfigError::Invalid {
                        name: "OUTBOUND_ALLOW_HOSTS",
                        reason: format!("{h:?}: {e}"),
                    })
                })
                .collect::<Result<_, _>>()?,
        };
        let provider_key = match get("PROVIDER_SIGNING_KEY").map(|v| v.trim().to_owned()) {
            None => return Err(ConfigError::Missing("PROVIDER_SIGNING_KEY")),
            Some(v) => ProviderKey::from_seed(
                &decode_key(&v).ok_or(ConfigError::Invalid {
                    name: "PROVIDER_SIGNING_KEY",
                    reason:
                        "must be a 32-byte Ed25519 seed, base64 (e.g. `openssl rand -base64 32`)"
                            .to_owned(),
                })?,
            ),
        };
        let contact = match get("PROVIDER_CONTACT").map(|v| v.trim().to_owned()) {
            None => format!("mailto:admin@{}", host_of(&domain)),
            Some(v) if is_contact_uri(&v) => v,
            Some(_) => {
                return Err(ConfigError::Invalid {
                    name: "PROVIDER_CONTACT",
                    reason: "must be a mailto: or https: URI, e.g. mailto:ops@example.com"
                        .to_owned(),
                });
            }
        };
        Ok(Self {
            domain,
            provider_key,
            contact,
            outbound_allow_hosts,
            admin_secret_key,
            admin_setup_token,
            admin_loopback_http,
            bind,
            rhypedb_addr,
            client_ip_header,
            registration,
            replay,
        })
    }
}

/// Whether `domain`'s host is `localhost` or a `*.localhost` name, which
/// resolvers must answer with loopback addresses (RFC 6761 §6.3).
fn is_loopback_name(domain: &Authority) -> bool {
    let host = host_of(domain);
    host == "localhost" || host.ends_with(".localhost")
}

/// A `mailto:` or `https:` URI (scheme in any case, RFC 3986 §3.1) with
/// something after the scheme and no whitespace or control characters.
fn is_contact_uri(v: &str) -> bool {
    let rest = ["mailto:", "https://"].iter().find_map(|scheme| {
        v.get(..scheme.len())
            .filter(|p| p.eq_ignore_ascii_case(scheme))
            .map(|_| &v[scheme.len()..])
    });
    rest.is_some_and(|r| !r.is_empty()) && !v.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// `domain` without its `:port` (an IPv6 literal keeps its brackets).
fn host_of(domain: &Authority) -> &str {
    let s = domain.as_str();
    if s.starts_with('[') {
        return s.find(']').map_or(s, |end| &s[..=end]);
    }
    s.rsplit_once(':').map_or(s, |(host, _)| host)
}

/// A 32-byte key in standard or URL-safe base64, padded or not.
fn decode_key(v: &str) -> Option<[u8; 32]> {
    use base64::Engine as _;
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
        .iter()
        .find_map(|e| e.decode(v).ok())
        .and_then(|b| b.try_into().ok())
}

/// A positive integer variable, or `default` when unset.
fn positive(
    get: &impl Fn(&str) -> Option<String>,
    name: &'static str,
    default: usize,
) -> Result<usize, ConfigError> {
    match get(name) {
        None => Ok(default),
        Some(v) => v
            .trim()
            .parse::<usize>()
            .ok()
            .filter(|n| *n > 0)
            .ok_or(ConfigError::Invalid {
                name,
                reason: "must be a positive integer".to_owned(),
            }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A test seed (bytes 0..32), base64.
    const SEED: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

    /// `pairs`, plus a valid `PROVIDER_SIGNING_KEY` unless `pairs` sets one.
    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let pairs: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |k| match pairs.iter().find(|(pk, _)| pk == k) {
            Some((_, v)) => Some(v.clone()),
            None if k == "PROVIDER_SIGNING_KEY" => Some(SEED.to_owned()),
            None => None,
        }
    }

    #[test]
    fn provider_signing_key_is_required_and_validated() {
        let only_domain = |k: &str| (k == "DOMAIN").then(|| "a.example".to_owned());
        assert!(matches!(
            Config::from_lookup(only_domain),
            Err(ConfigError::Missing("PROVIDER_SIGNING_KEY"))
        ));
        for bad in ["", "c2hvcnQ=", "not base64!"] {
            let r = Config::from_lookup(env(&[
                ("DOMAIN", "a.example"),
                ("PROVIDER_SIGNING_KEY", bad),
            ]));
            assert!(matches!(
                r,
                Err(ConfigError::Invalid {
                    name: "PROVIDER_SIGNING_KEY",
                    ..
                })
            ));
        }
        let c = Config::from_lookup(env(&[("DOMAIN", "a.example")])).unwrap();
        let expected = ProviderKey::from_seed(&std::array::from_fn(|i| i as u8));
        assert_eq!(c.provider_key.key_id(), expected.key_id());
        // Debug output names the key id, never the seed.
        assert!(!format!("{c:?}").contains(SEED));
    }

    #[test]
    fn contact_defaults_to_the_domain_host_and_is_validated() {
        let contact = |domain: &str, v: Option<&str>| {
            let mut pairs = vec![("DOMAIN", domain)];
            if let Some(v) = v {
                pairs.push(("PROVIDER_CONTACT", v));
            }
            Config::from_lookup(env(&pairs)).map(|c| c.contact)
        };
        assert_eq!(
            contact("a.example", None).unwrap(),
            "mailto:admin@a.example"
        );
        assert_eq!(
            contact("a.example:8443", None).unwrap(),
            "mailto:admin@a.example"
        );
        assert_eq!(
            contact("a.example", Some(" https://a.example/about ")).unwrap(),
            "https://a.example/about"
        );
        assert_eq!(
            contact("a.example", Some("MAILTO:ops@a.example")).unwrap(),
            "MAILTO:ops@a.example"
        );
        for bad in [
            "",
            "  ",
            "mailto:a@b\nX: y",
            "foo bar",
            "ops@example.com",
            "http://a.example",
            "mailto:",
            "https://",
        ] {
            assert!(matches!(
                contact("a.example", Some(bad)),
                Err(ConfigError::Invalid {
                    name: "PROVIDER_CONTACT",
                    ..
                })
            ));
        }
    }

    #[test]
    fn domain_is_required() {
        assert!(matches!(
            Config::from_lookup(env(&[])),
            Err(ConfigError::Missing("DOMAIN"))
        ));
    }

    #[test]
    fn defaults_and_normalisation() {
        let c = Config::from_lookup(env(&[("DOMAIN", " Social.Example ")])).unwrap();
        assert_eq!(c.domain.as_str(), "social.example");
        assert_eq!(
            c.replay,
            ReplayLimits {
                local_total: 250_000,
                remote_total: 250_000,
                per_signer: 6_000,
                per_remote_domain: 25_000,
            }
        );
        assert_eq!(c.bind.to_string(), "0.0.0.0:8080");
        assert_eq!(c.rhypedb_addr, "127.0.0.1:4201");
        assert_eq!(c.registration, RegistrationMode::Invite);
    }

    #[test]
    fn registration_mode_is_invite_or_closed() {
        let mode = |v: &str| {
            Config::from_lookup(env(&[("DOMAIN", "a.example"), ("REGISTRATION", v)]))
                .map(|c| c.registration)
        };
        assert_eq!(mode("closed").unwrap(), RegistrationMode::Closed);
        assert_eq!(mode(" invite ").unwrap(), RegistrationMode::Invite);
        for bad in ["open", "Invite", ""] {
            assert!(matches!(
                mode(bad),
                Err(ConfigError::Invalid {
                    name: "REGISTRATION",
                    ..
                })
            ));
        }
    }

    #[test]
    fn bad_domain_and_capacity_are_rejected() {
        let r = Config::from_lookup(env(&[("DOMAIN", "not a host")]));
        assert!(matches!(
            r,
            Err(ConfigError::Invalid { name: "DOMAIN", .. })
        ));
        let r = Config::from_lookup(env(&[("DOMAIN", "a.example"), ("REPLAY_PER_SIGNER", "0")]));
        assert!(matches!(
            r,
            Err(ConfigError::Invalid {
                name: "REPLAY_PER_SIGNER",
                ..
            })
        ));
    }

    #[test]
    fn admin_secrets_are_validated_and_never_printed() {
        let key = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
        let c = Config::from_lookup(env(&[
            ("DOMAIN", "a.example"),
            ("ADMIN_SECRET_KEY", key),
            ("ADMIN_SETUP_TOKEN", &"t".repeat(32)),
        ]))
        .unwrap();
        let k = c.admin_secret_key.clone().unwrap().0;
        assert_eq!(k[1], 1);
        assert_eq!(k[31], 31);
        let printed = format!("{c:?}");
        assert!(!printed.contains(key) && !printed.contains(&"t".repeat(32)));
        let defaults = Config::from_lookup(env(&[("DOMAIN", "a.example")])).unwrap();
        assert!(defaults.admin_secret_key.is_none() && defaults.admin_setup_token.is_none());
        for (name, value) in [
            ("ADMIN_SECRET_KEY", "c2hvcnQ="),
            ("ADMIN_SECRET_KEY", "not base64!"),
            ("ADMIN_SETUP_TOKEN", "short"),
        ] {
            let r = Config::from_lookup(env(&[("DOMAIN", "a.example"), (name, value)]));
            assert!(
                matches!(r, Err(ConfigError::Invalid { name: n, .. }) if n == name),
                "{name}={value}"
            );
        }
    }

    #[test]
    fn loopback_http_is_off_by_default_and_only_for_localhost() {
        let lookup = |domain: &str, flag: Option<&str>| {
            let mut pairs = vec![("DOMAIN", domain)];
            if let Some(f) = flag {
                pairs.push(("ADMIN_LOOPBACK_HTTP", f));
            }
            Config::from_lookup(env(&pairs)).map(|c| c.admin_loopback_http)
        };
        assert!(!lookup("localhost:8090", None).unwrap());
        assert!(!lookup("localhost:8090", Some("false")).unwrap());
        assert!(lookup("localhost:8090", Some("true")).unwrap());
        assert!(lookup("admin.localhost", Some(" true ")).unwrap());
        for (domain, flag) in [
            ("social.example", "true"),
            ("localhost.example", "true"),
            ("notlocalhost:8090", "true"),
            ("localhost:8090", "yes"),
            ("localhost:8090", "1"),
        ] {
            assert!(
                matches!(
                    lookup(domain, Some(flag)),
                    Err(ConfigError::Invalid {
                        name: "ADMIN_LOOPBACK_HTTP",
                        ..
                    })
                ),
                "{domain} {flag}"
            );
        }
    }

    #[test]
    fn outbound_allow_hosts_are_canonical_authorities() {
        let hosts = |v: Option<&str>| {
            let mut pairs = vec![("DOMAIN", "a.example")];
            if let Some(v) = v {
                pairs.push(("OUTBOUND_ALLOW_HOSTS", v));
            }
            Config::from_lookup(env(&pairs)).map(|c| {
                c.outbound_allow_hosts
                    .iter()
                    .map(|a| a.as_str().to_owned())
                    .collect::<Vec<_>>()
            })
        };
        assert!(hosts(None).unwrap().is_empty());
        assert!(hosts(Some("")).unwrap().is_empty());
        assert_eq!(
            hosts(Some(" Peer.Internal , localhost:8443,,b.example:443 ")).unwrap(),
            ["peer.internal", "localhost:8443", "b.example"]
        );
        for bad in [
            "http://peer.internal",
            "peer internal",
            "a.example:0x50",
            "[::1]:8443",
        ] {
            assert!(
                matches!(
                    hosts(Some(bad)),
                    Err(ConfigError::Invalid {
                        name: "OUTBOUND_ALLOW_HOSTS",
                        ..
                    })
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn bad_bind_is_rejected() {
        let r = Config::from_lookup(env(&[("DOMAIN", "a.example"), ("BIND", "nope")]));
        assert!(matches!(r, Err(ConfigError::Invalid { name: "BIND", .. })));
    }
}
