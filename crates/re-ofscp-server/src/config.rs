//! Runtime configuration, read from the environment.
//!
//! On jkbase the runtime clears the environment, so every variable here is
//! supplied as a project secret (`jkbase secret set KEY=value`).

use std::net::SocketAddr;

use re_ofscp_types::Authority;
use re_ofscp_types::auth::RegistrationMode;

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
}

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
        Ok(Self {
            domain,
            bind,
            rhypedb_addr,
            client_ip_header,
            registration,
            replay,
        })
    }
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

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let pairs: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |k| pairs.iter().find(|(pk, _)| pk == k).map(|(_, v)| v.clone())
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
    fn bad_bind_is_rejected() {
        let r = Config::from_lookup(env(&[("DOMAIN", "a.example"), ("BIND", "nope")]));
        assert!(matches!(r, Err(ConfigError::Invalid { name: "BIND", .. })));
    }
}
