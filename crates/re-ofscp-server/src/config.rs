//! Runtime configuration, read from the environment.
//!
//! On jkbase the runtime clears the environment, so every variable here is
//! supplied as a project secret (`jkbase secret set KEY=value`).

use std::net::SocketAddr;

use re_ofscp_types::Authority;

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
    /// Replay-store bounds (spec §4.5): `REPLAY_CAPACITY` (total live nonces,
    /// default 500 000; full → `503`), `REPLAY_PER_SIGNER` (default 6 000,
    /// about 10 signed requests/s sustained; over → `429`) and
    /// `REPLAY_PER_REMOTE_DOMAIN` (default 50 000; over → `429`).
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
            capacity: positive(&get, "REPLAY_CAPACITY", 500_000)?,
            per_signer: positive(&get, "REPLAY_PER_SIGNER", 6_000)?,
            per_remote_domain: positive(&get, "REPLAY_PER_REMOTE_DOMAIN", 50_000)?,
        };
        Ok(Self {
            domain,
            bind,
            rhypedb_addr,
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
                capacity: 500_000,
                per_signer: 6_000,
                per_remote_domain: 50_000,
            }
        );
        assert_eq!(c.bind.to_string(), "0.0.0.0:8080");
        assert_eq!(c.rhypedb_addr, "127.0.0.1:4201");
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
