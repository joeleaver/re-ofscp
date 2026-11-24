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
    /// Seals admin TOTP secrets at rest (`ADMIN_SECRET_KEY`: 32 random
    /// bytes, base64). Unset: the admin API is off (docs/decisions/0005).
    pub admin_secret_key: Option<Redacted<[u8; 32]>>,
    /// One-time token for creating the first admin (`ADMIN_SETUP_TOKEN`, at
    /// least 32 characters). Useless once an admin exists; remove it then.
    pub admin_setup_token: Option<Redacted<String>>,
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
        Ok(Self {
            domain,
            admin_secret_key,
            admin_setup_token,
            bind,
            rhypedb_addr,
            client_ip_header,
            registration,
            replay,
        })
    }
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
    fn bad_bind_is_rejected() {
        let r = Config::from_lookup(env(&[("DOMAIN", "a.example"), ("BIND", "nope")]));
        assert!(matches!(r, Err(ConfigError::Invalid { name: "BIND", .. })));
    }
}
