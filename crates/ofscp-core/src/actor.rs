//! Actor identifiers (`handle@domain`) and provider authorities (spec §2.2).
//!
//! An actor is the pair *(handle, domain)*. It is never reduced to a bare
//! handle for any lookup, authorization or storage decision
//! (lost-conn/ofscp#10): `alice@remote.example` and a local `alice` are two
//! different people.
//!
//! Two parsers are offered, matching the two choices §2.2 gives a receiver:
//!
//! * [`Actor::parse_canonical`] / [`Authority::parse_canonical`] **reject**
//!   any spelling that is not already canonical. Use these for signed headers
//!   (`X-OFSCP-Actor`, `X-OFSCP-Provider`), the WebSocket `authenticate` actor,
//!   and every field the spec says MUST be canonical.
//! * [`Actor::canonicalize`] / [`Authority::canonicalize`] **convert** a
//!   recognisable spelling (upper case, trailing dot, explicit `:443`) to its
//!   canonical form, for body fields where conversion is allowed.
//!
//! Internationalized domain names are accepted only in their ASCII (`xn--`)
//! form; a Unicode spelling is rejected rather than converted, which §2.2
//! permits and which keeps IDNA tables out of this crate.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Why an identifier was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IdentError {
    /// The handle does not match `^[a-z0-9_-]{3,32}$` (§2.2.1).
    #[error("handle must match ^[a-z0-9_-]{{3,32}}$")]
    Handle,
    /// The value has no `@` separating handle and domain.
    #[error("actor must have the form handle@domain")]
    MissingAt,
    /// The authority is malformed (bad label, bad port, non-ASCII, …).
    #[error("malformed provider authority")]
    Authority,
    /// The value is well-formed but not in canonical form.
    #[error("identifier is not in canonical form")]
    NotCanonical,
}

/// Whether `handle` matches `^[a-z0-9_-]{3,32}$` (§2.2.1).
pub fn is_valid_handle(handle: &str) -> bool {
    (3..=32).contains(&handle.len())
        && handle
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// A provider authority in canonical form: lowercase host, no trailing dot,
/// `:port` only when the port is not 443 (§2.2, §4.4.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Authority(String);

impl Authority {
    /// Accept `s` only if it is already canonical.
    pub fn parse_canonical(s: &str) -> Result<Self, IdentError> {
        let canonical = Self::canonicalize(s)?;
        if canonical.0 == s {
            Ok(canonical)
        } else {
            Err(IdentError::NotCanonical)
        }
    }

    /// Convert a recognisable spelling of an authority to canonical form.
    pub fn canonicalize(s: &str) -> Result<Self, IdentError> {
        if s.is_empty() || !s.is_ascii() {
            return Err(IdentError::Authority);
        }
        let lower = s.to_ascii_lowercase();
        let (host, port) = match lower.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (lower.as_str(), None),
        };
        let host = host.strip_suffix('.').unwrap_or(host);
        if !is_valid_hostname(host) {
            return Err(IdentError::Authority);
        }
        match port {
            None => Ok(Self(host.to_owned())),
            Some(port) => {
                // Digits only, no sign, no leading zero, within u16.
                let n: u16 = if !port.is_empty()
                    && port.bytes().all(|b| b.is_ascii_digit())
                    && !port.starts_with('0')
                {
                    port.parse().map_err(|_| IdentError::Authority)?
                } else {
                    return Err(IdentError::Authority);
                };
                if n == 443 {
                    Ok(Self(host.to_owned()))
                } else {
                    Ok(Self(format!("{host}:{n}")))
                }
            }
        }
    }

    /// The canonical spelling.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Authority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Dotted DNS name of LDH labels (1–63 bytes, no leading/trailing hyphen),
/// at most 253 bytes. IP-literal hosts in brackets are not accepted.
fn is_valid_hostname(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// A user anywhere in the network: `handle@domain` (§2.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Actor {
    handle: String,
    domain: Authority,
}

impl Actor {
    /// Build an actor from an already-validated handle and authority.
    pub fn new(handle: &str, domain: Authority) -> Result<Self, IdentError> {
        if !is_valid_handle(handle) {
            return Err(IdentError::Handle);
        }
        Ok(Self {
            handle: handle.to_owned(),
            domain,
        })
    }

    /// Accept `s` only if it is already a canonical actor.
    pub fn parse_canonical(s: &str) -> Result<Self, IdentError> {
        let (handle, domain) = s.split_once('@').ok_or(IdentError::MissingAt)?;
        Self::new(handle, Authority::parse_canonical(domain)?)
    }

    /// Convert a recognisable spelling to a canonical actor. Only the domain
    /// is normalised: a handle that is not already valid is refused, never
    /// lowercased (§2.2.1).
    pub fn canonicalize(s: &str) -> Result<Self, IdentError> {
        let (handle, domain) = s.split_once('@').ok_or(IdentError::MissingAt)?;
        Self::new(handle, Authority::canonicalize(domain)?)
    }

    /// The handle part.
    pub fn handle(&self) -> &str {
        &self.handle
    }

    /// The home-provider authority.
    pub fn domain(&self) -> &Authority {
        &self.domain
    }

    /// Whether this actor's home provider is `authority`.
    pub fn is_local_to(&self, authority: &Authority) -> bool {
        &self.domain == authority
    }
}

impl fmt::Display for Actor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.handle, self.domain)
    }
}

impl Serialize for Actor {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

/// Deserialising converts to canonical form (§2.2 allows either rejecting or
/// converting body fields). Fields the spec says MUST be canonical should be
/// checked with [`Actor::parse_canonical`] instead.
impl<'de> Deserialize<'de> for Actor {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::canonicalize(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles() {
        assert!(is_valid_handle("alice"));
        assert!(is_valid_handle("a_b-9"));
        assert!(!is_valid_handle("al"));
        assert!(!is_valid_handle("Alice"));
        assert!(!is_valid_handle(&"a".repeat(33)));
        assert!(!is_valid_handle("al.ice"));
    }

    #[test]
    fn canonical_authorities() {
        for ok in [
            "providera.com",
            "localhost:8080",
            "xn--bcher-kva.example",
            "a.b-c.d",
        ] {
            assert_eq!(Authority::parse_canonical(ok).unwrap().as_str(), ok);
        }
        for (input, want) in [
            ("ProviderA.com", "providera.com"),
            ("providera.com.", "providera.com"),
            ("providera.com:443", "providera.com"),
            ("PROVIDERA.COM.:443", "providera.com"),
        ] {
            assert_eq!(
                Authority::parse_canonical(input),
                Err(IdentError::NotCanonical)
            );
            assert_eq!(Authority::canonicalize(input).unwrap().as_str(), want);
        }
        for bad in [
            "",
            "bücher.example",
            "a..b",
            "-a.com",
            "a-.com",
            "a.com:",
            "a.com:08080",
            "a.com:99999",
            "a.com:+80",
            "[::1]:8080",
            "a_b.com",
            "a.com/x",
        ] {
            assert_eq!(
                Authority::canonicalize(bad),
                Err(IdentError::Authority),
                "{bad}"
            );
        }
    }

    #[test]
    fn actors() {
        let a = Actor::parse_canonical("alice@providera.com").unwrap();
        assert_eq!(a.handle(), "alice");
        assert_eq!(a.domain().as_str(), "providera.com");
        assert_eq!(a.to_string(), "alice@providera.com");

        assert_eq!(
            Actor::parse_canonical("alice@ProviderA.com"),
            Err(IdentError::NotCanonical)
        );
        assert_eq!(Actor::canonicalize("alice@ProviderA.com:443").unwrap(), a);
        // A handle is never lowercased (§2.2.1).
        assert_eq!(
            Actor::canonicalize("Alice@providera.com"),
            Err(IdentError::Handle)
        );
        assert_eq!(Actor::parse_canonical("alice"), Err(IdentError::MissingAt));
        assert_eq!(
            Actor::parse_canonical("alice@bob@x.com"),
            Err(IdentError::Authority)
        );
    }

    #[test]
    fn same_handle_on_two_providers_is_two_actors() {
        let local = Actor::parse_canonical("alice@a.example").unwrap();
        let remote = Actor::parse_canonical("alice@b.example").unwrap();
        assert_ne!(local, remote);
        let home = Authority::parse_canonical("a.example").unwrap();
        assert!(local.is_local_to(&home));
        assert!(!remote.is_local_to(&home));
    }

    #[test]
    fn error_messages() {
        assert_eq!(
            IdentError::Handle.to_string(),
            "handle must match ^[a-z0-9_-]{3,32}$"
        );
        assert_eq!(
            IdentError::NotCanonical.to_string(),
            "identifier is not in canonical form"
        );
    }

    #[test]
    fn serde_round_trip_canonicalizes() {
        let a: Actor = serde_json::from_str("\"bob@B.Example.\"").unwrap();
        assert_eq!(serde_json::to_string(&a).unwrap(), "\"bob@b.example\"");
    }
}
