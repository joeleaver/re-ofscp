//! Local ids, object URIs and refs: the other two identifier forms of §2.2
//! (actors and authorities are in [`crate::actor`]).

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{Authority, IdentError};

/// An object's id on the provider that hosts it (§2.2): opaque, path-safe,
/// meaningful only together with that provider.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LocalId(String);

impl LocalId {
    /// Accept `s` if it matches `^[A-Za-z0-9_-]{1,128}$`.
    pub fn new(s: &str) -> Result<Self, IdentError> {
        if is_local_id(s) {
            Ok(Self(s.to_owned()))
        } else {
            Err(IdentError::LocalId)
        }
    }

    /// The id as sent.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn is_local_id(s: &str) -> bool {
    (1..=128).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

impl fmt::Display for LocalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An absolute HTTPS URL naming an object across providers (§2.2), such as
/// `https://a.example/api/groups/grp_1`. Its authority is canonical; the
/// rest (path, query, fragment) is kept exactly as received, and may hold
/// only RFC 3986 URI characters (no spaces, controls or non-ASCII).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjectUri {
    authority: Authority,
    path: String,
}

impl ObjectUri {
    /// Parse `https://{authority}{path}` whose authority is already
    /// canonical (the serde default). A non-canonical authority is refused.
    pub fn parse(s: &str) -> Result<Self, IdentError> {
        Self::parse_with(s, Authority::parse_canonical)
    }

    /// Parse `https://{authority}{path}`, converting the authority to its
    /// canonical form where §2.2 allows a receiver to convert.
    pub fn canonicalize(s: &str) -> Result<Self, IdentError> {
        Self::parse_with(s, Authority::canonicalize)
    }

    fn parse_with(
        s: &str,
        authority: fn(&str) -> Result<Authority, IdentError>,
    ) -> Result<Self, IdentError> {
        let rest = s.strip_prefix("https://").ok_or(IdentError::ObjectUri)?;
        let (raw_authority, path) = match rest.find(['/', '?', '#']) {
            Some(i) => rest.split_at(i),
            None => (rest, ""),
        };
        if !is_uri_rest(path) {
            return Err(IdentError::ObjectUri);
        }
        let authority = authority(raw_authority).map_err(|e| match e {
            IdentError::NotCanonical => IdentError::NotCanonical,
            _ => IdentError::ObjectUri,
        })?;
        Ok(Self {
            authority,
            path: path.to_owned(),
        })
    }

    /// The provider that hosts the object.
    pub fn authority(&self) -> &Authority {
        &self.authority
    }

    /// Everything after the authority, as received (may be empty).
    pub fn path(&self) -> &str {
        &self.path
    }
}

/// Whether `rest` (path, query and fragment) uses only RFC 3986 characters:
/// unreserved, sub-delims, `:` `@` `/` `?` `#`, and `%` followed by two hex
/// digits.
fn is_uri_rest(rest: &str) -> bool {
    let bytes = rest.as_bytes();
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        if b == b'%' {
            let hex = |j: usize| bytes.get(j).is_some_and(u8::is_ascii_hexdigit);
            if !(hex(i + 1) && hex(i + 2)) {
                return false;
            }
            i += 3;
            continue;
        }
        let allowed = b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@/?#".contains(&b);
        if !allowed {
            return false;
        }
        i += 1;
    }
    true
}

impl fmt::Display for ObjectUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "https://{}{}", self.authority, self.path)
    }
}

/// A field documented as a *ref* (§2.2): a local id on the provider that
/// receives it, or an object URI. The two never overlap, since a local id
/// cannot contain `:` or `/`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ObjectRef {
    /// An object on the provider receiving the request.
    Local(LocalId),
    /// An object named across providers.
    Uri(ObjectUri),
}

impl ObjectRef {
    /// Parse a ref; a URI's authority must be canonical (see
    /// [`ObjectUri::parse`]).
    pub fn parse(s: &str) -> Result<Self, IdentError> {
        if is_local_id(s) {
            Ok(Self::Local(LocalId(s.to_owned())))
        } else {
            ObjectUri::parse(s).map(Self::Uri)
        }
    }
}

impl fmt::Display for ObjectRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local(id) => id.fmt(f),
            Self::Uri(uri) => uri.fmt(f),
        }
    }
}

/// Serialize as the display string; deserialize through the named parser.
macro_rules! string_serde {
    ($ty:ty, $parse:path) => {
        impl Serialize for $ty {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                $parse(&s).map_err(serde::de::Error::custom)
            }
        }
    };
}

string_serde!(LocalId, LocalId::new);
string_serde!(ObjectUri, ObjectUri::parse);
string_serde!(ObjectRef, ObjectRef::parse);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_ids() {
        for ok in ["grp_1", "A-z_09", &"x".repeat(128)] {
            assert_eq!(LocalId::new(ok).unwrap().as_str(), ok);
        }
        for bad in ["", "a/b", "a b", "a.b", "a%2F", &"x".repeat(129)] {
            assert_eq!(LocalId::new(bad), Err(IdentError::LocalId), "{bad}");
        }
        assert!(serde_json::from_str::<LocalId>("\"../etc\"").is_err());
    }

    #[test]
    fn object_uris() {
        let uri = ObjectUri::canonicalize("https://A.example:443/api/groups/grp_1").unwrap();
        assert_eq!(
            ObjectUri::parse("https://A.example/x"),
            Err(IdentError::NotCanonical),
            "parse is strict"
        );
        assert!(ObjectUri::parse("https://a.example/x%2Fy?q=1#f").is_ok());
        for bad in [
            "https://a.example/%zz",
            "https://a.example/%2",
            "https://a.example/é",
        ] {
            assert_eq!(ObjectUri::parse(bad), Err(IdentError::ObjectUri), "{bad}");
        }
        assert_eq!(uri.authority().as_str(), "a.example");
        assert_eq!(uri.path(), "/api/groups/grp_1");
        assert_eq!(uri.to_string(), "https://a.example/api/groups/grp_1");

        let bare = ObjectUri::parse("https://a.example:8443").unwrap();
        assert_eq!(bare.to_string(), "https://a.example:8443");

        for bad in [
            "http://a.example/x",
            "https://",
            "https:///x",
            "a.example/x",
            "https://bad_host/x",
        ] {
            assert_eq!(ObjectUri::parse(bad), Err(IdentError::ObjectUri), "{bad}");
        }
    }

    #[test]
    fn refs_are_local_ids_or_uris() {
        assert_eq!(
            ObjectRef::parse("chn_general").unwrap(),
            ObjectRef::Local(LocalId::new("chn_general").unwrap())
        );
        let uri = "https://b.example/api/groups/grp_2/channels/chn_9";
        match ObjectRef::parse(uri).unwrap() {
            ObjectRef::Uri(u) => assert_eq!(u.to_string(), uri),
            other => panic!("expected a URI, got {other:?}"),
        }
        assert!(ObjectRef::parse("not a ref").is_err());
    }

    #[test]
    fn serde_round_trips() {
        let uri: ObjectUri = serde_json::from_str("\"https://a.example/x\"").unwrap();
        assert_eq!(
            serde_json::to_string(&uri).unwrap(),
            "\"https://a.example/x\""
        );
        let r: ObjectRef = serde_json::from_str("\"msg_1\"").unwrap();
        assert_eq!(serde_json::to_string(&r).unwrap(), "\"msg_1\"");
        let a: Authority = serde_json::from_str("\"a.example\"").unwrap();
        assert_eq!(serde_json::to_string(&a).unwrap(), "\"a.example\"");
        // A path character outside RFC 3986 is refused (a space, an LF).
        for bad in ["\"https://a.example/a b\"", "\"https://a.example/a\\nb\""] {
            assert!(serde_json::from_str::<ObjectUri>(bad).is_err(), "{bad}");
        }
    }
}
