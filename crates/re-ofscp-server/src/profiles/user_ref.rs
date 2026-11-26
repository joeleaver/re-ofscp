//! Resolving a `{userRef}` path segment (§2.2) to a user this provider
//! hosts.
//!
//! A `{userRef}` is a bare handle (a local user), an actor `handle@domain`,
//! or a user object URI `https://{domain}/api/users/{handle}`. The router
//! has already percent-decoded the segment exactly once. Only users of this
//! provider can be resolved: an actor or URI naming another provider is
//! not ours to answer for (security requirement 1: `alice@b.com` is never
//! local `alice`).

use re_ofscp_types::{Actor, Authority, is_valid_handle};

/// The local handle `user_ref` names on `home`, or `None` if it is
/// malformed or names a user of another provider.
pub fn local_handle(user_ref: &str, home: &Authority) -> Option<String> {
    if is_valid_handle(user_ref) {
        return Some(user_ref.to_owned());
    }
    if user_ref.starts_with("https://") {
        return from_uri(user_ref, home);
    }
    // §2.2: a receiver may convert a non-canonical spelling of the domain
    // before comparing.
    let actor = Actor::canonicalize(user_ref).ok()?;
    actor.is_local_to(home).then(|| actor.handle().to_owned())
}

/// The handle in a user object URI on `home`: exactly
/// `https://{home}/api/users/{handle}`, with no query, fragment, user info
/// or trailing segments.
fn from_uri(uri: &str, home: &Authority) -> Option<String> {
    let url = url::Url::parse(uri).ok()?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    let authority = match url.port() {
        Some(port) => format!("{}:{port}", url.host_str()?),
        None => url.host_str()?.to_owned(),
    };
    if Authority::canonicalize(&authority).ok()? != *home {
        return None;
    }
    let handle = url.path().strip_prefix("/api/users/")?;
    is_valid_handle(handle).then(|| handle.to_owned())
}

/// The object URI of local user `handle` (§2.2).
pub fn user_uri(handle: &str, home: &Authority) -> String {
    format!("https://{home}/api/users/{handle}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home() -> Authority {
        Authority::parse_canonical("a.com").unwrap()
    }

    #[test]
    fn local_forms_resolve() {
        for r in [
            "jane",
            "jane@a.com",
            "jane@A.COM",
            "jane@a.com.",
            "jane@a.com:443",
            "https://a.com/api/users/jane",
            "https://A.com:443/api/users/jane",
        ] {
            assert_eq!(local_handle(r, &home()).as_deref(), Some("jane"), "{r}");
        }
    }

    #[test]
    fn remote_users_never_become_local() {
        for r in [
            "jane@b.com",
            "jane@a.com:8443",
            "https://b.com/api/users/jane",
            "https://a.com:8443/api/users/jane",
        ] {
            assert_eq!(local_handle(r, &home()), None, "{r}");
        }
    }

    #[test]
    fn malformed_refs_resolve_to_nothing() {
        for r in [
            "",
            "Jane",
            "ja",
            "jane@",
            "@a.com",
            "Jane@a.com",
            "http://a.com/api/users/jane",
            "https://a.com/api/users/jane/",
            "https://a.com/api/users/jane?x=1",
            "https://a.com/api/users/jane#f",
            "https://u@a.com/api/users/jane",
            "https://a.com/api/users/Jane",
            "https://a.com/api/groups/jane",
            "https://a.com/api/users/a/b",
        ] {
            assert_eq!(local_handle(r, &home()), None, "{r:?}");
        }
    }

    #[test]
    fn uris_with_a_port_keep_it() {
        let home = Authority::parse_canonical("localhost:8443").unwrap();
        assert_eq!(
            local_handle("https://localhost:8443/api/users/jane", &home).as_deref(),
            Some("jane")
        );
        assert_eq!(
            local_handle("https://localhost/api/users/jane", &home),
            None
        );
        assert_eq!(
            user_uri("jane", &home),
            "https://localhost:8443/api/users/jane"
        );
    }
}
