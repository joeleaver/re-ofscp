//! Resolving a `{userRef}` path segment (§2.2).
//!
//! A `{userRef}` is a bare handle (a local user), an actor `handle@domain`,
//! or a user object URI `https://{domain}/api/users/{handle}`. The router
//! has already percent-decoded the segment exactly once.
//!
//! [`resolve_actor`] names any user, local or remote, by their full actor
//! (the group member routes, §5.7, where remote members are members like
//! any other). [`local_handle`] resolves only users of this provider: an
//! actor or URI naming another provider is not ours to answer for
//! (security requirement 1: `alice@b.com` is never local `alice`).

use re_ofscp_types::{Actor, Authority, is_valid_handle};

/// The actor `user_ref` names, a bare handle being a user of `home`, or
/// `None` if it is malformed.
pub fn resolve_actor(user_ref: &str, home: &Authority) -> Option<Actor> {
    if is_valid_handle(user_ref) {
        return Actor::new(user_ref, home.clone()).ok();
    }
    if user_ref.starts_with("https://") {
        return from_uri(user_ref);
    }
    // §2.2: a receiver may convert a non-canonical spelling of the domain
    // before comparing.
    Actor::canonicalize(user_ref).ok()
}

/// The local handle `user_ref` names on `home`, or `None` if it is
/// malformed or names a user of another provider.
pub fn local_handle(user_ref: &str, home: &Authority) -> Option<String> {
    let actor = resolve_actor(user_ref, home)?;
    actor.is_local_to(home).then(|| actor.handle().to_owned())
}

/// The user a user object URI names: exactly
/// `https://{authority}/api/users/{handle}`, with no query, fragment, user
/// info or trailing segments.
fn from_uri(uri: &str) -> Option<Actor> {
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
    let handle = url.path().strip_prefix("/api/users/")?;
    if !is_valid_handle(handle) {
        return None;
    }
    Actor::new(handle, Authority::canonicalize(&authority).ok()?).ok()
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
    fn any_user_resolves_to_their_full_actor() {
        let actor = |s: &str| Actor::parse_canonical(s).unwrap();
        for (r, want) in [
            ("jane", "jane@a.com"),
            ("jane@a.com", "jane@a.com"),
            ("jane@B.com", "jane@b.com"),
            ("jane@b.com:8443", "jane@b.com:8443"),
            ("https://b.com/api/users/jane", "jane@b.com"),
            ("https://b.com:443/api/users/jane", "jane@b.com"),
        ] {
            assert_eq!(resolve_actor(r, &home()), Some(actor(want)), "{r}");
        }
        for r in [
            "",
            "Jane",
            "jane@",
            "https://b.com/api/users/jane/",
            "http://b.com/api/users/jane",
        ] {
            assert_eq!(resolve_actor(r, &home()), None, "{r:?}");
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
