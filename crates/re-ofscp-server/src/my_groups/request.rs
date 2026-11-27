//! Reading a `PUT`/`DELETE /api/me/groups/{groupRef}` request (spec §5.7,
//! *My groups*; §2.2): the `{groupRef}` path segment and the optional
//! `{ "role" }` body. Every check here answers `400` and records nothing.

use re_ofscp_types::Authority;
use re_ofscp_types::wire::GroupPointerRequest;

use crate::groups::validate::MAX_IDENT_CHARS;
use ofscp_core::{LocalId, ObjectUri};

/// A `{groupRef}` that names a group: `https://{authority}/api/groups/{id}`,
/// with the authority converted to canonical form (§2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRef {
    /// The group's provider, canonical.
    pub authority: Authority,
    /// The group's local id on that provider.
    pub group_id: String,
}

impl GroupRef {
    /// The canonical object URI.
    pub fn uri(&self) -> String {
        group_uri(&self.authority, &self.group_id)
    }
}

/// The object URI of group `group_id` on `authority` (§2.2).
pub fn group_uri(authority: &Authority, group_id: &str) -> String {
    format!("https://{authority}/api/groups/{group_id}")
}

/// Why a request was refused with `400`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invalid(pub String);

/// Read `{groupRef}`, which the router has percent-decoded exactly once.
///
/// It must be a group object URI and nothing else: `https`, an authority
/// that has a canonical form, then exactly `/api/groups/{id}` with a valid
/// local id. A query, a fragment, user info, a trailing slash or further
/// segments are refused, as is a local id on its own (a pointer names a
/// group across providers).
pub fn group_ref(raw: &str) -> Result<GroupRef, Invalid> {
    let not_a_group = || {
        Invalid(
            "`groupRef` must be a group object URI, https://{authority}/api/groups/{groupId}"
                .to_owned(),
        )
    };
    let uri = ObjectUri::canonicalize(raw).map_err(|_| not_a_group())?;
    let id = uri
        .path()
        .strip_prefix("/api/groups/")
        .ok_or_else(not_a_group)?;
    let id = LocalId::new(id).map_err(|_| not_a_group())?;
    Ok(GroupRef {
        authority: uri.authority().clone(),
        group_id: id.as_str().to_owned(),
    })
}

/// Read the optional body: empty, or `{ "role": "<role>" }`. A body that
/// is not a JSON object, or a `role` that is not a string, is refused; so
/// is a role no group could define (empty, longer than a role name may be,
/// or holding whitespace or controls, as `groups::validate` rules for role
/// names).
pub fn role_hint(body: &[u8]) -> Result<Option<String>, Invalid> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(None);
    }
    let shape = |e: serde_json::Error| {
        Invalid(format!(
            "the body must be {{\"role\": \"<role>\"}} with a string role: {e}"
        ))
    };
    // An object only: serde would also read a struct from a JSON array.
    let value: serde_json::Value = serde_json::from_slice(body).map_err(shape)?;
    if !value.is_object() {
        return Err(Invalid("the body must be a JSON object".to_owned()));
    }
    let req: GroupPointerRequest = serde_json::from_value(value).map_err(shape)?;
    let Some(role) = req.role else {
        return Ok(None);
    };
    if role.is_empty() {
        return Err(Invalid("`role` must not be empty".to_owned()));
    }
    if role.chars().count() > MAX_IDENT_CHARS {
        return Err(Invalid(format!(
            "`role` is limited to {MAX_IDENT_CHARS} characters"
        )));
    }
    if role.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(Invalid("`role` must not contain whitespace".to_owned()));
    }
    Ok(Some(role))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(raw: &str) -> String {
        group_ref(raw).unwrap().uri()
    }

    #[test]
    fn the_authority_is_made_canonical() {
        assert_eq!(
            ok("https://B.Example:443/api/groups/grp_9"),
            "https://b.example/api/groups/grp_9"
        );
        assert_eq!(
            ok("https://b.example.:8443/api/groups/g"),
            "https://b.example:8443/api/groups/g"
        );
    }

    #[test]
    fn anything_but_a_group_uri_is_refused() {
        for raw in [
            "grp_9",
            "alice@b.example",
            "http://b.example/api/groups/grp_9",
            "https://b.example/api/groups/",
            "https://b.example/api/groups/grp_9/",
            "https://b.example/api/groups/grp_9/channels/c",
            "https://b.example/api/groups/grp_9?x=1",
            "https://b.example/api/groups/grp_9#f",
            "https://u@b.example/api/groups/grp_9",
            "https://b.example/api/users/alice",
            "https://b.example/api/groups/grp%209",
            "https://b.example:0443/api/groups/grp_9",
            "https:///api/groups/grp_9",
            "",
        ] {
            assert!(group_ref(raw).is_err(), "{raw}");
        }
    }

    #[test]
    fn the_body_is_optional_and_its_role_a_string() {
        assert_eq!(role_hint(b""), Ok(None));
        assert_eq!(role_hint(b"{}"), Ok(None));
        assert_eq!(role_hint(br#"{"role":"admin"}"#), Ok(Some("admin".into())));
        assert_eq!(
            role_hint(br#"{"role":"mod","x":1}"#),
            Ok(Some("mod".into()))
        );
        for bad in [
            &br#"{"role":null}"#[..],
            br#"{"role":5}"#,
            br#"{"role":["admin"]}"#,
            br#"{"role":""}"#,
            br#"{"role":"a b"}"#,
            b"null",
            b"[]",
            b"not json",
        ] {
            assert!(role_hint(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
        let long = format!(r#"{{"role":"{}"}}"#, "r".repeat(MAX_IDENT_CHARS + 1));
        assert!(role_hint(long.as_bytes()).is_err());
    }
}
