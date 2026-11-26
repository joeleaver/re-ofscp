//! Request validation for groups and channels (§5.2, §5.2.1, §5.4, §5.5).
//!
//! The JSON shape is checked by deserialization (types, enums, no `null`);
//! this module adds the rules a schema cannot express and this provider's
//! size limits, which keep every stored object and every response bounded.
//! Each failure is a `400` whose detail names the field.

use std::collections::BTreeSet;

use re_ofscp_types::groups::{MetadataObject, PermissionMap, RoleDefinition};

/// Longest group or channel name, in characters.
pub const MAX_NAME_CHARS: usize = 100;
/// Longest group description, in characters.
pub const MAX_DESCRIPTION_CHARS: usize = 2000;
/// Longest channel topic, in characters.
pub const MAX_TOPIC_CHARS: usize = 1000;
/// Most tags on a channel.
pub const MAX_TAGS: usize = 16;
/// Longest tag, in characters.
pub const MAX_TAG_CHARS: usize = 64;
/// Most actions in a permission map.
pub const MAX_ACTIONS: usize = 32;
/// Most roles listed for one action, and most roles in a catalogue.
pub const MAX_ROLES: usize = 32;
/// Longest action or role name, role label or colour, in characters.
pub const MAX_IDENT_CHARS: usize = 64;
/// Most metadata objects on a group or channel.
pub const MAX_METADATA: usize = 16;
/// Largest serialized metadata list, in bytes.
pub const MAX_METADATA_BYTES: usize = 16 * 1024;

/// The channel actions whose list holds message types, not roles (§5.2.1).
const REPLY_ONLY_TO: &str = "replyOnlyTo";
/// Message types `replyOnlyTo` may name (§5.2.1, the schema's enum).
const MESSAGE_TYPES: [&str; 3] = ["message", "memo", "article"];

/// A validation failure: the `400` detail.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Invalid(pub String);

fn invalid(msg: impl Into<String>) -> Invalid {
    Invalid(msg.into())
}

fn chars(s: &str) -> usize {
    s.chars().count()
}

/// Text that is not empty or only whitespace, holds no control characters,
/// and is at most `max` characters.
fn text(field: &str, value: &str, max: usize, allow_blank: bool) -> Result<(), Invalid> {
    if !allow_blank && value.trim().is_empty() {
        return Err(invalid(format!("`{field}` must not be empty")));
    }
    if chars(value) > max {
        return Err(invalid(format!("`{field}` is limited to {max} characters")));
    }
    if value
        .chars()
        .any(|c| c.is_control() && c != '\n' && c != '\t')
    {
        return Err(invalid(format!(
            "`{field}` must not contain control characters"
        )));
    }
    Ok(())
}

/// A group or channel name.
pub fn name(value: &str) -> Result<(), Invalid> {
    text("name", value, MAX_NAME_CHARS, false)?;
    if value.contains(['\n', '\t']) {
        return Err(invalid("`name` must be a single line"));
    }
    Ok(())
}

/// A group description (may be empty).
pub fn description(value: &str) -> Result<(), Invalid> {
    text("description", value, MAX_DESCRIPTION_CHARS, true)
}

/// A channel topic (may be empty).
pub fn topic(value: &str) -> Result<(), Invalid> {
    text("topic", value, MAX_TOPIC_CHARS, true)
}

/// Channel tags: bounded, each a non-empty single line, no duplicates.
pub fn tags(values: &[String]) -> Result<(), Invalid> {
    if values.len() > MAX_TAGS {
        return Err(invalid(format!("at most {MAX_TAGS} `tags`")));
    }
    let mut seen = BTreeSet::new();
    for t in values {
        text("tags[]", t, MAX_TAG_CHARS, false)?;
        if t.contains(['\n', '\t']) {
            return Err(invalid("`tags[]` must be single lines"));
        }
        if !seen.insert(t.as_str()) {
            return Err(invalid(format!("duplicate tag {t:?}")));
        }
    }
    Ok(())
}

/// An action or role name: non-empty, bounded, no whitespace or controls.
fn ident(field: &str, value: &str) -> Result<(), Invalid> {
    if value.is_empty() {
        return Err(invalid(format!("`{field}` entries must not be empty")));
    }
    if chars(value) > MAX_IDENT_CHARS {
        return Err(invalid(format!(
            "`{field}` entries are limited to {MAX_IDENT_CHARS} characters"
        )));
    }
    if value.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(invalid(format!(
            "`{field}` entries must not contain whitespace"
        )));
    }
    Ok(())
}

fn map_shape(field: &str, map: &PermissionMap) -> Result<(), Invalid> {
    if map.len() > MAX_ACTIONS {
        return Err(invalid(format!("at most {MAX_ACTIONS} `{field}` actions")));
    }
    for (action, listed) in map {
        ident(field, action)?;
        if listed.len() > MAX_ROLES {
            return Err(invalid(format!(
                "at most {MAX_ROLES} entries for `{field}.{action}`"
            )));
        }
        let mut seen = BTreeSet::new();
        for entry in listed {
            ident(field, entry)?;
            if !seen.insert(entry.as_str()) {
                return Err(invalid(format!(
                    "duplicate {entry:?} in `{field}.{action}`"
                )));
            }
        }
    }
    Ok(())
}

/// A group permission map (§5.2).
pub fn group_permissions(map: &PermissionMap) -> Result<(), Invalid> {
    map_shape("permissions", map)
}

/// A channel permission map (§5.2.1): `replyOnlyTo` lists message types.
pub fn channel_permissions(map: &PermissionMap) -> Result<(), Invalid> {
    map_shape("permissions", map)?;
    if let Some(types) = map.get(REPLY_ONLY_TO)
        && let Some(bad) = types.iter().find(|t| !MESSAGE_TYPES.contains(&t.as_str()))
    {
        return Err(invalid(format!(
            "`permissions.replyOnlyTo` names {bad:?}; it lists message types (message, memo, article)"
        )));
    }
    Ok(())
}

/// A role catalogue (§5.2): bounded, unique names.
pub fn roles(catalogue: &[RoleDefinition]) -> Result<(), Invalid> {
    if catalogue.len() > MAX_ROLES {
        return Err(invalid(format!("at most {MAX_ROLES} `roles`")));
    }
    let mut seen = BTreeSet::new();
    for r in catalogue {
        ident("roles[].name", &r.name)?;
        if !seen.insert(r.name.as_str()) {
            return Err(invalid(format!("duplicate role {:?}", r.name)));
        }
        if let Some(label) = &r.label {
            text("roles[].label", label, MAX_IDENT_CHARS, false)?;
        }
        if let Some(color) = &r.color {
            text("roles[].color", color, MAX_IDENT_CHARS, false)?;
        }
    }
    Ok(())
}

/// A metadata list (§5.4): each object carries an `https://` `schema`, a
/// non-empty `version` and a `data` member; the list is bounded.
pub fn metadata(list: &[MetadataObject]) -> Result<(), Invalid> {
    if list.len() > MAX_METADATA {
        return Err(invalid(format!(
            "at most {MAX_METADATA} `metadata` objects"
        )));
    }
    for m in list {
        let schema = m.get("schema").and_then(|v| v.as_str());
        if !schema.is_some_and(|s| s.starts_with("https://") && url::Url::parse(s).is_ok()) {
            return Err(invalid("`metadata[].schema` must be an https:// URI"));
        }
        if !m
            .get("version")
            .and_then(|v| v.as_str())
            .is_some_and(|v| !v.is_empty())
        {
            return Err(invalid("`metadata[].version` must be a non-empty string"));
        }
        if !m.contains_key("data") {
            return Err(invalid("`metadata[].data` is required"));
        }
    }
    let size = serde_json::to_vec(list)
        .map(|v| v.len())
        .unwrap_or(usize::MAX);
    if size > MAX_METADATA_BYTES {
        return Err(invalid(format!(
            "`metadata` is limited to {MAX_METADATA_BYTES} bytes"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn meta(v: serde_json::Value) -> Vec<MetadataObject> {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn names() {
        assert!(name("Dev Guild").is_ok());
        assert!(name("").is_err());
        assert!(name("   ").is_err());
        assert!(name("a\nb").is_err());
        assert!(name("a\u{7}b").is_err());
        assert!(name(&"x".repeat(MAX_NAME_CHARS)).is_ok());
        assert!(name(&"x".repeat(MAX_NAME_CHARS + 1)).is_err());
        assert!(description("").is_ok());
        assert!(description("two\nlines").is_ok());
    }

    #[test]
    fn permission_maps() {
        let ok = PermissionMap::from([("post".into(), vec!["member".into()])]);
        assert!(group_permissions(&ok).is_ok());
        let dup = PermissionMap::from([("post".into(), vec!["member".into(), "member".into()])]);
        assert!(group_permissions(&dup).is_err());
        let blank = PermissionMap::from([("post".into(), vec![String::new()])]);
        assert!(group_permissions(&blank).is_err());
        let spaced = PermissionMap::from([("post".into(), vec!["a b".into()])]);
        assert!(group_permissions(&spaced).is_err());
        let reply = PermissionMap::from([("replyOnlyTo".into(), vec!["memo".into()])]);
        assert!(channel_permissions(&reply).is_ok());
        let bad = PermissionMap::from([("replyOnlyTo".into(), vec!["member".into()])]);
        assert!(channel_permissions(&bad).is_err());
    }

    #[test]
    fn catalogues_and_tags() {
        let r = |n: &str| RoleDefinition {
            name: n.into(),
            label: None,
            color: None,
        };
        assert!(roles(&[r("moderator"), r("admin")]).is_ok());
        assert!(roles(&[r("moderator"), r("moderator")]).is_err());
        assert!(tags(&["a".into(), "b".into()]).is_ok());
        assert!(tags(&["a".into(), "a".into()]).is_err());
        assert!(tags(&vec!["t".to_owned(); MAX_TAGS + 1]).is_err());
    }

    #[test]
    fn metadata_objects() {
        assert!(
            metadata(&meta(
                json!([{"schema": "https://x.example/s", "version": "1", "data": null}])
            ))
            .is_ok()
        );
        assert!(
            metadata(&meta(
                json!([{"schema": "http://x.example/s", "version": "1", "data": 1}])
            ))
            .is_err()
        );
        assert!(
            metadata(&meta(
                json!([{"schema": "https://x.example/s", "version": "", "data": 1}])
            ))
            .is_err()
        );
        assert!(
            metadata(&meta(
                json!([{"schema": "https://x.example/s", "version": "1"}])
            ))
            .is_err()
        );
        let big = "x".repeat(MAX_METADATA_BYTES);
        assert!(
            metadata(&meta(
                json!([{"schema": "https://x.example/s", "version": "1", "data": big}])
            ))
            .is_err()
        );
    }
}
