//! Reading notification requests (§10.1, §10.2). Every refusal here is a
//! `400` that changes nothing.

use std::collections::HashMap;

use ofscp_core::LocalId;
use ofscp_core::wire::{NotificationMode, NotificationScope, NotificationSetting};
use serde::Deserialize;

use super::settings::{mode, scope};
use super::store::kind;
use crate::messages::pager;

/// `limit` when absent or unusable (§10.1).
pub const DEFAULT_LIMIT: usize = 30;
/// The largest `limit`; larger values are clamped (§10.1).
pub const MAX_LIMIT: usize = 100;
/// Most `ids` one `seen` or `read` request may name: the whole kept feed.
pub const MAX_IDS: usize = super::store::FEED_CAP as usize;

/// Why a request was refused with `400`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invalid(pub String);

fn invalid(detail: impl Into<String>) -> Invalid {
    Invalid(detail.into())
}

/// `GET /api/me/notifications` parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListQuery {
    /// One of the store's kinds, or `None` for every kind: an unknown
    /// `type` is ignored (§10.1).
    pub kind: Option<&'static str>,
    /// How many entries at most.
    pub limit: usize,
    /// Entries strictly older than this feed position.
    pub before: Option<i64>,
}

const CURSOR_TAG: char = 'n';

/// The opaque cursor for feed position `n`.
pub fn encode_cursor(n: i64) -> String {
    format!("{CURSOR_TAG}{n}")
}

fn decode_cursor(cursor: &str) -> Option<i64> {
    let digits = cursor.strip_prefix(CURSOR_TAG)?;
    if digits.is_empty() || digits.len() > 18 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// Read the list query. Only a cursor this endpoint could not have issued
/// is refused.
pub fn list_query(q: &HashMap<String, String>) -> Result<ListQuery, Invalid> {
    let kind = match q.get("type").map(String::as_str) {
        Some(kind::MENTION) => Some(kind::MENTION),
        Some(kind::REPLY) => Some(kind::REPLY),
        Some(kind::MESSAGE) => Some(kind::MESSAGE),
        _ => None,
    };
    let before = match q.get("cursor") {
        None => None,
        Some(c) => Some(
            decode_cursor(c).ok_or_else(|| invalid("cursor is not one this endpoint issued"))?,
        ),
    };
    Ok(ListQuery {
        kind,
        limit: pager::parse_limit_within(
            q.get("limit").map(String::as_str),
            DEFAULT_LIMIT,
            MAX_LIMIT,
        ),
        before,
    })
}

/// A JSON object body read as `T`. Only an object: serde would also read
/// a struct from an array.
fn object<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, Invalid> {
    let schema = |e: serde_json::Error| invalid(format!("the body does not match the schema: {e}"));
    let value: serde_json::Value = serde_json::from_slice(body).map_err(schema)?;
    if !value.is_object() {
        return Err(invalid("the body must be a JSON object"));
    }
    serde_json::from_value(value).map_err(schema)
}

#[derive(Deserialize)]
struct MarkBody {
    #[serde(default)]
    ids: Option<Vec<String>>,
}

/// Read a `seen` or `read` body: the ids named, empty for all of the
/// caller's entries. An empty body is `{}`.
pub fn mark_body(body: &[u8]) -> Result<Vec<String>, Invalid> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(Vec::new());
    }
    let parsed: MarkBody = object(body)?;
    let ids = parsed.ids.unwrap_or_default();
    if ids.len() > MAX_IDS {
        return Err(invalid(format!("ids is limited to {MAX_IDS} entries")));
    }
    if ids.iter().any(|id| LocalId::new(id).is_err()) {
        return Err(invalid("every id must be a local id (§2.2)"));
    }
    Ok(ids)
}

/// A setting's scope, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    /// [`scope::GROUP`] or [`scope::CHANNEL`].
    pub scope_type: &'static str,
    /// Its local id.
    pub scope_id: LocalId,
}

impl Scope {
    /// The setting of this scope to `mode` (one of [`mode`]), as the wire
    /// carries it.
    pub fn setting(&self, mode: &str) -> NotificationSetting {
        NotificationSetting {
            scope_type: NotificationScope::from(self.scope_type),
            scope_id: self.scope_id.clone(),
            mode: NotificationMode::from(mode),
        }
    }
}

fn scope_of(scope_type: Option<&str>, scope_id: Option<&str>) -> Result<Scope, Invalid> {
    let scope_type = match scope_type {
        Some(scope::GROUP) => scope::GROUP,
        Some(scope::CHANNEL) => scope::CHANNEL,
        _ => return Err(invalid("scopeType must be \"group\" or \"channel\"")),
    };
    let scope_id = scope_id
        .and_then(|id| LocalId::new(id).ok())
        .ok_or_else(|| invalid("scopeId must be a local id (§2.2)"))?;
    Ok(Scope {
        scope_type,
        scope_id,
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SettingBody {
    scope_type: Option<String>,
    scope_id: Option<String>,
    mode: Option<String>,
}

/// Read a `PUT` body: the scope and its mode.
pub fn setting_body(body: &[u8]) -> Result<(Scope, &'static str), Invalid> {
    let parsed: SettingBody = object(body)?;
    let scope = scope_of(parsed.scope_type.as_deref(), parsed.scope_id.as_deref())?;
    let mode = match parsed.mode.as_deref() {
        Some(mode::ALL) => mode::ALL,
        Some(mode::MENTIONS) => mode::MENTIONS,
        Some(mode::NONE) => mode::NONE,
        _ => return Err(invalid("mode must be \"all\", \"mentions\" or \"none\"")),
    };
    Ok((scope, mode))
}

/// Read a `DELETE`'s query: the scope to clear.
pub fn clear_query(q: &HashMap<String, String>) -> Result<Scope, Invalid> {
    scope_of(
        q.get("scopeType").map(String::as_str),
        q.get("scopeId").map(String::as_str),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn list_defaults_clamps_and_ignores_unknown_types() {
        let q = list_query(&query(&[])).unwrap();
        assert_eq!((q.kind, q.limit, q.before), (None, DEFAULT_LIMIT, None));
        let q = list_query(&query(&[("type", "bogus"), ("limit", "500")])).unwrap();
        assert_eq!((q.kind, q.limit), (None, MAX_LIMIT));
        let q = list_query(&query(&[("type", "reply"), ("cursor", "n42")])).unwrap();
        assert_eq!((q.kind, q.before), (Some(kind::REPLY), Some(42)));
        for bad in ["", "n", "t42", "n-1", "n1x"] {
            assert!(list_query(&query(&[("cursor", bad)])).is_err(), "{bad}");
        }
    }

    #[test]
    fn mark_bodies() {
        assert!(mark_body(b"").unwrap().is_empty());
        assert!(mark_body(b"{}").unwrap().is_empty());
        assert_eq!(mark_body(br#"{"ids":["ntf_a"]}"#).unwrap(), ["ntf_a"]);
        assert!(mark_body(br#"{"ids":["not an id"]}"#).is_err());
        assert!(mark_body(br#"{"ids":"ntf_a"}"#).is_err());
        assert!(mark_body(b"[]").is_err());
        let many: Vec<String> = (0..=MAX_IDS).map(|i| format!("ntf_{i}")).collect();
        let body = serde_json::to_vec(&serde_json::json!({ "ids": many })).unwrap();
        assert!(mark_body(&body).is_err());
    }

    #[test]
    fn settings_and_scopes() {
        let (s, m) =
            setting_body(br#"{"scopeType":"channel","scopeId":"chn_1","mode":"all"}"#).unwrap();
        assert_eq!(
            (s.scope_type, s.scope_id.as_str(), m),
            ("channel", "chn_1", "all")
        );
        for bad in [
            r#"{"scopeType":"dm","scopeId":"chn_1","mode":"all"}"#,
            r#"{"scopeType":"group","scopeId":"a b","mode":"all"}"#,
            r#"{"scopeType":"group","scopeId":"grp_1","mode":"loud"}"#,
            r#"{"scopeType":"group","scopeId":"grp_1"}"#,
            "[]",
        ] {
            assert!(setting_body(bad.as_bytes()).is_err(), "{bad}");
        }
        assert!(clear_query(&query(&[("scopeType", "group"), ("scopeId", "grp_1")])).is_ok());
        assert!(clear_query(&query(&[("scopeType", "group")])).is_err());
    }
}
