//! Reading a `PATCH /api/me/read-markers` body (spec §7.7,
//! `read-markers-update-request.json`). Every check here answers `400`.
//!
//! A well-formed marker for a scope the caller cannot use is not a `400`:
//! it is ignored like an unknown scope (§7.7), which the service decides.

use ofscp_core::LocalId;

/// Most markers one request may carry.
pub const MAX_MARKERS_PER_REQUEST: usize = 100;

/// One marker to move forward, as sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarkerUpdate {
    /// The scope id, as sent: any non-empty string. One that is not a
    /// local id names no scope here.
    pub scope_id: String,
    /// The newest message read.
    pub last_read_message_id: LocalId,
}

/// Why a request was refused with `400`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invalid(pub String);

fn invalid(s: &str) -> Invalid {
    Invalid(s.to_owned())
}

/// Read the body: `{ "markers": [ { "scopeId", "lastReadMessageId" } ] }`
/// with one to [`MAX_MARKERS_PER_REQUEST`] markers. Unknown fields are
/// ignored (§2.3), so a client's extra `lastReadSeq` is harmless.
pub fn update_body(body: &[u8]) -> Result<Vec<MarkerUpdate>, Invalid> {
    let value: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| Invalid(format!("the body must be a JSON object: {e}")))?;
    let markers = value
        .as_object()
        .and_then(|o| o.get("markers"))
        .and_then(|m| m.as_array())
        .ok_or_else(|| invalid("the body must be {\"markers\": [ … ]}"))?;
    if markers.is_empty() {
        return Err(invalid("`markers` must hold at least one marker"));
    }
    if markers.len() > MAX_MARKERS_PER_REQUEST {
        return Err(Invalid(format!(
            "`markers` may hold at most {MAX_MARKERS_PER_REQUEST} markers"
        )));
    }
    markers
        .iter()
        .map(|m| {
            let obj = m
                .as_object()
                .ok_or_else(|| invalid("each marker must be an object"))?;
            let scope_id = match obj.get("scopeId") {
                Some(serde_json::Value::String(s)) if !s.is_empty() => s.clone(),
                _ => return Err(invalid("`scopeId` must be a non-empty string")),
            };
            let last_read_message_id = obj
                .get("lastReadMessageId")
                .and_then(|v| v.as_str())
                .and_then(|s| LocalId::new(s).ok())
                .ok_or_else(|| invalid("`lastReadMessageId` must be a message id"))?;
            Ok(MarkerUpdate {
                scope_id,
                last_read_message_id,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_formed_bodies_are_read() {
        let got = update_body(
            br#"{"markers":[{"scopeId":"chn_1","lastReadMessageId":"msg_2","lastReadSeq":7}]}"#,
        )
        .unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].scope_id, "chn_1");
        assert_eq!(got[0].last_read_message_id.as_str(), "msg_2");
        // A scope id that is no local id is not a 400: it is ignored later.
        assert!(update_body(br#"{"markers":[{"scopeId":"a b","lastReadMessageId":"m"}]}"#).is_ok());
    }

    #[test]
    fn malformed_bodies_are_refused() {
        let many = format!(
            r#"{{"markers":[{}]}}"#,
            vec![r#"{"scopeId":"c","lastReadMessageId":"m"}"#; MAX_MARKERS_PER_REQUEST + 1]
                .join(",")
        );
        for bad in [
            "",
            "[]",
            "{}",
            r#"{"markers":[]}"#,
            r#"{"markers":{}}"#,
            r#"{"markers":[1]}"#,
            r#"{"markers":[{"lastReadMessageId":"m"}]}"#,
            r#"{"markers":[{"scopeId":"","lastReadMessageId":"m"}]}"#,
            r#"{"markers":[{"scopeId":"c"}]}"#,
            r#"{"markers":[{"scopeId":"c","lastReadMessageId":"a/b"}]}"#,
            r#"{"markers":[{"scopeId":"c","lastReadMessageId":5}]}"#,
            many.as_str(),
        ] {
            assert!(update_body(bad.as_bytes()).is_err(), "{bad}");
        }
    }
}
