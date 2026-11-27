//! Values the stores write: fresh object ids and JSON documents.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;

use super::DbError;

/// A fresh local id: `prefix` + 128 random bits, base64url (§2.2).
pub fn new_id(prefix: &'static str) -> Result<String, DbError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| DbError::Query(format!("random source: {e}")))?;
    Ok(format!("{prefix}{}", B64URL.encode(bytes)))
}

/// `value` as a JSON document for a `doc` field.
pub fn json<T: serde::Serialize>(value: &T) -> Result<String, DbError> {
    serde_json::to_string(value).map_err(|e| DbError::Query(format!("encoding a document: {e}")))
}
