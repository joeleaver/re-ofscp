//! HTTP endpoints for channel messages (spec §7.1, §7.2), under
//! `/api/groups/{g}/channels/{c}/messages`.
//!
//! | Route | Auth | Who |
//! | --- | --- | --- |
//! | `POST …/messages` | signed | readers holding `post:<type>` |
//! | `GET …/messages` | optional | effective read access (§11.3) |
//! | `GET …/messages/{m}` | optional | effective read access |
//! | `PATCH …/messages/{m}` | signed | the author, within the edit window |
//! | `DELETE …/messages/{m}` | signed | the author, or `moderate` |
//! | `GET …/messages/{m}/replies` | optional | effective read access |
//! | `GET …/messages/{m}/reactions` | optional | effective read access |
//! | `PUT …/messages/{m}/reactions/{key}` | signed | readers holding `react` |
//! | `DELETE …/messages/{m}/reactions/{key}` | signed | the reaction's author |
//!
//! Remote actors use them exactly as local ones do, by their full
//! `handle@domain` (§8.2). A channel the caller cannot read is `404`, as
//! one that does not exist (§11.3); unsigned and provider-signed reads are
//! an anonymous viewer (§4.5).

use std::collections::HashMap;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Json, Router};
use ofscp_core::wire::{Message, MessagesPage, Paged, Reaction, ReactionPut};
use serde_json::Value;

use super::Created;
use super::ops::MessageError;
use super::reactions::Added;
use crate::AppState;
use crate::db::DbError;
use crate::groups::Caller;
use crate::problem::Problem;
use crate::signing::Authenticated;

/// Largest request body: an article at its limit with room for its
/// attachments and metadata.
pub const MESSAGE_BODY_LIMIT: usize = 512 * 1024;
/// Longest local id (§2.2).
const MAX_LOCAL_ID: usize = 128;

impl From<MessageError> for Problem {
    fn from(e: MessageError) -> Self {
        match e {
            MessageError::NotFound(d) => Problem::not_found().with_detail(d),
            MessageError::Forbidden(d) => Problem::forbidden().with_detail(d),
            MessageError::Invalid(i) => Problem::bad_request().with_detail(i.0),
            MessageError::BadCursor(c) => Problem::bad_request().with_detail(c.to_string()),
            MessageError::Conflict(d) => Problem::conflict().with_detail(d),
            MessageError::Db(DbError::Unavailable(e)) => {
                tracing::error!(error = %e, "message operation: database unavailable");
                Problem::service_unavailable(1)
            }
            // Other writers kept winning a compare-and-set. Usually nothing
            // was written; if an edit or delete had applied before its
            // event could be recorded, a retry is still safe (a repeated
            // edit changes nothing, a repeated delete is already done).
            MessageError::Db(DbError::Contended(e)) => {
                tracing::warn!(error = %e, "message operation: contended");
                Problem::service_unavailable(1)
            }
            MessageError::Db(e) => {
                tracing::error!(error = %e, "message operation failed");
                Problem::internal()
            }
        }
    }
}

/// The message routes, to be merged inside the signature layer.
pub fn router() -> Router<AppState> {
    const BASE: &str = "/api/groups/{group_id}/channels/{channel_id}/messages";
    Router::new()
        .route(BASE, get(history).post(create))
        .route(
            "/api/groups/{group_id}/channels/{channel_id}/messages/{message_id}",
            get(get_message).patch(edit).delete(delete),
        )
        .route(
            "/api/groups/{group_id}/channels/{channel_id}/messages/{message_id}/replies",
            get(replies),
        )
        .route(
            "/api/groups/{group_id}/channels/{channel_id}/messages/{message_id}/reactions",
            get(reactions),
        )
        .route(
            "/api/groups/{group_id}/channels/{channel_id}/messages/{message_id}/reactions/{key}",
            put(add_reaction).delete(remove_reaction),
        )
        .layer(DefaultBodyLimit::max(MESSAGE_BODY_LIMIT))
}

fn is_local_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_LOCAL_ID
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// The ids of a channel route; a bad one names nothing, and is answered
/// as a missing channel, the one `404` body these routes give (§11.3).
fn channel_ids(g: &str, c: &str) -> Result<(), Problem> {
    if is_local_id(g) && is_local_id(c) {
        Ok(())
    } else {
        Err(Problem::not_found().with_detail("no such channel"))
    }
}

/// `POST …/messages` (§7.1): `201` with a new message, `200` with the one
/// an earlier create with the same `clientMessageId` made.
async fn create(
    State(state): State<AppState>,
    auth: Authenticated,
    Path((g, c)): Path<(String, String)>,
    Json(body): Json<Value>,
) -> Result<Response, Problem> {
    let actor = auth.actor()?;
    channel_ids(&g, &c)?;
    Ok(
        match state.messages.create(actor, &g, &c, body, None).await? {
            Created::New(m) => (StatusCode::CREATED, Json(m.to_wire())).into_response(),
            Created::Existing(m) => (StatusCode::OK, Json(m.to_wire())).into_response(),
        },
    )
}

/// `GET …/messages` (§7.2).
async fn history(
    State(state): State<AppState>,
    caller: Caller,
    Path((g, c)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Json<MessagesPage>, Problem> {
    channel_ids(&g, &c)?;
    Ok(Json(state.messages.history(&caller, &g, &c, &q).await?))
}

/// `GET …/messages/{messageId}`.
async fn get_message(
    State(state): State<AppState>,
    caller: Caller,
    Path((g, c, m)): Path<(String, String, String)>,
) -> Result<Json<Message>, Problem> {
    channel_ids(&g, &c)?;
    Ok(Json(
        state.messages.get(&caller, &g, &c, &m).await?.to_wire(),
    ))
}

/// `PATCH …/messages/{messageId}` (§7.1): the edited message.
async fn edit(
    State(state): State<AppState>,
    auth: Authenticated,
    Path((g, c, m)): Path<(String, String, String)>,
    Json(body): Json<Value>,
) -> Result<Json<Message>, Problem> {
    let actor = auth.actor()?;
    channel_ids(&g, &c)?;
    let edited = state.messages.edit(actor, &g, &c, &m, body, None).await?;
    Ok(Json(edited.to_wire()))
}

/// `DELETE …/messages/{messageId}` (§7.1): `204`.
async fn delete(
    State(state): State<AppState>,
    auth: Authenticated,
    Path((g, c, m)): Path<(String, String, String)>,
) -> Result<StatusCode, Problem> {
    let actor = auth.actor()?;
    channel_ids(&g, &c)?;
    state.messages.delete(actor, &g, &c, &m, None).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET …/messages/{messageId}/replies` (§7.2).
async fn replies(
    State(state): State<AppState>,
    caller: Caller,
    Path((g, c, m)): Path<(String, String, String)>,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Json<MessagesPage>, Problem> {
    channel_ids(&g, &c)?;
    Ok(Json(state.messages.replies(&caller, &g, &c, &m, &q).await?))
}

/// `GET …/messages/{messageId}/reactions` (§7.1).
async fn reactions(
    State(state): State<AppState>,
    caller: Caller,
    Path((g, c, m)): Path<(String, String, String)>,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Json<Paged<Reaction>>, Problem> {
    channel_ids(&g, &c)?;
    Ok(Json(
        state.messages.reactions(&caller, &g, &c, &m, &q).await?,
    ))
}

/// The optional body of `PUT …/reactions/{key}` (§7.1): an absent or
/// empty body is not checked; any other must match
/// `reaction-put-request.json`.
fn reaction_put(body: &[u8]) -> Result<ReactionPut, Problem> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(ReactionPut::default());
    }
    let bad = |e: serde_json::Error| {
        Problem::bad_request().with_detail(format!("invalid reaction body: {e}"))
    };
    // An object, as the schema says: serde would also read a struct from
    // an array, field by field.
    match serde_json::from_slice::<Value>(body).map_err(bad)? {
        v @ Value::Object(_) => serde_json::from_value(v).map_err(bad),
        _ => Err(Problem::bad_request().with_detail("the reaction body must be a JSON object")),
    }
}

/// `PUT …/messages/{messageId}/reactions/{key}` (§7.1): `201` with a new
/// reaction, `200` with the one the caller already held.
async fn add_reaction(
    State(state): State<AppState>,
    auth: Authenticated,
    Path((g, c, m, key)): Path<(String, String, String, String)>,
    body: Bytes,
) -> Result<Response, Problem> {
    let actor = auth.actor()?;
    channel_ids(&g, &c)?;
    let put = reaction_put(&body)?;
    Ok(
        match state
            .messages
            .add_reaction(actor, &g, &c, &m, &key, &put, None)
            .await?
        {
            Added::New(r) => (StatusCode::CREATED, Json(r.to_wire())).into_response(),
            Added::Existing(r) => (StatusCode::OK, Json(r.to_wire())).into_response(),
        },
    )
}

/// `DELETE …/messages/{messageId}/reactions/{key}` (§7.1): `204`, whether
/// or not the caller held the reaction.
async fn remove_reaction(
    State(state): State<AppState>,
    auth: Authenticated,
    Path((g, c, m, key)): Path<(String, String, String, String)>,
) -> Result<StatusCode, Problem> {
    let actor = auth.actor()?;
    channel_ids(&g, &c)?;
    state
        .messages
        .remove_reaction(actor, &g, &c, &m, &key, None)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retryable_database_errors_are_503_and_others_500() {
        for e in [
            DbError::Unavailable("down".into()),
            DbError::Contended("busy".into()),
        ] {
            let p = Problem::from(MessageError::Db(e));
            assert_eq!(p.status(), StatusCode::SERVICE_UNAVAILABLE);
        }
        let p = Problem::from(MessageError::Db(DbError::Decode("bad".into())));
        assert_eq!(p.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let p = Problem::from(MessageError::Conflict("edited"));
        assert_eq!(p.status(), StatusCode::CONFLICT);
    }

    #[test]
    fn a_reaction_body_may_be_absent_empty_or_valid_but_not_invalid() {
        assert_eq!(reaction_put(b"").unwrap(), ReactionPut::default());
        assert_eq!(reaction_put(b" \n").unwrap(), ReactionPut::default());
        assert_eq!(reaction_put(b"{}").unwrap(), ReactionPut::default());
        assert_eq!(
            reaction_put(br#"{"unicode":"x"}"#)
                .unwrap()
                .unicode
                .as_deref(),
            Some("x")
        );
        for bad in [&b"null"[..], b"[]", br#"{"unicode":null}"#, b"{"] {
            assert!(reaction_put(bad).is_err());
        }
    }
}
