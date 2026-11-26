//! HTTP endpoints for groups and channels (spec §5.5) and tiers (§11.1).
//!
//! | Route | Auth | Who |
//! | --- | --- | --- |
//! | `POST /api/groups` | signed | local actors (provider policy) |
//! | `GET /api/groups/{g}` | optional | anyone for `public`/`discoverable`, else members |
//! | `PATCH /api/groups/{g}` | signed | `manage` |
//! | `DELETE /api/groups/{g}` | signed | owner |
//! | `GET /api/groups/{g}/channels` | optional | group readers; unreadable channels omitted |
//! | `POST /api/groups/{g}/channels` | signed | `manage` |
//! | `GET /api/groups/{g}/channels/{c}` | optional | effective read access (§11.3) |
//! | `PATCH /api/groups/{g}/channels/{c}` | signed | read access, then `manage` |
//! | `DELETE /api/groups/{g}/channels/{c}` | signed | read access, then `manage` |
//! | `GET /api/tiers` | none | anyone |
//!
//! Remote actors (§8.2) use every route but group creation exactly as
//! local ones do, by their full `handle@domain`. A channel the caller
//! cannot read is `404`, as one that does not exist, wherever its group is
//! readable (§11.3, lost-conn/ofscp#26); an unreadable group is `403`. Provider signatures read
//! as anonymous and are refused where a user must act.

use axum::Json;
use axum::extract::{FromRequestParts, Path, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use re_ofscp_types::groups::{
    Channel, ChannelCreateRequest, ChannelList, ChannelUpdateRequest, Group, GroupCreateRequest,
    GroupUpdateRequest, Tier, TierInfo, TiersResponse,
};

use super::Caller;
use super::ops::GroupError;
use crate::AppState;
use crate::problem::Problem;
use crate::signing::{Authenticated, Signer, Verified};

/// Longest local id (§2.2); longer path segments cannot name anything.
const MAX_LOCAL_ID: usize = 128;

impl From<GroupError> for Problem {
    fn from(e: GroupError) -> Self {
        match e {
            GroupError::NotFound(d) => Problem::not_found().with_detail(d),
            GroupError::Forbidden(d) => Problem::forbidden().with_detail(d),
            GroupError::Invalid(i) => Problem::bad_request().with_detail(i.0),
            GroupError::Conflict(d) => Problem::conflict().with_detail(d),
            GroupError::Db(e) => {
                tracing::error!(error = %e, "group operation failed");
                Problem::internal()
            }
        }
    }
}

impl<S: Send + Sync> FromRequestParts<S> for Caller {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(
            match parts.extensions.get::<Verified>().map(|v| &v.signer) {
                Some(Signer::Actor(a)) => Caller::Actor(a.clone()),
                Some(Signer::Provider(_)) | None => Caller::Anonymous,
            },
        )
    }
}

/// A path id that could be a local id; anything else names nothing.
fn local_id(id: &str, what: &'static str) -> Result<(), Problem> {
    let ok = !id.is_empty()
        && id.len() <= MAX_LOCAL_ID
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(Problem::not_found().with_detail(what))
    }
}

fn group_id(id: &str) -> Result<(), Problem> {
    local_id(id, "no such group")
}

fn channel_ids(g: &str, c: &str) -> Result<(), Problem> {
    group_id(g)?;
    local_id(c, "no such channel")
}

/// `POST /api/groups` (§5.5): `201` with the new group.
pub async fn create_group(
    State(state): State<AppState>,
    auth: Authenticated,
    Json(req): Json<GroupCreateRequest>,
) -> Result<Response, Problem> {
    let owner = auth.local_actor(&state.config.domain)?;
    let now = state.verifier.now();
    let group = state.groups.create_group(owner, req, now).await?;
    Ok((StatusCode::CREATED, Json(group)).into_response())
}

/// `GET /api/groups/{groupId}` (§5.5).
pub async fn get_group(
    State(state): State<AppState>,
    caller: Caller,
    Path(g): Path<String>,
) -> Result<Json<Group>, Problem> {
    group_id(&g)?;
    Ok(Json(state.groups.get_group(&caller, &g).await?))
}

/// `PATCH /api/groups/{groupId}` (§5.5).
pub async fn update_group(
    State(state): State<AppState>,
    auth: Authenticated,
    Path(g): Path<String>,
    Json(patch): Json<GroupUpdateRequest>,
) -> Result<Json<Group>, Problem> {
    let actor = auth.actor()?;
    group_id(&g)?;
    let now = state.verifier.now();
    Ok(Json(
        state.groups.update_group(actor, &g, &patch, now).await?,
    ))
}

/// `DELETE /api/groups/{groupId}` (§5.5): `204`.
pub async fn delete_group(
    State(state): State<AppState>,
    auth: Authenticated,
    Path(g): Path<String>,
) -> Result<StatusCode, Problem> {
    let actor = auth.actor()?;
    group_id(&g)?;
    state.groups.delete_group(actor, &g).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /api/groups/{groupId}/channels` (§5.5).
pub async fn list_channels(
    State(state): State<AppState>,
    caller: Caller,
    Path(g): Path<String>,
) -> Result<Json<ChannelList>, Problem> {
    group_id(&g)?;
    let items = state.groups.list_channels(&caller, &g).await?;
    Ok(Json(ChannelList { items }))
}

/// `POST /api/groups/{groupId}/channels` (§5.5): `201` with the channel.
pub async fn create_channel(
    State(state): State<AppState>,
    auth: Authenticated,
    Path(g): Path<String>,
    Json(req): Json<ChannelCreateRequest>,
) -> Result<Response, Problem> {
    let actor = auth.actor()?;
    group_id(&g)?;
    let now = state.verifier.now();
    let channel = state.groups.create_channel(actor, &g, req, now).await?;
    Ok((StatusCode::CREATED, Json(channel)).into_response())
}

/// `GET /api/groups/{groupId}/channels/{channelId}` (§5.5).
pub async fn get_channel(
    State(state): State<AppState>,
    caller: Caller,
    Path((g, c)): Path<(String, String)>,
) -> Result<Json<Channel>, Problem> {
    channel_ids(&g, &c)?;
    Ok(Json(state.groups.get_channel(&caller, &g, &c).await?))
}

/// `PATCH /api/groups/{groupId}/channels/{channelId}` (§5.5).
pub async fn update_channel(
    State(state): State<AppState>,
    auth: Authenticated,
    Path((g, c)): Path<(String, String)>,
    Json(patch): Json<ChannelUpdateRequest>,
) -> Result<Json<Channel>, Problem> {
    let actor = auth.actor()?;
    channel_ids(&g, &c)?;
    let now = state.verifier.now();
    Ok(Json(
        state
            .groups
            .update_channel(actor, &g, &c, &patch, now)
            .await?,
    ))
}

/// `DELETE /api/groups/{groupId}/channels/{channelId}` (§5.5): `204`.
pub async fn delete_channel(
    State(state): State<AppState>,
    auth: Authenticated,
    Path((g, c)): Path<(String, String)>,
) -> Result<StatusCode, Problem> {
    let actor = auth.actor()?;
    channel_ids(&g, &c)?;
    state.groups.delete_channel(actor, &g, &c).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// What each tier means, for `GET /api/tiers`.
fn describe(tier: Tier) -> (&'static str, &'static str) {
    match tier {
        Tier::Private => ("Private", "Members only. Joining is by invitation only."),
        Tier::Group => (
            "Group",
            "Members only. Joining follows the group's join policy.",
        ),
        Tier::Public => (
            "Public",
            "Anyone with the link can read, without signing in. Posting needs membership.",
        ),
        Tier::Discoverable => (
            "Discoverable",
            "Public, and may be recommended to people looking for something new.",
        ),
    }
}

/// `GET /api/tiers` (§11.1): the tiers this provider supports.
pub async fn tiers() -> Json<TiersResponse> {
    Json(TiersResponse {
        tiers: Tier::ALL
            .into_iter()
            .map(|t| {
                let (name, description) = describe(t);
                TierInfo {
                    id: t.as_str().to_owned(),
                    name: name.to_owned(),
                    description: description.to_owned(),
                }
            })
            .collect(),
    })
}
