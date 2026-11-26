//! HTTP endpoints for profiles, presence, memberships and privacy (spec
//! §5.1.2, §6).
//!
//! | Route | Auth | Spec |
//! | --- | --- | --- |
//! | `GET /api/me` | signed, local actor | §5.1.2 |
//! | `PATCH /api/me/profile` | signed, local actor | §6.3 |
//! | `PUT /api/me/presence` | signed, local actor | §6.4 |
//! | `GET /api/me/privacy` | signed, local actor | §6.6 |
//! | `PUT /api/me/privacy` | signed, local actor | §6.6 |
//! | `GET /api/users/{userRef}/profile` | any signer, or unsigned | §6.2 |
//! | `GET /api/users/{userRef}/presence` | any signer, or unsigned | §6.4 |
//! | `GET /api/users/{userRef}/groups` | any signer, or unsigned | §6.5 |
//!
//! Local-account endpoints refuse remote signers with `403` (security
//! requirement 1). The viewer endpoints accept local and remote users,
//! providers and unsigned callers (an anonymous viewer, which satisfies only
//! `public`); a signature that fails verification is still `401`. What each
//! sees follows the subject's privacy settings (§6.1).
//! A viewer who may not see something gets the same answer as if there
//! were nothing to see, never `403`, so a refusal reveals nothing
//! (docs/decisions/0009; spec behaviour settled in lost-conn/ofscp#26).

use axum::Json;
use axum::extract::{Path, State};
use re_ofscp_types::profile::{
    Presence, PresenceUpdate, PrivacySettings, PrivacyUpdate, ProfileUpdate, UserAccount,
    UserGroups, UserProfile,
};
use serde_json::Map;

use super::validate::{self, Invalid};
use super::{StoredProfile, render_privacy, user_ref};
use crate::AppState;
use crate::privacy::Viewer;
use crate::problem::Problem;
use crate::signing::{Authenticated, MaybeAuthenticated};

/// Largest body accepted by the profile, presence and privacy updates:
/// room for two full actor lists (§6.6) with metadata, far below the
/// signed-body cap.
pub const PROFILE_BODY_LIMIT: usize = 256 * 1024;

fn internal(e: impl std::fmt::Display) -> Problem {
    tracing::error!(error = %e, "profile operation failed");
    Problem::internal()
}

fn bad_request(e: Invalid) -> Problem {
    Problem::bad_request().with_detail(e.0)
}

/// The one answer for every `{userRef}` this provider cannot serve:
/// malformed, another provider's user, unknown, or disabled.
fn no_such_user() -> Problem {
    Problem::not_found().with_detail("no such user on this provider")
}

/// The active local user `user_ref` names.
async fn subject(state: &AppState, user_ref: &str) -> Result<StoredProfile, Problem> {
    let profiles = &state.profiles;
    let handle = user_ref::local_handle(user_ref, &profiles.domain).ok_or_else(no_such_user)?;
    profiles
        .store
        .profile(&handle)
        .await
        .map_err(internal)?
        .ok_or_else(no_such_user)
}

/// The caller's own active profile. A signer whose account is gone (it was
/// disabled mid-request) gets `401`, as its keys no longer verify.
async fn own_profile(state: &AppState, handle: &str) -> Result<StoredProfile, Problem> {
    state
        .profiles
        .store
        .profile(handle)
        .await
        .map_err(internal)?
        .ok_or_else(|| Problem::unauthorized().with_detail("this account is not active"))
}

/// `GET /api/me` (§5.1.2): the caller's `UserAccount`.
pub async fn me(
    State(state): State<AppState>,
    auth: Authenticated,
) -> Result<Json<UserAccount>, Problem> {
    let actor = auth.local_actor(&state.config.domain)?;
    let profile = own_profile(&state, actor.handle()).await?;
    Ok(Json(UserAccount {
        profile: state.profiles.render(profile, true),
        settings: Map::new(),
    }))
}

/// `PATCH /api/me/profile` (§6.3): update the caller's profile and return
/// it, bio included.
pub async fn update_profile(
    State(state): State<AppState>,
    auth: Authenticated,
    Json(update): Json<ProfileUpdate>,
) -> Result<Json<UserProfile>, Problem> {
    let actor = auth.local_actor(&state.config.domain)?;
    let changes = validate::profile_update(&update).map_err(bad_request)?;
    let now = state.verifier.now();
    let profile = state
        .profiles
        .store
        .update_profile(actor.handle(), &changes, now)
        .await
        .map_err(internal)?
        .ok_or_else(|| Problem::unauthorized().with_detail("this account is not active"))?;
    Ok(Json(state.profiles.render(profile, true)))
}

/// `PUT /api/me/presence` (§6.4): replace the caller's explicit presence
/// and return their own presence as viewers they admit would see it.
pub async fn set_presence(
    State(state): State<AppState>,
    auth: Authenticated,
    Json(update): Json<PresenceUpdate>,
) -> Result<Json<Presence>, Problem> {
    let actor = auth.local_actor(&state.config.domain)?;
    validate::presence_update(&update).map_err(bad_request)?;
    let now = state.verifier.now();
    let stored = state
        .profiles
        .store
        .set_presence(
            actor.handle(),
            update.availability,
            update.status.as_deref(),
            &update.metadata,
            now,
        )
        .await
        .map_err(internal)?;
    Ok(Json(state.profiles.effective_presence(actor, Some(stored))))
}

/// `GET /api/me/privacy` (§6.6).
pub async fn privacy(
    State(state): State<AppState>,
    auth: Authenticated,
) -> Result<Json<PrivacySettings>, Problem> {
    let actor = auth.local_actor(&state.config.domain)?;
    let privacy = state
        .profiles
        .store
        .privacy(actor.handle())
        .await
        .map_err(internal)?;
    Ok(Json(render_privacy(privacy)))
}

/// `PUT /api/me/privacy` (§6.6): change the given settings, leave the rest,
/// and return them all.
pub async fn update_privacy(
    State(state): State<AppState>,
    auth: Authenticated,
    Json(update): Json<PrivacyUpdate>,
) -> Result<Json<PrivacySettings>, Problem> {
    let actor = auth.local_actor(&state.config.domain)?;
    let store = &state.profiles.store;
    // Validated against what is stored; if a concurrent first save created
    // the settings meanwhile, validate again against those
    // (see `ProfileStore::update_privacy`).
    for _ in 0..PRIVACY_ATTEMPTS {
        let current = store.privacy(actor.handle()).await.map_err(internal)?;
        let changes = validate::privacy_update(&update, &current.allow, &current.deny)
            .map_err(bad_request)?;
        let now = state.verifier.now();
        if let Some(privacy) = store
            .update_privacy(actor.handle(), &changes, &current, now)
            .await
            .map_err(internal)?
        {
            return Ok(Json(render_privacy(privacy)));
        }
    }
    Err(Problem::conflict().with_detail("privacy settings are being changed concurrently; retry"))
}

/// How often `PUT /api/me/privacy` re-validates after losing a first-save
/// race before giving up with `409`.
const PRIVACY_ATTEMPTS: usize = 4;

/// `GET /api/users/{userRef}/profile` (§6.2).
pub async fn user_profile(
    State(state): State<AppState>,
    auth: MaybeAuthenticated,
    Path(user_ref): Path<String>,
) -> Result<Json<UserProfile>, Problem> {
    let profile = subject(&state, &user_ref).await?;
    let viewer = Viewer::from_verified(auth.0.as_ref());
    let shown = state
        .profiles
        .profile_for(profile, &viewer)
        .await
        .map_err(internal)?;
    Ok(Json(shown))
}

/// `GET /api/users/{userRef}/presence` (§6.4).
pub async fn user_presence(
    State(state): State<AppState>,
    auth: MaybeAuthenticated,
    Path(user_ref): Path<String>,
) -> Result<Json<Presence>, Problem> {
    let profile = subject(&state, &user_ref).await?;
    let viewer = Viewer::from_verified(auth.0.as_ref());
    let shown = state
        .profiles
        .presence_for(&profile.handle, &viewer)
        .await
        .map_err(internal)?;
    Ok(Json(shown))
}

/// `GET /api/users/{userRef}/groups` (§6.5).
pub async fn user_groups(
    State(state): State<AppState>,
    auth: MaybeAuthenticated,
    Path(user_ref): Path<String>,
) -> Result<Json<UserGroups>, Problem> {
    let profile = subject(&state, &user_ref).await?;
    let viewer = Viewer::from_verified(auth.0.as_ref());
    let shown = state
        .profiles
        .groups_for(&profile.handle, &viewer)
        .await
        .map_err(internal)?;
    Ok(Json(shown))
}
