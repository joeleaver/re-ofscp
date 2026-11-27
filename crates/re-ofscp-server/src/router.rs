//! The HTTP router: every route, and the layers around them.

use std::time::Duration;

use axum::routing::{delete, get, patch, post, put};
use axum::{Json, Router, extract::State, middleware};
use re_ofscp_types::{Health, OFSCP_VERSION};

use crate::problem::{self, Problem, ProblemBase};
use crate::{
    AppState, accounts, admin, cors, discovery, follows, groups, messages, my_groups,
    notifications, profiles, read_markers, signing, ws,
};

/// Build the HTTP router.
///
/// Layer order, outermost first: tracing, CORS (§3.4: preflights are
/// answered before anything else, and every response, problems included,
/// gets the headers; the admin paths are excluded by path), problem
/// rendering (so every [`Problem`], including the signature layer's and
/// extractors' rejections, gets its body), signature verification (OFSCP
/// routes only), routes.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .route(
            "/api/auth/register",
            post(accounts::routes::register).layer(auth_body_limit()),
        )
        .route(
            "/api/auth/login",
            post(accounts::routes::login).layer(auth_body_limit()),
        )
        .route(
            "/api/auth/device-keys",
            post(accounts::routes::register_device_key)
                .layer(auth_body_limit())
                .get(accounts::routes::list_device_keys),
        )
        .route(
            "/api/auth/device-keys/{key_id}",
            delete(accounts::routes::revoke_device_key),
        )
        .route(
            "/.well-known/ofscp/users/{handle}/keys",
            get(accounts::routes::user_keys),
        )
        .route("/api/groups", post(groups::routes::create_group))
        .route(
            "/api/groups/{group_id}",
            get(groups::routes::get_group)
                .patch(groups::routes::update_group)
                .delete(groups::routes::delete_group),
        )
        .route(
            "/api/groups/{group_id}/channels",
            get(groups::routes::list_channels).post(groups::routes::create_channel),
        )
        .route(
            "/api/groups/{group_id}/channels/{channel_id}",
            get(groups::routes::get_channel)
                .patch(groups::routes::update_channel)
                .delete(groups::routes::delete_channel),
        )
        .route("/api/tiers", get(groups::routes::tiers))
        .merge(groups::member_routes::routes())
        .merge(groups::invite_routes::routes())
        .route("/api/me", get(profiles::routes::me))
        .route(
            "/api/me/profile",
            patch(profiles::routes::update_profile).layer(profile_body_limit()),
        )
        .route(
            "/api/me/presence",
            put(profiles::routes::set_presence).layer(profile_body_limit()),
        )
        .route(
            "/api/me/privacy",
            get(profiles::routes::privacy)
                .put(profiles::routes::update_privacy)
                .layer(profile_body_limit()),
        )
        .route("/api/me/groups", get(my_groups::routes::list))
        .route(
            "/api/me/groups/{group_ref}",
            put(my_groups::routes::put)
                .delete(my_groups::routes::delete)
                .layer(axum::extract::DefaultBodyLimit::max(
                    my_groups::routes::BODY_LIMIT,
                )),
        )
        .route(
            "/api/me/follows",
            get(follows::routes::list)
                .post(follows::routes::create)
                .layer(axum::extract::DefaultBodyLimit::max(
                    follows::routes::BODY_LIMIT,
                )),
        )
        .route(
            "/api/me/follows/{channel_ref}",
            delete(follows::routes::delete),
        )
        .route(
            "/api/me/read-markers",
            get(read_markers::routes::list)
                .patch(read_markers::routes::update)
                .layer(axum::extract::DefaultBodyLimit::max(
                    read_markers::routes::BODY_LIMIT,
                )),
        )
        .route("/api/me/notifications", get(notifications::routes::list))
        .route(
            "/api/me/notifications/seen",
            post(notifications::routes::seen).layer(axum::extract::DefaultBodyLimit::max(
                notifications::routes::MARK_BODY_LIMIT,
            )),
        )
        .route(
            "/api/me/notifications/read",
            post(notifications::routes::read).layer(axum::extract::DefaultBodyLimit::max(
                notifications::routes::MARK_BODY_LIMIT,
            )),
        )
        .route(
            "/api/me/notification-settings",
            get(notifications::routes::settings)
                .put(notifications::routes::put_setting)
                .delete(notifications::routes::clear_setting)
                .layer(axum::extract::DefaultBodyLimit::max(
                    notifications::routes::SETTING_BODY_LIMIT,
                )),
        )
        .route(
            "/api/users/{user_ref}/profile",
            get(profiles::routes::user_profile),
        )
        .route(
            "/api/users/{user_ref}/presence",
            get(profiles::routes::user_presence),
        )
        .route(
            "/api/users/{user_ref}/groups",
            get(profiles::routes::user_groups),
        )
        .route(discovery::PATH, get(discovery::get))
        .route("/problems/{code}", get(problem::describe))
        .merge(messages::routes::router())
        // The upgrade is normally unsigned, and the `authenticate` handshake
        // inside the socket authenticates (§7.1). It sits inside the
        // signature layer all the same: an upgrade that carries `X-OFSCP-*`
        // headers is a signed request on a route of this specification, so
        // it must verify like any other, and a provider-signed one gets
        // `403`/`401` instead of a socket (§4.5, §8 *Authorization*;
        // docs/decisions/0021).
        .route(ws::PATH, get(ws::upgrade))
        .fallback(|| async { Problem::not_found() })
        .method_not_allowed_fallback(|| async { Problem::method_not_allowed() })
        .layer(middleware::from_fn_with_state(
            signing::SignatureLayer::new(
                state.verifier.clone(),
                state.config.client_ip_header.clone(),
            ),
            signing::authenticate,
        ))
        // Added after the signature layer, so it does not wrap them: admin
        // requests are authenticated by the admin session, never by OFSCP
        // signatures (docs/decisions/0005).
        .merge(admin::routes::router())
        .layer(middleware::map_response_with_state(
            ProblemBase::new(&state.config.domain),
            problem::render,
        ))
        .layer(middleware::from_fn(cors::layer))
        .layer(
            tower_http::trace::TraceLayer::new_for_http().make_span_with(
                // The path only, with invite tokens redacted: query strings
                // and some paths carry secrets (invite tokens in `?invite=`,
                // §4.1.1 "SHOULD NOT log invite tokens"; group invite tokens
                // in `/api/invites/{token}/…`, §5.6).
                |req: &axum::http::Request<axum::body::Body>| {
                    tracing::info_span!(
                        "request",
                        method = %req.method(),
                        path = %crate::logpath::loggable(req.uri().path()),
                    )
                },
            ),
        )
        .with_state(state)
}

/// Body limit for the unauthenticated auth endpoints, whose bodies are a
/// handle, a password (at most 1 KiB) and similar: far below axum's 2 MiB
/// default, so nobody can make the provider buffer and parse megabytes
/// before any check.
fn auth_body_limit() -> axum::extract::DefaultBodyLimit {
    axum::extract::DefaultBodyLimit::max(accounts::routes::AUTH_BODY_LIMIT)
}

/// Body limit for the profile, presence and privacy updates.
fn profile_body_limit() -> axum::extract::DefaultBodyLimit {
    axum::extract::DefaultBodyLimit::max(profiles::routes::PROFILE_BODY_LIMIT)
}

/// `GET /api/health` — liveness plus a database reachability probe.
async fn health(State(state): State<AppState>) -> Json<Health> {
    let database = tokio::time::timeout(Duration::from_secs(2), state.db.ping())
        .await
        .unwrap_or(false);
    Json(Health {
        status: if database { "ok" } else { "degraded" }.to_owned(),
        ofscp: OFSCP_VERSION.to_owned(),
        domain: state.config.domain.to_string(),
        database,
    })
}
