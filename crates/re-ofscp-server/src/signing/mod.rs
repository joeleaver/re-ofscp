//! OFSCP request signing (spec §4.4–§4.6, §7.1, §8.1).
//!
//! * [`canonical`]: byte-exact canonical strings and Ed25519 sign/verify,
//!   re-exported from [`ofscp_core::signing`].
//! * [`keys`]: how the verifier finds signers' public keys.
//! * [`verify`]: the §4.5 verification pipeline.
//! * [`ws`]: the WebSocket `authenticate` handshake (§7.1) and re-confirming
//!   the key of a live connection.
//! * [`authenticate`]: middleware that verifies any request carrying
//!   `X-OFSCP-*` headers and exposes the result to handlers via
//!   [`Authenticated`].
//!
//! A request with **no** signing headers passes through anonymously (public
//! endpoints such as discovery). A request with **any** signing header must
//! verify completely, or it is rejected; a half-signed request is never
//! treated as anonymous. Nor is a provider-signed one: no route accepts
//! provider signatures, so it is answered `403` (denied provider) or `401`
//! on every route, discovery, the keys endpoint and the `/api/ws` upgrade
//! included (§8 *Authorization*, lost-conn/ofscp#42). An unsigned upgrade
//! passes through and authenticates inside the socket (§7.1); see
//! docs/decisions/0021.

pub mod canonical;
pub mod keys;
pub mod verify;
pub mod ws;

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::extract::{FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use re_ofscp_types::{Actor, Authority};

pub use keys::{
    KeyError, KeyFuture, KeyResolver, Lifetime, ReconfirmFuture, Reconfirmed, Requester, Resolved,
    StaticKeys, classify,
};
pub use verify::{
    Clock, Precheck, RequestParts, Signer, SystemClock, Verified, Verifier, VerifyError,
};
pub use ws::{WsAuthenticate, WsPrecheck, WsVerified};

use crate::client::{Peer, client_keys_by};
use crate::problem::Problem;

/// Largest request body the signature layer will buffer (it must hash the
/// whole body before any handler runs). Larger bodies get `413`.
pub const MAX_SIGNED_BODY: usize = 1024 * 1024;

/// How long the signature layer waits for a signed body to arrive. Slower
/// bodies get `408`, so a connection cannot pin a precheck (and its memory)
/// indefinitely. Correctness does not depend on this: the nonce is recorded
/// against a fresh clock reading (see `Verifier::complete`).
pub const SIGNED_BODY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// The state of the [`authenticate`] layer.
#[derive(Clone)]
pub struct SignatureLayer {
    verifier: Arc<Verifier>,
    /// `CLIENT_IP_HEADER`: how to tell clients apart, so the remote key
    /// fetches a request causes are charged to the client that sent it.
    client_ip_header: Option<String>,
}

impl SignatureLayer {
    /// Verify with `verifier`, identifying clients as `client::client_key`
    /// does with `client_ip_header`.
    pub fn new(verifier: Arc<Verifier>, client_ip_header: Option<String>) -> Self {
        Self {
            verifier,
            client_ip_header,
        }
    }
}

/// Middleware: verify signed requests, pass unsigned ones through.
///
/// Steps 1–4 (headers, host, timestamp, replay) run before the body is read,
/// so a request that fails them costs no buffering.
pub async fn authenticate(
    State(layer): State<SignatureLayer>,
    req: Request,
    next: Next,
) -> Response {
    let verifier = &layer.verifier;
    if !verify::headers::ALL
        .iter()
        .any(|h| req.headers().contains_key(*h))
    {
        return next.run(req).await;
    }
    let (parts, body) = req.into_parts();
    let client = client_keys_by(
        layer.client_ip_header.as_deref(),
        &parts.headers,
        &Peer::from_parts(&parts),
    );
    let requester = Requester::within(client.key, client.network);
    let request = RequestParts {
        method: &parts.method,
        uri: &parts.uri,
        headers: &parts.headers,
    };
    let pre = match verifier.precheck(request) {
        Ok(pre) => pre,
        Err(e) => return reject(&e, parts.uri.path()),
    };
    let read = tokio::time::timeout(SIGNED_BODY_TIMEOUT, to_bytes(body, MAX_SIGNED_BODY)).await;
    let Ok(read) = read else {
        return Problem::request_timeout()
            .with_detail("the signed request body did not arrive in time")
            .into_response();
    };
    let bytes = match read {
        Ok(b) => b,
        Err(e) => {
            let too_large = std::error::Error::source(&e)
                .is_some_and(|s| s.is::<http_body_util::LengthLimitError>());
            return if too_large {
                Problem::payload_too_large()
                    .with_detail(format!(
                        "signed bodies are limited to {MAX_SIGNED_BODY} bytes"
                    ))
                    .into_response()
            } else {
                Problem::bad_request()
                    .with_detail("could not read request body")
                    .into_response()
            };
        }
    };
    match verifier.complete(pre, request, &bytes, &requester).await {
        Ok(verified) => {
            let mut req = Request::from_parts(parts, Body::from(bytes));
            req.extensions_mut().insert(verified);
            next.run(req).await
        }
        Err(e) => reject(&e, parts.uri.path()),
    }
}

fn reject(e: &VerifyError, path: &str) -> Response {
    let path = crate::logpath::loggable(path);
    tracing::info!(reason = %e, path = %path, "rejected signed request");
    Problem::from(e.clone()).into_response()
}

/// Extractor: the request was signed and verified. `401` otherwise.
#[derive(Debug, Clone)]
pub struct Authenticated(pub Verified);

impl<S: Send + Sync> FromRequestParts<S> for Authenticated {
    type Rejection = Problem;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Verified>()
            .cloned()
            .map(Self)
            .ok_or_else(|| {
                Problem::unauthorized().with_detail("this endpoint requires a signed request")
            })
    }
}

/// Extractor: the verified signature if the request was signed, `None` if
/// it carried no signature headers at all. A request whose signature fails
/// verification never gets this far: the middleware answers it `401`.
/// For reads that admit anonymous viewers (§6.1 `public`).
#[derive(Debug, Clone)]
pub struct MaybeAuthenticated(pub Option<Verified>);

impl<S: Send + Sync> FromRequestParts<S> for MaybeAuthenticated {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(parts.extensions.get::<Verified>().cloned()))
    }
}

impl Authenticated {
    /// The signing actor. Only actors are ever verified: a provider
    /// signature was already answered `403` or `401` by the middleware
    /// (lost-conn/ofscp#42).
    pub fn actor(&self) -> &Actor {
        &self.0.actor
    }

    /// The signing actor, required to be a local account of `home`. Remote
    /// actors are refused with `403` (§4.7, security requirement 1): a remote
    /// `alice@elsewhere` is never treated as local `alice`.
    pub fn local_actor(&self, home: &Authority) -> Result<&Actor, Problem> {
        let actor = self.actor();
        if actor.is_local_to(home) {
            Ok(actor)
        } else {
            Err(Problem::forbidden().with_detail("this endpoint is for local accounts only"))
        }
    }
}
