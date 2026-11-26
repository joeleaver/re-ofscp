//! The authentication handshake of a new connection (spec §7.1
//! "Authentication handshake").
//!
//! The provider sends `auth.challenge {nonce, expiresAt}` at once. The
//! first message must be an `authenticate` signed over that nonce, and it
//! must arrive before `expiresAt` (the auth timeout); anything else, a
//! failed verification, or the timeout ends the connection with an
//! `error` and close `4001`.
//!
//! A remote actor's provider is checked against federation policy before
//! any key is fetched (§4.6). Revocations and policy changes that land
//! while a handshake is verifying are caught by the hub's access epoch: if
//! it moved, the new connection re-checks before it is acknowledged.

use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures_util::StreamExt as _;
use futures_util::stream::SplitStream;
use serde::Deserialize;
use serde_json::json;

use super::Hub;
use super::conn::read_error_close;
use super::protocol::{self, Close, WsError, close};
use super::registry::{ConnId, ConnShared, Refused};
use crate::federation::UNKNOWN_RETRY_SECS;
use crate::signing::{Lifetime, Reconfirmed, Requester, VerifyError, WsAuthenticate, WsVerified};

/// Bytes of randomness in a challenge nonce (§7.1: at least 128 bits).
pub const NONCE_BYTES: usize = 24;

/// The `data` of an `authenticate` command (`ws/authenticate.json`).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthData {
    actor: String,
    key_id: String,
    timestamp: String,
    signature: String,
}

/// What a connection needs for its handshake.
pub(super) struct Handshake<'a> {
    pub hub: &'a Arc<Hub>,
    pub id: ConnId,
    pub shared: &'a ConnShared,
    pub requester: &'a Requester,
}

/// A fresh challenge nonce, or `None` if the random source failed.
fn challenge_nonce() -> Option<String> {
    let mut bytes = [0u8; NONCE_BYTES];
    getrandom::fill(&mut bytes).ok()?;
    Some(URL_SAFE_NO_PAD.encode(bytes))
}

impl Handshake<'_> {
    /// Send the challenge and wait for a valid `authenticate`. `None` when
    /// the connection is closing instead (a close has been requested).
    pub async fn run(&self, stream: &mut SplitStream<WebSocket>) -> Option<WsVerified> {
        let hub = self.hub;
        let Some(nonce) = challenge_nonce() else {
            tracing::error!(conn = %self.id, "random source failed; closing");
            self.shared
                .close(Close::new(close::INTERNAL, "random source failed"));
            return None;
        };
        let now = hub.now();
        let ttl = i64::try_from(hub.config.auth_timeout.as_secs()).unwrap_or(i64::MAX);
        self.shared.deliver(
            protocol::event(
                "auth.challenge",
                None,
                json!({
                    "nonce": nonce,
                    "expiresAt": crate::timefmt::rfc3339(now.saturating_add(ttl)),
                }),
                now,
            )
            .into(),
        );
        let deadline = tokio::time::Instant::now() + hub.config.auth_timeout;
        let text = tokio::select! {
            biased;
            _ = self.shared.closed() => return None,
            () = tokio::time::sleep_until(deadline) => {
                self.fail(None, &WsError::unauthorized("no authenticate before the challenge expired"));
                return None;
            }
            frame = next_text(stream, self.shared) => frame?,
        };
        if text.len() > hub.config.max_preauth_bytes {
            self.shared
                .close(Close::new(close::TOO_BIG, "message too big"));
            return None;
        }
        let cmd = match protocol::parse(&text) {
            Ok(cmd) => cmd,
            Err(m) => {
                self.fail(m.id.as_deref(), &WsError::bad_request(m.why));
                return None;
            }
        };
        if cmd.kind != "authenticate" {
            let e = WsError::unauthorized("the first message must be authenticate");
            self.fail(Some(&cmd.id), &e);
            return None;
        }
        let data: AuthData = match serde_json::from_value(cmd.data) {
            Ok(d) => d,
            Err(_) => {
                let e = WsError::bad_request(
                    "authenticate needs actor, keyId, timestamp and signature",
                );
                self.fail(Some(&cmd.id), &e);
                return None;
            }
        };
        match self.verify(&nonce, &data).await {
            Ok(verified) => {
                self.shared.deliver(
                    protocol::event(
                        "authenticated",
                        Some(&cmd.id),
                        json!({ "actor": verified.actor.to_string() }),
                        hub.now(),
                    )
                    .into(),
                );
                tracing::info!(conn = %self.id, actor = %verified.actor, key = %verified.key_id, "WebSocket authenticated");
                Some(verified)
            }
            Err(Failure::Error(e, then)) => {
                tracing::info!(conn = %self.id, code = e.code, why = %e.message, "WebSocket authentication failed");
                self.shared
                    .deliver(e.to_event(Some(&cmd.id), hub.now()).into());
                self.shared.close(then);
                None
            }
            Err(Failure::Closing) => None,
        }
    }

    /// Verify `data` against `nonce` and register the connection.
    async fn verify(&self, nonce: &str, data: &AuthData) -> Result<WsVerified, Failure> {
        let hub = self.hub;
        let verifier = &hub.verifier;
        let auth = WsAuthenticate {
            actor: &data.actor,
            key_id: &data.key_id,
            timestamp: &data.timestamp,
            signature: &data.signature,
        };
        let pre = verifier
            .ws_precheck(&auth, nonce)
            .map_err(Failure::verify)?;
        let epoch = hub.access_epoch();
        let verified = tokio::select! {
            biased;
            _ = self.shared.closed() => return Err(Failure::Closing),
            done = tokio::time::timeout(
                hub.config.verify_timeout,
                verifier.ws_complete(pre, self.requester),
            ) => match done {
                Ok(result) => result.map_err(Failure::verify)?,
                Err(_) => {
                    return Err(Failure::auth(WsError::service_unavailable(
                        "signing keys could not be obtained in time; retry shortly",
                        5,
                    )));
                }
            },
        };
        hub.registry
            .authenticate(self.id, &verified.actor, &verified.key_id)
            .map_err(|refused| match refused {
                Refused::ShuttingDown => Failure::Closing,
                _ => Failure::Error(
                    WsError::too_many_requests("too many connections for this actor", 30),
                    Close::new(close::TRY_AGAIN, "connection cap reached"),
                ),
            })?;
        if verified.actor.is_local_to(&hub.local) && hub.access_epoch() != epoch {
            self.recheck(&verified).await?;
        }
        Ok(verified)
    }

    /// A local revocation landed while `verified` was being verified:
    /// check the key again now that the connection is registered (and so
    /// reachable by later revocations). A remote actor needs no such
    /// check: its connection watches the federation policy from the start
    /// (a denial already in force ends it at once) and re-confirms its key
    /// on its lease.
    async fn recheck(&self, verified: &WsVerified) -> Result<(), Failure> {
        let hub = self.hub;
        match hub
            .verifier
            .reconfirm(verified, Lifetime::Unbounded, self.requester)
            .await
        {
            Reconfirmed::Present(_) => Ok(()),
            Reconfirmed::Gone => Err(Failure::Error(
                WsError::unauthorized("unknown or revoked key"),
                Close::new(close::REVOKED, "credentials revoked"),
            )),
            Reconfirmed::Unconfirmed(_) => Err(Failure::auth(WsError::service_unavailable(
                "signing keys could not be obtained; retry shortly",
                5,
            ))),
        }
    }

    /// Answer with `e` and close `4001`.
    fn fail(&self, correlation: Option<&str>, e: &WsError) {
        tracing::info!(conn = %self.id, code = e.code, why = %e.message, "WebSocket handshake refused");
        self.shared
            .deliver(e.to_event(correlation, self.hub.now()).into());
        self.shared
            .close(Close::new(close::AUTH_FAILED, "authentication failed"));
    }
}

/// Why a handshake did not complete.
enum Failure {
    /// Answer with this error, then close so.
    Error(WsError, Close),
    /// The connection is closing anyway.
    Closing,
}

impl Failure {
    /// Answer with `e`, then close `4001`.
    fn auth(e: WsError) -> Self {
        Self::Error(e, Close::new(close::AUTH_FAILED, "authentication failed"))
    }

    /// The answer to a failed verification (§7.3 codes; the close is
    /// always `4001`, the key was not shown revoked).
    fn verify(e: VerifyError) -> Self {
        let msg = e.to_string();
        Self::auth(match e {
            VerifyError::KeysUnavailable { retry_after }
            | VerifyError::StoreFull { retry_after }
            | VerifyError::WarmingUp { retry_after } => {
                WsError::service_unavailable(msg, retry_after)
            }
            VerifyError::LedgerUnavailable => WsError::service_unavailable(msg, 5),
            VerifyError::PolicyUnknown => WsError::service_unavailable(msg, UNKNOWN_RETRY_SECS),
            // §8.5: `error` then `4001`.
            VerifyError::Forbidden => WsError::forbidden(msg),
            VerifyError::RateLimited { retry_after } => {
                WsError::too_many_requests(msg, retry_after)
            }
            _ => WsError::unauthorized(msg),
        })
    }
}

/// The next text message, skipping control frames. `None` (with a close
/// requested) when the client went away or sent something else.
async fn next_text(stream: &mut SplitStream<WebSocket>, shared: &ConnShared) -> Option<String> {
    loop {
        match stream.next().await {
            Some(Ok(Message::Text(t))) => return Some(t.as_str().to_owned()),
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
            Some(Ok(Message::Binary(_))) => {
                shared.close(Close::new(
                    close::UNSUPPORTED,
                    "binary messages are not supported",
                ));
                return None;
            }
            Some(Ok(Message::Close(_))) | None => {
                shared.close(Close::new(close::NORMAL, "client closed"));
                return None;
            }
            Some(Err(e)) => {
                shared.close(read_error_close(e));
                return None;
            }
        }
    }
}
