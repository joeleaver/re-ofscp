//! The signed-in admin: shared state for every screen, and the one place
//! requests are sent from, so that a `401` anywhere signs the console out.
//!
//! The CSRF token is part of [`AdminSessionInfo`] and lives only in this
//! signal: never in `localStorage`, `sessionStorage` or a cookie. A reload
//! asks the server for it again (`GET /api/admin/session`).

use re_ofscp_types::admin::AdminSessionInfo;
use rinch::prelude::*;
use serde::de::DeserializeOwned;

use crate::api;
use crate::logic::problem::ApiError;
use crate::logic::request::{self, ApiCall};

/// Where the session stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// Asking the server whether a session cookie is still good.
    Checking,
    /// The server couldn't be asked (offline, server down).
    Unreachable(String),
    /// Signed out.
    SignedOut,
    /// Signed in (possibly restricted).
    SignedIn(AdminSessionInfo),
}

/// The shared session store (`create_store` / `use_store`).
#[derive(Clone, Copy)]
pub struct Session {
    /// Where the session stands.
    pub status: Signal<Status>,
    /// A message for the sign-in screen, such as why the session ended.
    pub notice: Signal<Option<String>>,
}

impl Default for Session {
    /// A store that starts by checking for an existing session.
    fn default() -> Self {
        Self {
            status: Signal::new(Status::Checking),
            notice: Signal::new(None),
        }
    }
}

impl Session {
    /// The signed-in admin, if any.
    pub fn info(&self) -> Option<AdminSessionInfo> {
        match self.status.get() {
            Status::SignedIn(info) => Some(info),
            Status::Checking | Status::Unreachable(_) | Status::SignedOut => None,
        }
    }

    fn csrf(&self) -> Option<String> {
        untracked(|| self.info()).map(|i| i.csrf_token)
    }

    /// Record a new or refreshed session.
    pub fn signed_in(&self, info: AdminSessionInfo) {
        self.notice.set(None);
        self.status.set(Status::SignedIn(info));
    }

    /// Forget the session, with an optional message for the sign-in screen.
    pub fn signed_out(&self, notice: Option<String>) {
        self.notice.set(notice);
        self.status.set(Status::SignedOut);
    }

    /// Sign out if `result` says the session is gone.
    fn watch<T>(&self, result: Result<T, ApiError>) -> Result<T, ApiError> {
        if let Err(e) = &result
            && e.is_unauthorized()
            && untracked(|| self.info()).is_some()
        {
            self.signed_out(Some(
                "Your session ended. Sign in again to continue.".to_owned(),
            ));
        }
        result
    }

    /// Send `call` (with the CSRF token if it is a mutation) and decode the
    /// answer.
    pub async fn call<T: DeserializeOwned>(self, call: ApiCall) -> Result<T, ApiError> {
        let csrf = call.is_mutation().then(|| self.csrf()).flatten();
        let result = api::json(call, csrf.as_deref()).await;
        self.watch(result)
    }

    /// Send `call`, whose answer has no body.
    pub async fn call_empty(self, call: ApiCall) -> Result<(), ApiError> {
        let csrf = call.is_mutation().then(|| self.csrf()).flatten();
        let result = api::empty(call, csrf.as_deref()).await;
        self.watch(result)
    }

    /// Ask the server for the current session and record the answer: used
    /// at start-up and after each set-up step.
    pub async fn refresh(self) {
        match api::json::<AdminSessionInfo>(request::session(), None).await {
            Ok(info) => self.signed_in(info),
            Err(e) if e.is_unauthorized() => {
                if untracked(|| self.info()).is_some() {
                    self.signed_out(Some(
                        "Your session ended. Sign in again to continue.".to_owned(),
                    ));
                } else {
                    self.signed_out(None);
                }
            }
            Err(e) => self.status.set(Status::Unreachable(e.message())),
        }
    }

    /// End the session on the server, then here. If the server can't be
    /// told, the session stays (the cookie would still work) and the error
    /// is returned for the caller to show.
    pub async fn sign_out(self) -> Result<(), ApiError> {
        match self.call_empty(request::logout()).await {
            Ok(()) => {
                self.signed_out(Some("You're signed out.".to_owned()));
                Ok(())
            }
            // Already gone: `call_empty` has signed the console out.
            Err(e) if e.is_unauthorized() => Ok(()),
            Err(e) => Err(e),
        }
    }
}
