//! What an API answer does to the session: the decisions behind
//! `Session::watch` and `Session::refresh`, kept free of signals so they
//! are unit-tested natively.

use re_ofscp_types::admin::AdminSessionInfo;

use super::problem::ApiError;

/// The sign-in screen's notice when a session the console held is refused.
pub const SESSION_ENDED: &str = "Your session ended. Sign in again to continue.";

/// A change to the session store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transition {
    /// Leave the session (and the sign-in notice) as it is.
    Keep,
    /// Record this session and clear the sign-in notice.
    SignIn(AdminSessionInfo),
    /// Go back to sign-in, showing this notice (or none).
    SignOut(Option<String>),
    /// The server couldn't be asked; the message says why.
    Unreachable(String),
}

/// After an ordinary request failed with `error`. `signed_in` is whether
/// the console held a session when the answer came.
///
/// A `401` ends a session the console held, with a notice saying so. With
/// no session there is nothing to end (a refused sign-in is the sign-in
/// screen's own error to show), and any other failure is the asking
/// screen's to show.
pub fn after_request(error: &ApiError, signed_in: bool) -> Transition {
    if error.is_unauthorized() && signed_in {
        Transition::SignOut(Some(SESSION_ENDED.to_owned()))
    } else {
        Transition::Keep
    }
}

/// After asking the server for the current session (start-up, retry, and
/// each set-up step). `signed_in` is whether the console held a session
/// when the answer came.
///
/// A `401` always lands on sign-in: with the notice when it ends a session
/// the console held, and without one when there was none to end (a first
/// visit). Any other failure means the server couldn't be asked.
pub fn after_refresh(answer: Result<AdminSessionInfo, ApiError>, signed_in: bool) -> Transition {
    match answer {
        Ok(info) => Transition::SignIn(info),
        Err(e) if e.is_unauthorized() => {
            Transition::SignOut(signed_in.then(|| SESSION_ENDED.to_owned()))
        }
        Err(e) => Transition::Unreachable(e.message()),
    }
}

#[cfg(test)]
mod tests {
    use re_ofscp_types::admin::AdminRole;

    use super::*;

    fn info() -> AdminSessionInfo {
        AdminSessionInfo {
            username: "joe".into(),
            role: AdminRole::Owner,
            totp_enabled: true,
            password_change_required: false,
            restricted: false,
            csrf_token: "c".into(),
            expires_at: "2026-11-24T12:00:00Z".into(),
        }
    }

    fn status(status: u16) -> ApiError {
        ApiError::Status {
            status,
            message: "No.".to_owned(),
        }
    }

    #[test]
    fn a_refused_request_ends_a_held_session_with_a_notice() {
        assert_eq!(
            after_request(&status(401), true),
            Transition::SignOut(Some(SESSION_ENDED.to_owned()))
        );
    }

    #[test]
    fn a_refused_request_without_a_session_changes_nothing() {
        assert_eq!(after_request(&status(401), false), Transition::Keep);
    }

    #[test]
    fn other_request_failures_are_the_screens_to_show() {
        for e in [
            status(400),
            status(403),
            status(503),
            ApiError::Network("offline".to_owned()),
            ApiError::Unreadable("eof".to_owned()),
        ] {
            assert_eq!(after_request(&e, true), Transition::Keep, "{e:?}");
            assert_eq!(after_request(&e, false), Transition::Keep, "{e:?}");
        }
    }

    #[test]
    fn a_refresh_records_the_session() {
        assert_eq!(after_refresh(Ok(info()), false), Transition::SignIn(info()));
        assert_eq!(after_refresh(Ok(info()), true), Transition::SignIn(info()));
    }

    #[test]
    fn a_refused_refresh_ends_a_held_session_with_a_notice() {
        assert_eq!(
            after_refresh(Err(status(401)), true),
            Transition::SignOut(Some(SESSION_ENDED.to_owned()))
        );
    }

    #[test]
    fn a_refused_refresh_without_a_session_signs_in_quietly() {
        assert_eq!(
            after_refresh(Err(status(401)), false),
            Transition::SignOut(None)
        );
    }

    #[test]
    fn a_failed_refresh_says_the_server_is_unreachable() {
        let down = ApiError::Network("offline".to_owned());
        assert_eq!(
            after_refresh(Err(down.clone()), true),
            Transition::Unreachable(down.message())
        );
        assert_eq!(
            after_refresh(Err(status(503)), false),
            Transition::Unreachable("No.".to_owned())
        );
    }
}
