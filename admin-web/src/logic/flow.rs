//! Which screen a session belongs on: sign-in, the restricted set-up steps
//! (a new password, then TOTP enrollment), or the console.

use re_ofscp_types::admin::AdminSessionInfo;

/// The screen for the current session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// No session: sign in.
    SignIn,
    /// Restricted: choose a new password (another admin chose this one).
    ChangePassword,
    /// Restricted: enroll a TOTP authenticator.
    EnrollTotp,
    /// A full session.
    Console,
}

/// The stage for `session`.
///
/// A restricted session changes its password first, because another admin
/// knows it, then enrolls TOTP. A session the server calls restricted for
/// a reason this console doesn't know is sent back to sign-in rather than
/// shown a console whose every request would be refused.
pub fn stage(session: Option<&AdminSessionInfo>) -> Stage {
    match session {
        None => Stage::SignIn,
        Some(s) if !s.restricted => Stage::Console,
        Some(s) if s.password_change_required => Stage::ChangePassword,
        Some(s) if !s.totp_enabled => Stage::EnrollTotp,
        Some(_) => Stage::SignIn,
    }
}

/// How many set-up steps `session` still has, this one included.
pub fn remaining_steps(session: &AdminSessionInfo) -> usize {
    match stage(Some(session)) {
        Stage::ChangePassword | Stage::EnrollTotp => {
            usize::from(session.password_change_required) + usize::from(!session.totp_enabled)
        }
        Stage::SignIn | Stage::Console => 0,
    }
}

#[cfg(test)]
mod tests {
    use re_ofscp_types::admin::AdminRole;

    use super::*;

    fn info(restricted: bool, totp: bool, change: bool) -> AdminSessionInfo {
        AdminSessionInfo {
            username: "joe".into(),
            role: AdminRole::Owner,
            totp_enabled: totp,
            password_change_required: change,
            restricted,
            csrf_token: "c".into(),
            expires_at: "2026-11-24T12:00:00Z".into(),
        }
    }

    #[test]
    fn stages() {
        assert_eq!(stage(None), Stage::SignIn);
        assert_eq!(stage(Some(&info(false, true, false))), Stage::Console);
        assert_eq!(stage(Some(&info(true, false, true))), Stage::ChangePassword);
        assert_eq!(stage(Some(&info(true, true, true))), Stage::ChangePassword);
        assert_eq!(stage(Some(&info(true, false, false))), Stage::EnrollTotp);
        assert_eq!(stage(Some(&info(true, true, false))), Stage::SignIn);
    }

    #[test]
    fn remaining_steps_counts_this_one() {
        assert_eq!(remaining_steps(&info(true, false, true)), 2);
        assert_eq!(remaining_steps(&info(true, false, false)), 1);
        assert_eq!(remaining_steps(&info(true, true, true)), 1);
        assert_eq!(remaining_steps(&info(false, true, false)), 0);
        assert_eq!(remaining_steps(&info(true, true, false)), 0);
    }
}
