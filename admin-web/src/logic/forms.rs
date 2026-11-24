//! Form validation: what the user typed, checked and turned into the
//! shared request types before anything is sent. The server checks it all
//! again; this is for quick, specific feedback.

use re_ofscp_types::admin::{
    AdminLoginRequest, AdminRole, CreateAccount, CreateAdmin, CreateInvite, MAX_ACCOUNT_QUERY_LEN,
    MAX_INVITE_TTL_SECS, PasswordChange, TotpConfirm, is_valid_admin_username,
};
use re_ofscp_types::auth::{MAX_PASSWORD_LEN, MIN_PASSWORD_LEN};
use re_ofscp_types::is_valid_handle;

use super::Invalid;

/// Digits in a TOTP code.
pub const CODE_DIGITS: usize = 6;

/// A typed TOTP code without the spaces authenticator apps show
/// (`123 456`), if it is six digits.
pub fn normalize_code(code: &str) -> Option<String> {
    let digits: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    (digits.len() == CODE_DIGITS && digits.bytes().all(|b| b.is_ascii_digit())).then_some(digits)
}

fn code_problem() -> Invalid {
    Invalid::new(format!(
        "Enter the {CODE_DIGITS}-digit code from your authenticator app."
    ))
}

fn check_password(password: &str, what: &str) -> Result<(), Invalid> {
    if (MIN_PASSWORD_LEN..=MAX_PASSWORD_LEN).contains(&password.len()) {
        Ok(())
    } else {
        Err(Invalid::new(format!(
            "{what} must be at least {MIN_PASSWORD_LEN} characters \
             (and at most {MAX_PASSWORD_LEN} bytes)."
        )))
    }
}

fn check_username(username: &str) -> Result<(), Invalid> {
    if is_valid_admin_username(username) {
        Ok(())
    } else {
        Err(Invalid::new(
            "Usernames are 3 to 64 characters: lowercase letters, digits, '.', '_' and '-', \
             starting with a letter or digit.",
        ))
    }
}

fn check_handle(handle: &str) -> Result<(), Invalid> {
    if is_valid_handle(handle) {
        Ok(())
    } else {
        Err(Invalid::new(
            "Handles are 3 to 32 characters: lowercase letters, digits, '_' and '-'.",
        ))
    }
}

/// The sign-in form. The code is optional: an admin who hasn't enrolled
/// TOTP yet signs in with the password alone.
pub fn login(username: &str, password: &str, code: &str) -> Result<AdminLoginRequest, Invalid> {
    let username = username.trim();
    if username.is_empty() || password.is_empty() {
        return Err(Invalid::new("Enter your username and password."));
    }
    let code = if code.trim().is_empty() {
        None
    } else {
        Some(normalize_code(code).ok_or_else(code_problem)?)
    };
    Ok(AdminLoginRequest {
        username: username.to_owned(),
        password: password.to_owned(),
        code,
    })
}

/// Changing one's own password: the current one, and the new one twice.
pub fn password_change(current: &str, new: &str, confirm: &str) -> Result<PasswordChange, Invalid> {
    if current.is_empty() {
        return Err(Invalid::new("Enter your current password."));
    }
    check_password(new, "The new password")?;
    if new != confirm {
        return Err(Invalid::new("The new passwords don't match."));
    }
    if new == current {
        return Err(Invalid::new(
            "Choose a new password that differs from the current one.",
        ));
    }
    Ok(PasswordChange {
        current_password: current.to_owned(),
        new_password: new.to_owned(),
    })
}

/// Confirming TOTP enrollment.
pub fn totp_confirm(code: &str) -> Result<TotpConfirm, Invalid> {
    Ok(TotpConfirm {
        code: normalize_code(code).ok_or_else(code_problem)?,
    })
}

/// The account search box: `None` lists every account (up to the cap).
pub fn account_query(q: &str) -> Result<Option<String>, Invalid> {
    let q = q.trim();
    if q.len() > MAX_ACCOUNT_QUERY_LEN {
        return Err(Invalid::new(format!(
            "Search for at most {MAX_ACCOUNT_QUERY_LEN} characters."
        )));
    }
    Ok((!q.is_empty()).then(|| q.to_owned()))
}

/// Creating an account. An empty display name lets the server use the
/// handle.
pub fn create_account(
    handle: &str,
    display_name: &str,
    password: &str,
) -> Result<CreateAccount, Invalid> {
    let handle = handle.trim();
    check_handle(handle)?;
    check_password(password, "The password")?;
    let display_name = display_name.trim();
    Ok(CreateAccount {
        handle: handle.to_owned(),
        display_name: (!display_name.is_empty()).then(|| display_name.to_owned()),
        password: password.to_owned(),
    })
}

/// Seconds in a day.
const DAY_SECS: i64 = 86_400;

/// Issuing an invite: an optional handle to pin it to, and a lifetime in
/// whole days (empty: the server's default of 7 days).
pub fn create_invite(handle: &str, ttl_days: &str) -> Result<CreateInvite, Invalid> {
    let handle = handle.trim();
    if !handle.is_empty() {
        check_handle(handle)?;
    }
    let max_days = MAX_INVITE_TTL_SECS / DAY_SECS;
    let ttl_days = ttl_days.trim();
    let ttl_secs = if ttl_days.is_empty() {
        None
    } else {
        let days: i64 = ttl_days
            .parse()
            .ok()
            .filter(|d| (1..=max_days).contains(d))
            .ok_or_else(|| {
                Invalid::new(format!(
                    "The lifetime is a whole number of days, 1 to {max_days}."
                ))
            })?;
        Some(days * DAY_SECS)
    };
    Ok(CreateInvite {
        handle: (!handle.is_empty()).then(|| handle.to_owned()),
        ttl_secs,
    })
}

/// Creating an admin, who must change this password at first sign-in.
pub fn create_admin(username: &str, password: &str, role: &str) -> Result<CreateAdmin, Invalid> {
    let username = username.trim();
    check_username(username)?;
    check_password(password, "The initial password")?;
    let role = AdminRole::parse(role).ok_or_else(|| Invalid::new("Choose a role."))?;
    Ok(CreateAdmin {
        username: username.to_owned(),
        password: password.to_owned(),
        role,
    })
}

/// The audit log's admin filter: `None` for every admin.
pub fn audit_admin(username: &str) -> Result<Option<String>, Invalid> {
    let username = username.trim();
    if username.is_empty() {
        return Ok(None);
    }
    check_username(username)?;
    Ok(Some(username.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_six_digits_spaces_allowed() {
        assert_eq!(normalize_code("123456").as_deref(), Some("123456"));
        assert_eq!(normalize_code(" 123 456 ").as_deref(), Some("123456"));
        for bad in ["12345", "1234567", "12345a", "", "１２３４５６"] {
            assert_eq!(normalize_code(bad), None, "{bad}");
        }
    }

    #[test]
    fn login_code_is_optional_but_checked_when_given() {
        let r = login(" joe ", "pw", "").unwrap();
        assert_eq!(r.username, "joe");
        assert_eq!(r.code, None);
        assert_eq!(
            login("joe", "pw", "123 456").unwrap().code.as_deref(),
            Some("123456")
        );
        assert!(login("joe", "pw", "12").is_err());
        assert!(login("", "pw", "").is_err());
        assert!(login("joe", "", "").is_err());
    }

    #[test]
    fn password_change_rules() {
        let ok = password_change("old-password", "new-password", "new-password").unwrap();
        assert_eq!(ok.current_password, "old-password");
        assert_eq!(ok.new_password, "new-password");
        assert!(password_change("", "new-password", "new-password").is_err());
        assert!(password_change("old", "short", "short").is_err());
        assert!(password_change("old", "new-password", "new-passwore").is_err());
        assert!(password_change("same-password", "same-password", "same-password").is_err());
        let long = "x".repeat(MAX_PASSWORD_LEN + 1);
        assert!(password_change("old", &long, &long).is_err());
    }

    #[test]
    fn account_search() {
        assert_eq!(account_query("  ").unwrap(), None);
        assert_eq!(account_query(" al ").unwrap().as_deref(), Some("al"));
        assert!(account_query(&"a".repeat(MAX_ACCOUNT_QUERY_LEN + 1)).is_err());
    }

    #[test]
    fn account_creation() {
        let a = create_account(" alice ", "  ", "password1").unwrap();
        assert_eq!(a.handle, "alice");
        assert_eq!(a.display_name, None);
        let a = create_account("alice", " Alice A. ", "password1").unwrap();
        assert_eq!(a.display_name.as_deref(), Some("Alice A."));
        assert!(create_account("Alice", "", "password1").is_err());
        assert!(create_account("al", "", "password1").is_err());
        assert!(create_account("alice", "", "short").is_err());
    }

    #[test]
    fn invites() {
        let i = create_invite("", "").unwrap();
        assert_eq!((i.handle, i.ttl_secs), (None, None));
        let i = create_invite(" bob ", "3").unwrap();
        assert_eq!(i.handle.as_deref(), Some("bob"));
        assert_eq!(i.ttl_secs, Some(3 * 86_400));
        assert_eq!(
            create_invite("", "30").unwrap().ttl_secs,
            Some(MAX_INVITE_TTL_SECS)
        );
        for bad in ["0", "31", "1.5", "-1", "week"] {
            assert!(create_invite("", bad).is_err(), "{bad}");
        }
        assert!(create_invite("Bob!", "").is_err());
    }

    #[test]
    fn admin_creation() {
        let a = create_admin(" ops-1 ", "password1", "operator").unwrap();
        assert_eq!(a.username, "ops-1");
        assert_eq!(a.role, AdminRole::Operator);
        assert!(create_admin("ops-1", "password1", "").is_err());
        assert!(create_admin("ops-1", "password1", "admin").is_err());
        assert!(create_admin("Ops", "password1", "owner").is_err());
        assert!(create_admin("ops-1", "short", "owner").is_err());
    }

    #[test]
    fn audit_admin_filter() {
        assert_eq!(audit_admin(" ").unwrap(), None);
        assert_eq!(audit_admin("ops").unwrap().as_deref(), Some("ops"));
        assert!(audit_admin("OPS").is_err());
    }
}
