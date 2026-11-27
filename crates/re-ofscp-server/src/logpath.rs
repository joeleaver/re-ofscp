//! Request paths as they may be logged. A path can carry a bearer secret:
//! `POST /api/invites/{token}/redeem` (§5.6) names a group invite's token,
//! which must never reach the logs. Query strings are never logged at all
//! (they can carry account invite tokens, §4.1.1).

use std::borrow::Cow;

/// The prefix of the routes whose next segment is an invite token.
const INVITE_TOKEN_ROUTES: &str = "/api/invites/";

/// `path` with any secret segment replaced by a placeholder.
pub fn loggable(path: &str) -> Cow<'_, str> {
    match path.strip_prefix(INVITE_TOKEN_ROUTES) {
        Some(rest) => {
            let tail = rest.find('/').map_or("", |i| &rest[i..]);
            Cow::Owned(format!("{INVITE_TOKEN_ROUTES}{{token}}{tail}"))
        }
        None => Cow::Borrowed(path),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_tokens_are_redacted_and_other_paths_kept() {
        assert_eq!(
            loggable("/api/invites/gi_secret/redeem"),
            "/api/invites/{token}/redeem"
        );
        assert_eq!(loggable("/api/invites/gi_secret"), "/api/invites/{token}");
        assert_eq!(loggable("/api/invites/"), "/api/invites/{token}");
        assert_eq!(
            loggable("/api/groups/grp_1/invites"),
            "/api/groups/grp_1/invites"
        );
    }
}
