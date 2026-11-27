//! Group invite tokens, terms and wire shapes (spec §5.6,
//! docs/decisions/0019).
//!
//! A token is `gi_` + 256 random bits (base64url): a bearer secret that
//! is returned once, by the create, and otherwise never stored, logged or
//! listed. Only its SHA-256 is kept.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use ofscp_core::LocalId;
use re_ofscp_types::Actor;
use re_ofscp_types::wire::{Invite, InviteCreateRequest, Role, Timestamp};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::invite_store::{InviteTerms, StoredInvite};
use super::validate::Invalid;
use crate::db::DbError;
use crate::timefmt;

/// Prefix of every group invite token.
pub const TOKEN_PREFIX: &str = "gi_";
/// Most uses one invite may allow (provider policy). Bounds the slots a
/// redemption reads (`invite_store.rs`).
pub const MAX_INVITE_USES: u32 = 1_000;
/// Furthest ahead an invite may expire (provider policy): a year.
pub const MAX_INVITE_LIFETIME_SECS: i64 = 365 * 24 * 60 * 60;

/// Longest token accepted from a client. Ours are 46 characters; anything
/// much longer is not one of ours and is refused without a lookup.
const MAX_TOKEN_LEN: usize = 128;

/// A fresh token.
pub fn new_token() -> Result<String, DbError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| DbError::Query(format!("random source: {e}")))?;
    Ok(format!("{TOKEN_PREFIX}{}", B64URL.encode(bytes)))
}

/// The stored form of `token`: SHA-256, hex. `None` if `token` cannot be
/// one of ours (wrong prefix or implausibly long), so it is never looked up.
pub fn token_hash(token: &str) -> Option<String> {
    if !token.starts_with(TOKEN_PREFIX) || token.len() > MAX_TOKEN_LEN {
        return None;
    }
    Some(
        Sha256::digest(token.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    )
}

/// The terms of a create request that need no group to check: guests are
/// refused (this provider has no guest accounts, §4.8), `maxUses` is
/// within `1..=`[`MAX_INVITE_USES`], and `expiresAt` lies after `now` and
/// at most [`MAX_INVITE_LIFETIME_SECS`] ahead. The role and channel are
/// checked against the group by the caller; `role` here is the requested
/// one, `member` when absent.
pub fn terms(req: &InviteCreateRequest, now: i64) -> Result<InviteTerms, Invalid> {
    if req.grants_guest == Some(true) {
        return Err(Invalid(
            "`grantsGuest` is not supported: this provider does not offer guest accounts"
                .to_owned(),
        ));
    }
    if let Some(n) = req.max_uses
        && !(1..=MAX_INVITE_USES).contains(&n)
    {
        return Err(Invalid(format!(
            "`maxUses` must be between 1 and {MAX_INVITE_USES}"
        )));
    }
    let expires_at = match req.expires_at {
        None => None,
        Some(at) => {
            let at = at.as_second();
            if at <= now {
                return Err(Invalid("`expiresAt` must be in the future".to_owned()));
            }
            if at > now.saturating_add(MAX_INVITE_LIFETIME_SECS) {
                return Err(Invalid(
                    "`expiresAt` may be at most a year ahead".to_owned(),
                ));
            }
            Some(at)
        }
    };
    Ok(InviteTerms {
        channel_id: req.channel_id.as_ref().map(|c| c.as_str().to_owned()),
        role: req
            .role
            .clone()
            .unwrap_or_else(|| super::access::roles::MEMBER.to_owned()),
        max_uses: req.max_uses,
        expires_at,
    })
}

/// An invite as `GET /api/groups/{groupId}/invites` lists it: the §5.6
/// `Invite` without its `token`, which is not stored and so cannot be
/// listed (docs/decisions/0019).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListedInvite {
    /// The invite's local id.
    pub id: LocalId,
    /// The group it is for.
    pub group_id: LocalId,
    /// The channel to land in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<LocalId>,
    /// The role it gives.
    pub role: Role,
    /// How many times it may be used; absent is unlimited.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_uses: Option<u32>,
    /// How many times it has been used.
    pub uses: u32,
    /// When it stops working.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Timestamp>,
    /// Who made it.
    pub created_by: Actor,
    /// When.
    pub created_at: Timestamp,
}

fn local_id(invite: &StoredInvite, s: &str) -> Result<LocalId, DbError> {
    LocalId::new(s).map_err(|_| DbError::Decode(format!("invite {}: bad id", invite.id)))
}

impl StoredInvite {
    /// The listed form, with `uses` as counted.
    pub fn to_listed(&self, uses: u32) -> Result<ListedInvite, DbError> {
        Ok(ListedInvite {
            id: local_id(self, &self.id)?,
            group_id: local_id(self, &self.group_id)?,
            channel_id: match &self.channel_id {
                Some(c) => Some(local_id(self, c)?),
                None => None,
            },
            role: self.role.clone(),
            max_uses: self.max_uses,
            uses,
            expires_at: self.expires_at.map(timefmt::timestamp),
            created_by: self.created_by.clone(),
            created_at: timefmt::timestamp(self.created_at),
        })
    }

    /// The §5.6 `Invite` the create answers, carrying `token`.
    pub fn to_created(&self, token: String) -> Result<Invite, DbError> {
        let l = self.to_listed(0)?;
        Ok(Invite {
            id: l.id,
            group_id: l.group_id,
            channel_id: l.channel_id,
            token,
            role: Some(l.role),
            grants_guest: None,
            max_uses: l.max_uses,
            uses: 0,
            expires_at: l.expires_at,
            created_by: l.created_by,
            created_at: l.created_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_767_268_800;

    fn req(v: serde_json::Value) -> InviteCreateRequest {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn tokens_are_long_random_and_hash_only_when_ours() {
        let a = new_token().unwrap();
        let b = new_token().unwrap();
        assert_ne!(a, b);
        assert!(a.starts_with(TOKEN_PREFIX) && a.len() == 46, "{a}");
        assert_eq!(token_hash(&a).unwrap().len(), 64);
        assert_eq!(token_hash(&a), token_hash(&a));
        assert_eq!(token_hash("ai_account_invite"), None);
        assert_eq!(token_hash(&format!("gi_{}", "x".repeat(200))), None);
    }

    #[test]
    fn terms_default_to_a_member_invite_without_limits() {
        let t = terms(&req(serde_json::json!({})), NOW).unwrap();
        assert_eq!(
            t,
            InviteTerms {
                channel_id: None,
                role: "member".to_owned(),
                max_uses: None,
                expires_at: None,
            }
        );
        let t = terms(&req(serde_json::json!({"grantsGuest": false})), NOW).unwrap();
        assert_eq!(t.role, "member");
    }

    #[test]
    fn terms_refuse_guests_and_out_of_range_limits() {
        assert!(terms(&req(serde_json::json!({"grantsGuest": true})), NOW).is_err());
        assert!(terms(&req(serde_json::json!({"maxUses": 0})), NOW).is_err());
        assert!(terms(&req(serde_json::json!({"maxUses": 1001})), NOW).is_err());
        assert!(terms(&req(serde_json::json!({"maxUses": 1000})), NOW).is_ok());
        let at = |secs: i64| req(serde_json::json!({"expiresAt": timefmt::rfc3339(NOW + secs)}));
        assert!(terms(&at(0), NOW).is_err());
        assert!(terms(&at(-60), NOW).is_err());
        assert_eq!(terms(&at(60), NOW).unwrap().expires_at, Some(NOW + 60));
        assert!(terms(&at(MAX_INVITE_LIFETIME_SECS), NOW).is_ok());
        assert!(terms(&at(MAX_INVITE_LIFETIME_SECS + 1), NOW).is_err());
    }
}
