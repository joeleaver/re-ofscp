//! Guest accounts: provisioning from an invite (§5.6) and upgrading to a
//! full account (§4.8.1).

use core::fmt;

use serde::{Deserialize, Serialize};

use super::auth::REDACTED;
use super::{KeyAlgorithm, Role, UserProfile};
use crate::{Actor, LocalId};

/// `POST /api/invites/{token}/guest`: become a guest of a group (§5.6). The
/// request is unsigned and carries the guest's first device key. Its key
/// fields are snake_case like §4.3's; `displayName` is camelCase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestCreateRequest {
    /// The guest's display name.
    #[serde(
        default,
        rename = "displayName",
        skip_serializing_if = "Option::is_none"
    )]
    pub display_name: Option<String>,
    /// The guest device's public key, base64.
    pub public_key: String,
    /// Always Ed25519 in v0.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<KeyAlgorithm>,
    /// A name the person recognises.
    pub device_name: String,
}

/// The `201 Created` answer to a guest provisioning (§5.6). The spec's
/// casing is mixed: `key_id` as in §4.3, `groupId` camelCase.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GuestCreateResponse {
    /// The new guest actor.
    pub actor: Actor,
    /// The device key's id, bound to the guest.
    pub key_id: String,
    /// The guest's profile (`guest: true`).
    pub profile: UserProfile,
    /// The group the guest joined.
    #[serde(rename = "groupId")]
    pub group_id: LocalId,
    /// The guest's role in it, `guest` by default.
    pub role: Role,
}

/// `POST /api/me/claim`: turn a guest into a full account in place
/// (§4.8.1).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GuestClaimRequest {
    /// The new handle (not starting with `guest_`).
    pub handle: String,
    /// The new password.
    pub password: String,
    /// The new display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// An account invite, for a provider whose registration is by invite.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_token: Option<String>,
}

impl fmt::Debug for GuestClaimRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuestClaimRequest")
            .field("handle", &self.handle)
            .field("password", &REDACTED)
            .field("display_name", &self.display_name)
            .field(
                "invite_token",
                &self.invite_token.as_ref().map(|_| REDACTED),
            )
            .finish()
    }
}

/// `POST /api/me/merge`: fold a guest into an existing account on the same
/// provider, authenticated by that account's password (§4.8.1).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestMergeRequest {
    /// The existing account's handle.
    pub handle: String,
    /// Its password.
    pub password: String,
}

impl fmt::Debug for GuestMergeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuestMergeRequest")
            .field("handle", &self.handle)
            .field("password", &REDACTED)
            .finish()
    }
}

/// The answer to a guest claim or merge (§4.8.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GuestUpgradeResponse {
    /// The full account the guest became.
    pub actor: Actor,
    /// The device key's id, unchanged.
    pub key_id: String,
    /// The account's profile.
    pub profile: UserProfile,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwords_and_invites_stay_out_of_debug() {
        let claim = GuestClaimRequest {
            handle: "ada".into(),
            password: "hunter22".into(),
            display_name: None,
            invite_token: Some("ai_secret".into()),
        };
        let shown = format!("{claim:?}");
        assert!(shown.contains("ada"));
        assert!(!shown.contains("hunter22") && !shown.contains("ai_secret"));
        let merge = GuestMergeRequest {
            handle: "ada".into(),
            password: "hunter22".into(),
        };
        assert!(!format!("{merge:?}").contains("hunter22"));
    }

    #[test]
    fn the_create_response_keeps_the_specs_mixed_casing() {
        let body = serde_json::json!({
            "actor": "guest_7f3a@a.com",
            "key_id": "dk_guest_abc",
            "profile": {
                "id": "https://a.com/api/users/guest_7f3a", "handle": "guest_7f3a",
                "domain": "a.com", "guest": true, "expiresAt": "2025-03-08T12:00:00Z",
                "updatedAt": "2025-03-01T12:00:00Z", "metadata": []
            },
            "groupId": "grp_1",
            "role": "guest"
        });
        let decoded: GuestCreateResponse = serde_json::from_value(body.clone()).unwrap();
        assert_eq!(decoded.profile.guest, Some(true));
        assert_eq!(serde_json::to_value(&decoded).unwrap(), body);
    }
}
