//! Invites, members and join requests (spec §5.6, §5.7).

use core::fmt;

use serde::{Deserialize, Serialize};

use super::auth::REDACTED;
use super::{Role, Timestamp, open_enum};
use crate::{Actor, LocalId};

/// A link that lets people join a group (§5.6). Its `token` is a bearer
/// secret: `Debug` never shows it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Invite {
    /// The invite's local id.
    pub id: LocalId,
    /// The group it is for.
    pub group_id: LocalId,
    /// The channel to land in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<LocalId>,
    /// The secret token in the link.
    pub token: String,
    /// The role it gives.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<Role>,
    /// Whether someone without an account may use it as a guest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants_guest: Option<bool>,
    /// How many times it may be used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_uses: Option<u32>,
    /// How many times it has been used.
    pub uses: u32,
    /// When it stops working.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Timestamp>,
    /// Who made it.
    pub created_by: Actor,
    /// When.
    pub created_at: Timestamp,
}

impl fmt::Debug for Invite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Invite")
            .field("id", &self.id)
            .field("group_id", &self.group_id)
            .field("channel_id", &self.channel_id)
            .field("token", &REDACTED)
            .field("role", &self.role)
            .field("grants_guest", &self.grants_guest)
            .field("max_uses", &self.max_uses)
            .field("uses", &self.uses)
            .field("expires_at", &self.expires_at)
            .field("created_by", &self.created_by)
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// The answer to `POST /api/invites/{token}/redeem`, redeeming an invite
/// as an existing account (§5.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteRedeemResponse {
    /// The group joined.
    pub group_id: LocalId,
    /// The invite's channel, if it names one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<LocalId>,
    /// The role the invite gave.
    pub role: Role,
}

/// `POST /api/groups/{groupId}/invites` (§5.6).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteCreateRequest {
    /// The channel to land in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<LocalId>,
    /// The role it gives.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<Role>,
    /// Whether someone without an account may use it as a guest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants_guest: Option<bool>,
    /// How many times it may be used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_uses: Option<u32>,
    /// When it stops working.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Timestamp>,
}

/// A member of a group (§5.7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Member {
    /// Who.
    pub user: Actor,
    /// Their role.
    pub role: Role,
    /// Their nickname in this group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name_override: Option<String>,
    /// When they joined.
    pub joined_at: Timestamp,
}

open_enum! {
    /// Where a join request stands (§5.7).
    pub enum JoinRequestState {
        /// Waiting for a manager.
        Pending = "pending",
        /// Let in.
        Approved = "approved",
        /// Turned down.
        Denied = "denied",
    }
}

/// A request to join a group whose policy is `request` (§5.7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JoinRequest {
    /// The request's local id.
    pub id: LocalId,
    /// The group.
    pub group_id: LocalId,
    /// Who asked.
    pub user: Actor,
    /// Where it stands.
    pub state: JoinRequestState,
    /// What they said.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// When they asked.
    pub requested_at: Timestamp,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn an_invites_token_stays_out_of_debug() {
        let invite: Invite = serde_json::from_value(json!({
            "id": "inv_1", "groupId": "grp_1", "token": "kQ8sJ2mZ0rV1xN6bC3dF9wYt",
            "uses": 0, "createdBy": "jane@a.com", "createdAt": "2025-03-01T12:00:00Z"
        }))
        .unwrap();
        let shown = format!("{invite:?}");
        assert!(shown.contains("inv_1") && !shown.contains("kQ8sJ2mZ0rV1xN6bC3dF9wYt"));
    }

    #[test]
    fn the_redeem_answer_round_trips() {
        let body = json!({"groupId": "grp_1", "channelId": "chn_general", "role": "member"});
        let r: InviteRedeemResponse = serde_json::from_value(body.clone()).unwrap();
        assert_eq!(r.role, "member");
        assert_eq!(serde_json::to_value(&r).unwrap(), body);
    }
}
