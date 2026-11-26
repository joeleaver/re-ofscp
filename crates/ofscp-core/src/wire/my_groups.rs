//! The user's group list at their home provider: its own memberships plus
//! membership pointers to remote groups (spec §5.7, *My groups*).
//!
//! A pointer is a reference only, like a follow or a conversation pointer:
//! the group's provider stays the authority on membership and role
//! ([`super::Membership`], §5.5).

use serde::{Deserialize, Serialize};

use super::{MetadataObject, Role, Timestamp, some};
use crate::ObjectUri;

/// One entry of the group list (`GroupPointer`), as `GET /api/me/groups`
/// lists it and `PUT /api/me/groups/{groupRef}` answers it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupPointer {
    /// The group's object URI, `https://{authority}/api/groups/{groupId}`,
    /// with a canonical authority (§2.2).
    pub group: ObjectUri,
    /// For a group the home provider hosts, the user's current role; for
    /// a remote group, the hint the client last recorded, which may be
    /// stale or absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<Role>,
    /// When the entry last changed.
    pub updated_at: Timestamp,
}

/// The optional body of `PUT /api/me/groups/{groupRef}`: the role to store
/// as a hint. A `role` that is not a string (`null` included) is refused.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupPointerRequest {
    /// The user's role, as the client last saw it.
    #[serde(
        default,
        deserialize_with = "some",
        skip_serializing_if = "Option::is_none"
    )]
    pub role: Option<Role>,
}

/// `GET /api/me/groups`: every group the provider hosts that the caller is
/// a member of, and every pointer the caller has recorded.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GroupPointersResponse {
    /// The entries.
    pub groups: Vec<GroupPointer>,
    /// Extension data (§5.4).
    #[serde(default)]
    pub metadata: Vec<MetadataObject>,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn a_pointer_needs_a_canonical_group_uri() {
        let ok =
            json!({"group": "https://b.com/api/groups/grp_9", "updatedAt": "2026-02-01T10:00:00Z"});
        let p: GroupPointer = serde_json::from_value(ok.clone()).unwrap();
        assert!(p.role.is_none());
        assert_eq!(serde_json::to_value(&p).unwrap(), ok);
        let upper =
            json!({"group": "https://B.com/api/groups/grp_9", "updatedAt": "2026-02-01T10:00:00Z"});
        assert!(serde_json::from_value::<GroupPointer>(upper).is_err());
        let http =
            json!({"group": "http://b.com/api/groups/grp_9", "updatedAt": "2026-02-01T10:00:00Z"});
        assert!(serde_json::from_value::<GroupPointer>(http).is_err());
    }

    #[test]
    fn a_null_role_hint_is_refused_and_an_empty_body_is_fine() {
        assert!(serde_json::from_value::<GroupPointerRequest>(json!({"role": null})).is_err());
        let empty: GroupPointerRequest = serde_json::from_value(json!({})).unwrap();
        assert!(empty.role.is_none());
    }
}
