//! Contacts (spec §6.7).

use serde::{Deserialize, Serialize};

use super::{MetadataObject, Timestamp, open_enum};
use crate::Actor;

open_enum! {
    /// Where a contact stands (§6.7).
    pub enum ContactState {
        /// Asked, not yet answered.
        Pending = "pending",
        /// Both agreed.
        Accepted = "accepted",
    }
}

open_enum! {
    /// Who asked, for a pending contact (§6.7).
    pub enum ContactDirection {
        /// You asked them.
        Outgoing = "outgoing",
        /// They asked you.
        Incoming = "incoming",
    }
}

/// One of your contacts (§6.7).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Contact {
    /// Who.
    pub user: Actor,
    /// Where it stands.
    pub state: ContactState,
    /// Who asked, while pending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<ContactDirection>,
    /// When it began.
    pub created_at: Timestamp,
    /// When it last changed.
    pub updated_at: Timestamp,
    /// Extension data.
    #[serde(default)]
    pub metadata: Vec<MetadataObject>,
}

/// `GET /api/me/contacts` (§6.7).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContactsResponse {
    /// Your contacts.
    pub contacts: Vec<Contact>,
    /// Extension data.
    #[serde(default)]
    pub metadata: Vec<MetadataObject>,
}

/// `POST /api/me/contacts` (§6.7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactCreateRequest {
    /// Who to ask.
    pub user: Actor,
}

open_enum! {
    /// What a federated contact event does (§6.7).
    pub enum ContactAction {
        /// Ask.
        Request = "request",
        /// Agree to an outgoing request.
        Accept = "accept",
        /// End it.
        Remove = "remove",
    }
}

/// `POST /api/federation/contacts`, sent by a client to the other person's
/// provider (§6.7, "Federation").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactEvent {
    /// What it does.
    pub action: ContactAction,
    /// Who sends it.
    pub from: Actor,
    /// Who it is for.
    pub to: Actor,
}
