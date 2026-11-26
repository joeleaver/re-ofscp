//! What a provider shares about others and itself: known providers (§8.6),
//! tiers (§11) and the discovery feed (§8.4).

use serde::{Deserialize, Serialize};

use super::{Content, MetadataObject, Paged, Tier, Timestamp};
use crate::{Actor, Authority, ObjectRef};

/// `GET /api/providers`: the providers this one knows (§8.6).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProvidersResponse {
    /// The known providers.
    pub providers: Vec<KnownProvider>,
    /// Extension data.
    #[serde(default)]
    pub metadata: Vec<MetadataObject>,
}

/// A provider another provider knows of.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KnownProvider {
    /// Its authority.
    pub domain: Authority,
    /// Its name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// When it was added to the list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub added_at: Option<Timestamp>,
}

/// `GET /api/tiers` (§11).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TiersResponse {
    /// The tiers this provider offers.
    pub tiers: Vec<TierInfo>,
}

/// One tier, described for people.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierInfo {
    /// The tier's value.
    pub id: Tier,
    /// Its name.
    pub name: String,
    /// What it means.
    pub description: String,
}

/// `GET /api/discover`: one page of discoverable channels (§8.4).
pub type DiscoverResponse = Paged<DiscoverItem>;

/// A discoverable channel, perhaps with a recent message as a sample.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoverItem {
    /// The channel (usually an object URI).
    pub channel: ObjectRef,
    /// Its group (usually an object URI).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_id: Option<ObjectRef>,
    /// The provider that hosts it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<Authority>,
    /// A recent message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample: Option<DiscoverSample>,
    /// Extension data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Vec<MetadataObject>>,
}

/// A recent message in a discoverable channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoverSample {
    /// The message's id on the channel's provider.
    pub id: String,
    /// Who wrote it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<Actor>,
    /// When.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<Timestamp>,
    /// What it says.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<Content>,
}
