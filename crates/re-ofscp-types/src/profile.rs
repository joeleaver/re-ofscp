//! User profiles, presence and privacy settings (spec §5.1, §6).
//!
//! These are OFSCP protocol types, defined once in [`ofscp_core::wire`];
//! this path is kept for the server and the admin UI.

pub use ofscp_core::wire::{
    Availability, GroupEntry, MetadataObject, Patch, Presence, PresenceUpdate, PrivacySettings,
    PrivacyUpdate, ProfileUpdate, SetAvailability, UserAccount, UserGroups, UserProfile,
    Visibility, VisibilityPolicy,
};
