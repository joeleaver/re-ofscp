//! Checking profile, privacy and presence input before anything is stored
//! (§6.3, §6.4, §6.6). Every failure is a `400` with the message as detail.
//! The limits are this provider's own (docs/decisions/0009).

use std::collections::BTreeSet;

use re_ofscp_types::Actor;
use re_ofscp_types::profile::{MetadataObject, Patch};

use super::store::{PrivacyChanges, ProfileChanges, metadata_json};
use crate::accounts::MAX_DISPLAY_NAME_CHARS;

/// Longest bio, in characters.
pub const MAX_BIO_CHARS: usize = 2000;
/// Longest presence status, in characters.
pub const MAX_STATUS_CHARS: usize = 200;
/// Most entries in one metadata list.
pub const MAX_METADATA_ENTRIES: usize = 32;
/// Largest serialized metadata list, in bytes.
pub const MAX_METADATA_BYTES: usize = 16 * 1024;
/// Most actors in an allow or deny list.
pub const MAX_LIST_ENTRIES: usize = 500;

/// A refused input, explained.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Invalid(pub String);

fn invalid(msg: impl Into<String>) -> Invalid {
    Invalid(msg.into())
}

/// A display name: trimmed, 1 to [`MAX_DISPLAY_NAME_CHARS`] characters, no
/// control characters. Returns the trimmed name.
pub fn display_name(name: &str) -> Result<String, Invalid> {
    let name = name.trim();
    let len = name.chars().count();
    if len == 0 || len > MAX_DISPLAY_NAME_CHARS {
        return Err(invalid(format!(
            "displayName must be 1 to {MAX_DISPLAY_NAME_CHARS} characters"
        )));
    }
    if name.chars().any(char::is_control) {
        return Err(invalid("displayName must not contain control characters"));
    }
    Ok(name.to_owned())
}

/// Free text of at most `max` characters, with no control characters but
/// (when `multiline`) line feeds and tabs.
fn text(field: &str, value: &str, max: usize, multiline: bool) -> Result<(), Invalid> {
    if value.chars().count() > max {
        return Err(invalid(format!("{field} is limited to {max} characters")));
    }
    let allowed = |c: char| multiline && (c == '\n' || c == '\t');
    if value.chars().any(|c| c.is_control() && !allowed(c)) {
        return Err(invalid(format!(
            "{field} must not contain control characters"
        )));
    }
    Ok(())
}

/// Whether `s` is an absolute `https` URL with a host.
fn is_https_url(s: &str) -> bool {
    url::Url::parse(s).is_ok_and(|u| u.scheme() == "https" && u.host_str().is_some())
}

/// A metadata list (§5.4): each `schema` an https URL, each `version`
/// non-empty, within the entry and size limits.
pub fn metadata(field: &str, list: &[MetadataObject]) -> Result<(), Invalid> {
    if list.len() > MAX_METADATA_ENTRIES {
        return Err(invalid(format!(
            "{field} is limited to {MAX_METADATA_ENTRIES} entries"
        )));
    }
    for m in list {
        if !is_https_url(&m.schema) {
            return Err(invalid(format!(
                "{field}: each schema must be an https URL"
            )));
        }
        if m.version.is_empty() {
            return Err(invalid(format!("{field}: each version must be non-empty")));
        }
    }
    if metadata_json(list).len() > MAX_METADATA_BYTES {
        return Err(invalid(format!(
            "{field} is limited to {MAX_METADATA_BYTES} bytes"
        )));
    }
    Ok(())
}

/// A `PATCH /api/me/profile` body, as changes to store.
///
/// Avatars: `null` removes the avatar. Any URL is refused for now: an
/// avatar must be an `Attachment` this provider hosts (§6.3 SHOULD), and it
/// hosts no media until §5.8 is built (docs/decisions/0009). A URL that is
/// not `https` is refused with its own message (§6.3 MUST).
pub fn profile_update(
    update: &re_ofscp_types::profile::ProfileUpdate,
) -> Result<ProfileChanges, Invalid> {
    let display_name = update
        .display_name
        .as_deref()
        .map(display_name)
        .transpose()?;
    let avatar = match &update.avatar {
        Patch::Keep => None,
        Patch::Clear => Some(String::new()),
        Patch::Set(url) if !is_https_url(url) => {
            return Err(invalid("avatar must be an https URL"));
        }
        Patch::Set(_) => {
            return Err(invalid(
                "avatar must be an image uploaded to this provider with POST /api/media, \
                 which this provider does not offer yet; only null (remove) is accepted",
            ));
        }
    };
    if let Some(bio) = &update.bio {
        text("bio", bio, MAX_BIO_CHARS, true)?;
    }
    if let Some(list) = &update.metadata {
        metadata("metadata", list)?;
    }
    Ok(ProfileChanges {
        display_name,
        avatar,
        bio: update.bio.clone(),
        metadata: update.metadata.clone(),
    })
}

/// An allow or deny list: every entry an actor, converted to canonical form
/// (§2.2), duplicates dropped, at most [`MAX_LIST_ENTRIES`].
fn actor_list(field: &str, list: &[String]) -> Result<Vec<Actor>, Invalid> {
    if list.len() > MAX_LIST_ENTRIES {
        return Err(invalid(format!(
            "{field} is limited to {MAX_LIST_ENTRIES} entries"
        )));
    }
    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(list.len());
    for entry in list {
        let actor = Actor::canonicalize(entry)
            .map_err(|e| invalid(format!("{field}: {entry:?} is not an actor ({e})")))?;
        if seen.insert(actor.clone()) {
            out.push(actor);
        }
    }
    Ok(out)
}

/// A `PUT /api/me/privacy` body, as changes to store. `current_allow` and
/// `current_deny` are the stored lists, so a request replacing only one
/// list still cannot leave an actor on both.
pub fn privacy_update(
    update: &re_ofscp_types::profile::PrivacyUpdate,
    current_allow: &[Actor],
    current_deny: &[Actor],
) -> Result<PrivacyChanges, Invalid> {
    let allow = update
        .allow_list
        .as_deref()
        .map(|l| actor_list("allowList", l))
        .transpose()?;
    let deny = update
        .deny_list
        .as_deref()
        .map(|l| actor_list("denyList", l))
        .transpose()?;
    if let Some(list) = &update.metadata {
        metadata("metadata", list)?;
    }
    let final_allow = allow.as_deref().unwrap_or(current_allow);
    let final_deny = deny.as_deref().unwrap_or(current_deny);
    if let Some(both) = final_allow.iter().find(|a| final_deny.contains(a)) {
        return Err(invalid(format!(
            "{both} cannot be on both allowList and denyList"
        )));
    }
    Ok(PrivacyChanges {
        presence: update.presence_visibility,
        profile: update.profile_visibility,
        membership: update.membership_visibility,
        allow,
        deny,
        metadata: update.metadata.clone(),
    })
}

/// A `PUT /api/me/presence` body. `offline`, derived from connection
/// liveness (§7.5), cannot even be decoded: `SetAvailability` has no such
/// value.
pub fn presence_update(update: &re_ofscp_types::profile::PresenceUpdate) -> Result<(), Invalid> {
    if let Some(status) = &update.status {
        text("status", status, MAX_STATUS_CHARS, false)?;
    }
    metadata("metadata", update.new_metadata())
}

#[cfg(test)]
mod tests;
