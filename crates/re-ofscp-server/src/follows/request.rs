//! Reading follow requests (spec §7.6, §2.2, §2.4): a channel reference,
//! from the `POST` body or the `DELETE` path, and the `POST` body itself.
//! Every check here answers `400` and records nothing.

use ofscp_core::{Authority, LocalId, ObjectUri};

/// A channel a follow names, in the one form it is stored under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelRef {
    /// A channel hosted here, by local id. A local channel URI names it
    /// too; `group_id` is the group that URI named, which must be the
    /// channel's own group.
    Local {
        /// The channel's local id.
        channel_id: String,
        /// The group a channel URI named, if the reference was one.
        group_id: Option<String>,
    },
    /// A channel on another provider.
    Remote {
        /// The channel's provider, canonical (§2.2).
        authority: Authority,
        /// Its group's local id there.
        group_id: String,
        /// Its local id there.
        channel_id: String,
    },
}

impl ChannelRef {
    /// The text a follow of this channel is stored and listed under: the
    /// local id, or the canonical object URI of a remote channel.
    pub fn stored(&self) -> String {
        match self {
            ChannelRef::Local { channel_id, .. } => channel_id.clone(),
            ChannelRef::Remote {
                authority,
                group_id,
                channel_id,
            } => channel_uri(authority, group_id, channel_id),
        }
    }
}

/// The object URI of channel `channel_id` of group `group_id` on
/// `authority` (§2.2).
pub fn channel_uri(authority: &Authority, group_id: &str, channel_id: &str) -> String {
    format!("https://{authority}/api/groups/{group_id}/channels/{channel_id}")
}

/// The object URI of the group of a remote channel stored as
/// [`ChannelRef::stored`] gave it (§2.2): the channel URI up to
/// `/channels/`. `None` for anything else.
pub fn group_uri_of(stored_channel: &str) -> Option<&str> {
    let (group, _) = stored_channel.split_once("/channels/")?;
    group.starts_with("https://").then_some(group)
}

/// Why a request was refused with `400`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invalid(pub String);

/// Read a channel reference (§2.4): a bare local id names a channel hosted
/// here; otherwise it must be a channel object URI,
/// `https://{authority}/api/groups/{groupId}/channels/{channelId}` with
/// nothing after the id (no query, fragment or trailing slash). The
/// authority is converted to canonical form, and a URI whose authority is
/// `home` names a local channel.
pub fn channel_ref(raw: &str, home: &Authority) -> Result<ChannelRef, Invalid> {
    if let Ok(id) = LocalId::new(raw) {
        return Ok(ChannelRef::Local {
            channel_id: id.as_str().to_owned(),
            group_id: None,
        });
    }
    let not_a_channel = || {
        Invalid(
            "`channel` must be a channel id or a channel object URI, \
             https://{authority}/api/groups/{groupId}/channels/{channelId}"
                .to_owned(),
        )
    };
    let uri = ObjectUri::canonicalize(raw).map_err(|_| not_a_channel())?;
    let rest = uri
        .path()
        .strip_prefix("/api/groups/")
        .ok_or_else(not_a_channel)?;
    let (group, channel) = rest.split_once("/channels/").ok_or_else(not_a_channel)?;
    let group = LocalId::new(group).map_err(|_| not_a_channel())?;
    let channel = LocalId::new(channel).map_err(|_| not_a_channel())?;
    let (group_id, channel_id) = (group.as_str().to_owned(), channel.as_str().to_owned());
    if uri.authority() == home {
        return Ok(ChannelRef::Local {
            channel_id,
            group_id: Some(group_id),
        });
    }
    Ok(ChannelRef::Remote {
        authority: uri.authority().clone(),
        group_id,
        channel_id,
    })
}

/// Read a `POST /api/me/follows` body: a JSON object with a non-empty
/// string `channel` and, optionally, a non-empty string `groupId`
/// (`follow-create-request.json`). Returns the channel reference's text.
///
/// `groupId` is checked but not used: the provider knows a local channel's
/// group, and a channel URI names its own (docs/decisions/0021).
pub fn create_body(body: &[u8]) -> Result<String, Invalid> {
    let value: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| Invalid(format!("the body must be a JSON object: {e}")))?;
    let obj = value
        .as_object()
        .ok_or_else(|| Invalid("the body must be a JSON object".to_owned()))?;
    let channel = match obj.get("channel") {
        Some(serde_json::Value::String(s)) if !s.is_empty() => s.clone(),
        _ => return Err(Invalid("`channel` must be a non-empty string".to_owned())),
    };
    match obj.get("groupId") {
        None => {}
        Some(serde_json::Value::String(s)) if !s.is_empty() => {}
        Some(_) => {
            return Err(Invalid(
                "`groupId`, when present, must be a non-empty string".to_owned(),
            ));
        }
    }
    Ok(channel)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home() -> Authority {
        Authority::canonicalize("a.example").unwrap()
    }

    #[test]
    fn local_ids_and_local_uris_name_the_same_channel() {
        let bare = channel_ref("chn_1", &home()).unwrap();
        let uri = channel_ref(
            "https://A.example:443/api/groups/grp_1/channels/chn_1",
            &home(),
        )
        .unwrap();
        assert_eq!(bare.stored(), "chn_1");
        assert_eq!(uri.stored(), "chn_1");
        assert_eq!(
            uri,
            ChannelRef::Local {
                channel_id: "chn_1".to_owned(),
                group_id: Some("grp_1".to_owned())
            }
        );
    }

    #[test]
    fn remote_uris_are_stored_canonical() {
        let r = channel_ref(
            "https://B.Example./api/groups/grp_2/channels/chn_9",
            &home(),
        )
        .unwrap();
        assert_eq!(
            r.stored(),
            "https://b.example/api/groups/grp_2/channels/chn_9"
        );
        assert_eq!(
            group_uri_of(&r.stored()),
            Some("https://b.example/api/groups/grp_2")
        );
        assert_eq!(group_uri_of("chn_1"), None);
    }

    #[test]
    fn malformed_references_are_refused() {
        for raw in [
            "",
            "chn 1",
            "http://b.example/api/groups/g/channels/c",
            "https://b.example/api/groups/g",
            "https://b.example/api/groups/g/channels/c/",
            "https://b.example/api/groups/g/channels/c?x=1",
            "https://b.example/api/groups/g/channels/c#f",
            "https://b.example/api/groups/g/x/channels/c",
            "https://b.example/api/groups/g/channels/c/messages",
        ] {
            assert!(channel_ref(raw, &home()).is_err(), "{raw}");
        }
    }

    #[test]
    fn create_bodies_need_a_string_channel() {
        assert_eq!(create_body(br#"{"channel":"chn_1"}"#).unwrap(), "chn_1");
        assert!(create_body(br#"{"channel":"chn_1","groupId":"grp_1","x":1}"#).is_ok());
        for bad in [
            &b""[..],
            b"[]",
            br#"{"channel":""}"#,
            br#"{"channel":1}"#,
            br#"{"channel":"chn_1","groupId":""}"#,
            br#"{"channel":"chn_1","groupId":null}"#,
        ] {
            assert!(create_body(bad).is_err());
        }
    }
}
