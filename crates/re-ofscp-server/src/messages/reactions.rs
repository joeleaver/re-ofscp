//! Reactions on channel messages (§7.1 *Reactions*): adding, removing and
//! listing them. A user holds at most one reaction per `key` per message,
//! and adding it again is idempotent.

use std::collections::HashMap;

use ofscp_core::Actor;
use ofscp_core::wire::{Paged, Reaction, ReactionPut};
use ofscp_core::ws::{ReactionAdded, ReactionRemoved};

use super::Messages;
use super::fanout::{Live, Origin};
use super::model::StoredReaction;
use super::ops::MessageError;
use super::pager::{self, CursorKind, PageRequest};
use super::store::Counter;
use super::store_reactions::NewReaction;
use super::validate::Invalid;
use crate::db::DbError;
use crate::groups::Caller;
use crate::groups::access;

/// Longest reaction `key`, in bytes.
pub const MAX_KEY_BYTES: usize = 64;
/// Longest `unicode`, in bytes.
pub const MAX_UNICODE_BYTES: usize = 64;
/// Longest `image` URL, in bytes.
pub const MAX_IMAGE_BYTES: usize = 2048;

const NO_MESSAGE: &str = "no such message";
const MAY_NOT_REACT: &str = "you may not react in this channel";

/// How an add was answered.
#[derive(Debug, Clone, PartialEq)]
pub enum Added {
    /// A new reaction (`201`).
    New(StoredReaction),
    /// The caller already held it (`200`); nothing changed.
    Existing(StoredReaction),
}

/// A reaction `key` (§5.3): a non-empty string of at most
/// [`MAX_KEY_BYTES`] bytes with no control characters. It is a path
/// segment over REST, so it arrives percent-decoded.
pub fn check_key(key: &str) -> Result<(), Invalid> {
    if key.is_empty() || key.len() > MAX_KEY_BYTES || key.chars().any(char::is_control) {
        return Err(Invalid(format!(
            "a reaction key is 1 to {MAX_KEY_BYTES} bytes, with no control characters"
        )));
    }
    Ok(())
}

/// The optional fields of an add (`reaction-put-request.json`): `unicode`
/// short, `image` an `https` URL.
pub fn check_put(put: &ReactionPut) -> Result<(), Invalid> {
    if let Some(u) = &put.unicode
        && (u.is_empty() || u.len() > MAX_UNICODE_BYTES || u.chars().any(char::is_control))
    {
        return Err(Invalid(format!(
            "unicode is 1 to {MAX_UNICODE_BYTES} bytes, with no control characters"
        )));
    }
    if let Some(i) = &put.image {
        let https =
            url::Url::parse(i).is_ok_and(|u| u.scheme() == "https" && u.host_str().is_some());
        if !https || i.len() > MAX_IMAGE_BYTES {
            return Err(Invalid(format!(
                "image must be an https URL of at most {MAX_IMAGE_BYTES} bytes"
            )));
        }
    }
    Ok(())
}

impl Messages {
    /// `PUT …/reactions/{key}` and `reaction.add`.
    #[allow(clippy::too_many_arguments)]
    pub async fn add_reaction(
        &self,
        actor: &Actor,
        group_id: &str,
        channel_id: &str,
        message_id: &str,
        key: &str,
        put: &ReactionPut,
        origin: Option<&Origin>,
    ) -> Result<Added, MessageError> {
        let caller = Caller::Actor(actor.clone());
        let (g, channel) = self.readable(&caller, group_id, channel_id).await?;
        let message = self.existing(channel_id, message_id).await?;
        // A tombstone takes no new reactions (decision 0017).
        if message.is_deleted() {
            return Err(MessageError::NotFound(NO_MESSAGE));
        }
        if !access::may_react(&g.standing, &g.group.policy(), &channel.policy()) {
            return Err(MessageError::Forbidden(MAY_NOT_REACT));
        }
        check_key(key)?;
        check_put(put)?;
        if let Some(r) = self.store.reaction(&message.id, actor, key).await? {
            return Ok(Added::Existing(r));
        }
        let _turn = self.locks.lock(channel_id).await;
        let n = self
            .store
            .take_counter(&message.id, Counter::Reactions)
            .await?
            .ok_or(MessageError::NotFound(NO_MESSAGE))?;
        let new = NewReaction {
            message_id: &message.id,
            channel_id,
            group_id,
            n,
            author: actor,
            key,
            unicode: put.unicode.as_deref(),
            image: put.image.as_deref(),
            now: self.now(),
        };
        let reaction = match self.store.insert_reaction(&new).await {
            Ok(r) => r,
            // Added meanwhile by another process.
            Err(DbError::Conflict(e)) => {
                return match self.store.reaction(&message.id, actor, key).await? {
                    Some(r) => Ok(Added::Existing(r)),
                    None => Err(DbError::Conflict(e).into()),
                };
            }
            Err(e) => return Err(e.into()),
        };
        let live = Live::ReactionAdded(ReactionAdded {
            group_id: message.group_id.clone(),
            channel_id: message.channel_id.clone(),
            reaction: reaction.to_wire(),
        });
        self.fanout
            .deliver(group_id, channel_id, live, origin)
            .await;
        Ok(Added::New(reaction))
    }

    /// `DELETE …/reactions/{key}` and `reaction.remove`. Removing a
    /// reaction the caller does not hold changes nothing and fans out
    /// nothing; on a WebSocket the requester still gets its answer.
    /// Whether one was removed.
    pub async fn remove_reaction(
        &self,
        actor: &Actor,
        group_id: &str,
        channel_id: &str,
        message_id: &str,
        key: &str,
        origin: Option<&Origin>,
    ) -> Result<bool, MessageError> {
        let caller = Caller::Actor(actor.clone());
        self.readable(&caller, group_id, channel_id).await?;
        let message = self.existing(channel_id, message_id).await?;
        check_key(key)?;
        let _turn = self.locks.lock(channel_id).await;
        if !self.store.remove_reaction(&message.id, actor, key).await? {
            return Ok(false);
        }
        let live = Live::ReactionRemoved(ReactionRemoved {
            group_id: message.group_id.clone(),
            channel_id: message.channel_id.clone(),
            message_id: message.id.clone(),
            key: key.to_owned(),
            author: actor.clone(),
        });
        self.fanout
            .deliver(group_id, channel_id, live, origin)
            .await;
        Ok(true)
    }

    /// `GET …/messages/{messageId}/reactions`: one page of the message's
    /// reactions, in the order they were added.
    pub async fn reactions(
        &self,
        caller: &Caller,
        group_id: &str,
        channel_id: &str,
        message_id: &str,
        query: &HashMap<String, String>,
    ) -> Result<Paged<Reaction>, MessageError> {
        let req = PageRequest::from_query(CursorKind::Reactions, query)?;
        self.readable(caller, group_id, channel_id).await?;
        let message = self.existing(channel_id, message_id).await?;
        let store = &self.store;
        let id = &message.id;
        let walked = pager::walk(
            CursorKind::Reactions,
            req,
            message.reaction_seq,
            |ns| async move { store.reactions_at(id, &ns).await },
        )
        .await?;
        Ok(Paged {
            items: walked.items.into_iter().map(|(_, r)| r.to_wire()).collect(),
            page: walked.page,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_and_put_bodies_are_bounded() {
        assert!(check_key("heart").is_ok());
        assert!(check_key("❤️").is_ok());
        for bad in ["", "a\nb", &"k".repeat(MAX_KEY_BYTES + 1)] {
            assert!(check_key(bad).is_err(), "{bad:?}");
        }
        let put = |unicode: Option<&str>, image: Option<&str>| ReactionPut {
            unicode: unicode.map(str::to_owned),
            image: image.map(str::to_owned),
        };
        assert!(check_put(&ReactionPut::default()).is_ok());
        assert!(check_put(&put(Some("❤️"), Some("https://cdn.example/h.png"))).is_ok());
        for bad in [
            put(Some(""), None),
            put(None, Some("http://cdn.example/h.png")),
            put(None, Some("not a url")),
            put(
                None,
                Some(&format!(
                    "https://e.example/{}",
                    "a".repeat(MAX_IMAGE_BYTES)
                )),
            ),
        ] {
            assert!(check_put(&bad).is_err(), "{bad:?}");
        }
    }
}
