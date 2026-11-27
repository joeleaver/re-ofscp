//! Replaying a channel's timeline after a resume cursor (§7.1 "Resuming
//! after a disconnect"; decision 0017).
//!
//! A timeline position is taken by every create, edit and delete, and a
//! live event carries its position as `cursor` (`t{n}`, the space REST
//! history pages in). A `subscribe` with `since: {channel: cursor}`
//! replays positions after the cursor, oldest first: a create as
//! `message.created`, an edit as `message.updated` and a delete as
//! `message.deleted`, each with its own cursor. An edit or create replays
//! the message as it stands now, so an edit made after a disconnect is
//! not shown twice in two states. Positions nothing landed on (a write
//! that failed after taking its position) are skipped.
//!
//! The resume is truncated, and the client backfills through history
//! (§7.2), when the cursor is not a timeline cursor of this channel, names
//! a position past the end, or leaves more than [`MAX_REPLAY`] positions
//! to replay. Reactions and typing are not timeline events and are never
//! replayed.

use std::collections::HashMap;
use std::sync::Arc;

use ofscp_core::Actor;

use super::fanout::Live;
use super::model::StoredMessage;
use super::ops::{MessageError, channel_message, message_deleted};
use super::pager::{self, CursorKind};
use super::store::{StoredEvent, event_kind};
use super::{Messages, log};
use crate::groups::Caller;
use crate::ws::protocol;
use crate::ws::seams::{Replay, ReplayFuture, SeamError, Timeline};

/// Most timeline positions one resume replays.
pub const MAX_REPLAY: i64 = 200;

/// The provider's [`Timeline`], over its message log.
#[derive(Debug, Clone)]
pub struct MessageTimeline {
    messages: Arc<Messages>,
}

impl MessageTimeline {
    /// Replays from `messages`.
    pub fn new(messages: Arc<Messages>) -> Self {
        Self { messages }
    }
}

impl Timeline for MessageTimeline {
    fn replay<'a>(&'a self, actor: &'a Actor, topic: &'a str, since: &'a str) -> ReplayFuture<'a> {
        Box::pin(async move {
            self.messages
                .replay(actor, topic, since)
                .await
                .map_err(|e| SeamError(e.to_string()))
        })
    }
}

fn truncated() -> Replay {
    Replay {
        events: Vec::new(),
        truncated: true,
    }
}

impl Messages {
    /// The events of channel `channel_id` after `since`, as `actor` may
    /// see them now. A channel the actor cannot read replays nothing and
    /// is truncated: the subscribe that asked was granted a moment ago,
    /// and the access re-check ends it.
    pub async fn replay(
        &self,
        actor: &Actor,
        channel_id: &str,
        since: &str,
    ) -> Result<Replay, MessageError> {
        let Some(after) = pager::decode_cursor(CursorKind::Timeline, since) else {
            return Ok(truncated());
        };
        let Some(group_id) = self.groups.channel_group(channel_id).await? else {
            return Ok(truncated());
        };
        let caller = Caller::Actor(actor.clone());
        match self.readable(&caller, &group_id, channel_id).await {
            Ok(_) => {}
            Err(MessageError::NotFound(_) | MessageError::Forbidden(_)) => return Ok(truncated()),
            Err(e) => return Err(e),
        }
        let last = log::read(self.store.db(), channel_id).await?.last();
        if after > last || last - after > MAX_REPLAY {
            return Ok(truncated());
        }
        let positions: Vec<i64> = (after + 1..=last).collect();
        if positions.is_empty() {
            return Ok(Replay::default());
        }
        let created: HashMap<i64, StoredMessage> = self
            .store
            .at_positions(channel_id, &positions)
            .await?
            .into_iter()
            .collect();
        let events: Vec<StoredEvent> = self.store.events_at(channel_id, &positions).await?;
        let mut ids: Vec<String> = events.iter().map(|e| e.message_id.clone()).collect();
        ids.sort();
        ids.dedup();
        let current: HashMap<String, StoredMessage> = self
            .store
            .by_ids(&ids)
            .await?
            .into_iter()
            .map(|m| (m.id.as_str().to_owned(), m))
            .collect();
        let events: HashMap<i64, StoredEvent> = events.into_iter().map(|e| (e.seq, e)).collect();
        let now = self.now();
        let mut out = Vec::new();
        for pos in positions {
            // Both lookups read the messages as they stand now.
            let live = if let Some(m) = created.get(&pos) {
                Some(Live::Created(channel_message(m, Some(pos))))
            } else if let Some(e) = events.get(&pos) {
                current
                    .get(e.message_id.as_str())
                    .and_then(|m| replayed_event(e, m, pos))
            } else {
                None
            };
            if let Some(live) = live {
                out.push(protocol::event(live.kind(), None, live.data(), now));
            }
        }
        Ok(Replay {
            events: out,
            truncated: false,
        })
    }
}

/// What an edit or delete at `pos` replays as, given the message as it
/// now stands. An event of a kind this version does not write replays as
/// nothing.
fn replayed_event(e: &StoredEvent, m: &StoredMessage, pos: i64) -> Option<Live> {
    match e.kind.as_str() {
        event_kind::UPDATED => Some(Live::Updated(channel_message(m, Some(pos)))),
        event_kind::DELETED => Some(Live::Deleted(message_deleted(m, Some(pos)))),
        _ => None,
    }
}
