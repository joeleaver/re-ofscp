//! One connection's typing indicators (§7.1 *Typing indicators*).
//!
//! A `typing.start` holds for [`TYPING_EXPIRY`] unless refreshed by
//! another; the command worker wakes at the earliest deadline and emits
//! `stop` for each that passed. A `typing.stop` emits `stop` only for a
//! channel that has an active `start`. When the connection ends its worker
//! is dropped, and [`Typing`]'s `Drop` emits `stop` for every channel
//! still active, so a dropped connection never leaves an indicator stuck.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use ofscp_core::ws::TypingState;
use ofscp_core::{Actor, LocalId};
use tokio::time::Instant;

use crate::messages::Messages;

/// How long a `typing.start` holds without a refresh (§7.1: RECOMMENDED
/// 6 seconds).
pub const TYPING_EXPIRY: Duration = Duration::from_secs(6);

/// Where one connection's actor is typing.
pub struct Typing {
    messages: Arc<Messages>,
    actor: Actor,
    /// Channel → (its group, when the `start` expires).
    active: HashMap<LocalId, (String, Instant)>,
}

impl Typing {
    /// No indicator yet, for `actor`, fanned out through `messages`.
    pub fn new(messages: Arc<Messages>, actor: Actor) -> Self {
        Self {
            messages,
            actor,
            active: HashMap::new(),
        }
    }

    /// Start, or refresh, the indicator in `channel_id` of `group_id`.
    pub async fn start(&mut self, group_id: String, channel_id: &LocalId) {
        self.messages
            .typing(&group_id, channel_id, &self.actor, TypingState::Start)
            .await;
        self.active.insert(
            channel_id.clone(),
            (group_id, Instant::now() + TYPING_EXPIRY),
        );
    }

    /// Stop the indicator in `channel_id`, if one is active.
    pub async fn stop(&mut self, channel_id: &LocalId) {
        if let Some((group_id, _)) = self.active.remove(channel_id) {
            self.messages
                .typing(&group_id, channel_id, &self.actor, TypingState::Stop)
                .await;
        }
    }

    /// When the next active indicator expires.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.active.values().map(|(_, at)| *at).min()
    }

    /// Stop every indicator whose `start` expired by `now`.
    pub async fn expire(&mut self, now: Instant) {
        let due: Vec<LocalId> = self
            .active
            .iter()
            .filter(|(_, (_, at))| *at <= now)
            .map(|(c, _)| c.clone())
            .collect();
        for channel_id in due {
            self.stop(&channel_id).await;
        }
    }
}

impl Drop for Typing {
    fn drop(&mut self) {
        if self.active.is_empty() {
            return;
        }
        // The runtime is gone only at shutdown, when no one is listening.
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let (messages, actor) = (self.messages.clone(), self.actor.clone());
        let active = std::mem::take(&mut self.active);
        runtime.spawn(async move {
            for (channel_id, (group_id, _)) in active {
                messages
                    .typing(&group_id, &channel_id, &actor, TypingState::Stop)
                    .await;
            }
        });
    }
}
