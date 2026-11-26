//! The notification feed and its settings (spec §10.1, §10.2).

use serde::{Deserialize, Serialize};

use super::{Timestamp, open_enum};
use crate::{Actor, LocalId};

open_enum! {
    /// Why a notification was made (§10.1).
    pub enum NotificationKind {
        /// You were mentioned.
        Mention = "mention",
        /// Someone replied to you.
        Reply = "reply",
        /// A new message, where your settings ask for all of them.
        Message = "message",
    }
}

/// An entry in your notification feed, for a channel on your home provider
/// (§10.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Notification {
    /// The notification's local id.
    pub id: LocalId,
    /// Why it was made.
    #[serde(rename = "type")]
    pub kind: NotificationKind,
    /// The message that caused it.
    pub source_message_id: LocalId,
    /// That message's channel.
    pub channel_id: LocalId,
    /// That channel's group.
    pub group_id: LocalId,
    /// Who wrote the message.
    pub author: Actor,
    /// When.
    pub created_at: Timestamp,
    /// When you saw it in a list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seen_at: Option<Timestamp>,
    /// When you read it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_at: Option<Timestamp>,
}

/// Unread notifications, by kind.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationCounts {
    /// Unread mentions.
    pub mention: u64,
    /// Unread replies.
    pub reply: u64,
    /// Unread messages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<u64>,
}

/// `GET /api/me/notifications` (§10.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotificationsResponse {
    /// Newest first.
    pub items: Vec<Notification>,
    /// What is still unread.
    pub counts: NotificationCounts,
    /// The cursor for the next page, if there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// The answer to `POST /api/me/notifications/seen` or `.../read` (§10.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationsMarkResponse {
    /// How many entries changed.
    pub affected: u64,
    /// What is still unread.
    pub counts: NotificationCounts,
}

open_enum! {
    /// What a notification setting applies to (§10.1).
    pub enum NotificationScope {
        /// A whole group.
        Group = "group",
        /// One channel.
        Channel = "channel",
    }
}

open_enum! {
    /// Which messages notify you (§10.1).
    pub enum NotificationMode {
        /// Every message.
        All = "all",
        /// Mentions and replies.
        Mentions = "mentions",
        /// None.
        None = "none",
    }
}

/// One notification setting (§10.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotificationSetting {
    /// A group or a channel.
    pub scope_type: NotificationScope,
    /// Its local id.
    pub scope_id: LocalId,
    /// Which messages notify you there.
    pub mode: NotificationMode,
}

/// `GET /api/me/notification-settings` (§10.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationSettingsResponse {
    /// Your settings.
    pub prefs: Vec<NotificationSetting>,
}
