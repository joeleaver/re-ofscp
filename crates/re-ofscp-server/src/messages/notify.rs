//! The seam the notification feed (§10.1) plugs into: what the message
//! operations hand on once a new message is committed.
//!
//! `Messages::create` runs the returned future in a task of its own and
//! waits for it, outside the channel's lock: a client that drops its
//! request mid-way still leaves every entry made, and a client that waits
//! sees its message's entries in place when the create answers. A failure
//! there is the notifier's to log; the message stands either way.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use ofscp_core::Actor;

use super::model::StoredMessage;

/// Boxed future returned by [`Notify::message_created`].
pub type NotifyFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// Told of each new channel message.
pub trait Notify: Send + Sync {
    /// `message` was created (not edited) in its channel; it replies to a
    /// message by `parent_author`, if any.
    fn message_created(
        self: Arc<Self>,
        message: StoredMessage,
        parent_author: Option<Actor>,
    ) -> NotifyFuture;
}
