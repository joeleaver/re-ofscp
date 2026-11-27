//! The seam the notification feed (§10.1) plugs into: what the message
//! operations hand on once a new message is committed.
//!
//! `Messages::create` runs the returned future in a task of its own and
//! waits for it, outside the channel's lock: a client that drops its
//! request mid-way still leaves every entry made, and a client that waits
//! sees what the future made in place when the create answers. Work whose
//! size the author does not control (the feed's `message` entries for
//! `all` settings) the notifier leaves out of the future: the future only
//! queues it, and waits only while that bounded queue is full
//! (back-pressure, docs/decisions/0023). A failure is the notifier's to
//! log; the message stands either way.

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
