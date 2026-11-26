//! What the WebSocket layer needs from other subsystems, as traits with
//! conservative defaults until those subsystems land:
//!
//! * [`TopicAuthorizer`]: effective read access to a channel (§11.3,
//!   security requirement 5). The provider runs
//!   [`super::channels::GroupTopics`], over the groups module; [`NoTopics`]
//!   (nothing is readable) serves tests without a database.
//! * [`Timeline`]: replaying a channel's timeline after a resume cursor
//!   (§7.1 "Resuming after a disconnect"), from the message log. Default
//!   [`NoTimeline`]: every resume is truncated, so clients backfill
//!   through REST history.

use std::future::Future;
use std::pin::Pin;

use re_ofscp_types::Actor;

/// Whether an actor may read a topic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopicAccess {
    /// Effective read access holds now.
    Readable,
    /// It does not, or the topic does not exist; the two are not told
    /// apart, so a subscribe cannot probe for a private channel.
    Unreadable,
}

/// An authorizer or timeline could not answer (its store is down).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct SeamError(pub String);

/// Boxed future returned by [`TopicAuthorizer::check`].
pub type AccessFuture<'a> =
    Pin<Box<dyn Future<Output = Result<TopicAccess, SeamError>> + Send + 'a>>;

/// Decides effective read access (§11.3) to subscription topics (channel
/// ids). Checked at subscribe time and again whenever
/// [`super::Hub::access_changed`] names the topic or actor, and on the
/// periodic sweep; a topic that stops being readable ends with an
/// unsolicited `unsubscribed {reason: "access_revoked"}`.
pub trait TopicAuthorizer: Send + Sync {
    /// Whether `actor` (canonical `(handle, domain)`, possibly remote) may
    /// read `topic` now.
    fn check<'a>(&'a self, actor: &'a Actor, topic: &'a str) -> AccessFuture<'a>;
}

/// No topics at all: every subscribe is answered `not_found`.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoTopics;

impl TopicAuthorizer for NoTopics {
    fn check<'a>(&'a self, _actor: &'a Actor, _topic: &'a str) -> AccessFuture<'a> {
        Box::pin(async { Ok(TopicAccess::Unreadable) })
    }
}

/// What a resume can replay.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Replay {
    /// The timeline events strictly after the cursor, oldest first,
    /// serialized as server events (each carrying its `cursor`).
    pub events: Vec<String>,
    /// The gap exceeds what the provider will replay (or the cursor is not
    /// one it knows): the `subscribed` ack lists the topic in `truncated`,
    /// and the client backfills through REST history (§7.2).
    pub truncated: bool,
}

/// Boxed future returned by [`Timeline::replay`].
pub type ReplayFuture<'a> = Pin<Box<dyn Future<Output = Result<Replay, SeamError>> + Send + 'a>>;

/// The channel timelines, for resuming after a disconnect. Cursors are in
/// the same space as REST history (§7.2).
pub trait Timeline: Send + Sync {
    /// The events of `topic` after `since`, as `actor` may see them.
    fn replay<'a>(&'a self, actor: &'a Actor, topic: &'a str, since: &'a str) -> ReplayFuture<'a>;
}

/// No message log yet: every resume is truncated.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoTimeline;

impl Timeline for NoTimeline {
    fn replay<'a>(
        &'a self,
        _actor: &'a Actor,
        _topic: &'a str,
        _since: &'a str,
    ) -> ReplayFuture<'a> {
        Box::pin(async {
            Ok(Replay {
                events: Vec::new(),
                truncated: true,
            })
        })
    }
}
