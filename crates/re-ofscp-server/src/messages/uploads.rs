//! What messages need from media uploads (§5.8): whether an attachment is
//! one this provider hosts, and its stored record.
//!
//! The upload endpoints (`POST /api/media`) are not built yet, so the
//! provider runs [`NoUploads`]: it has issued no uploads, so it hosts no
//! attachment. Under §5.8 that refuses every attachment from a local
//! author (local users must upload to this provider) and leaves remote
//! authors' attachments to the checks for attachments it does not host.
//! The media module replaces it through `AppStateBuilder::uploads`.

use std::future::Future;
use std::pin::Pin;

use ofscp_core::Actor;
use ofscp_core::wire::Attachment;

use crate::db::DbError;

/// An upload this provider issued.
#[derive(Debug, Clone, PartialEq)]
pub struct HostedUpload {
    /// Who uploaded it.
    pub uploader: Actor,
    /// Its target is this provider (a *local upload*, §5.8 *Target*).
    pub local_target: bool,
    /// It can be referenced (a pre-signed upload has completed).
    pub complete: bool,
    /// The provider's own record of it, thumbnail included: what a message
    /// stores in place of the client's copy.
    pub attachment: Attachment,
}

/// Boxed future returned by [`Uploads::hosted`].
pub type HostedFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Option<HostedUpload>, DbError>> + Send + 'a>>;

/// The provider's uploads.
pub trait Uploads: Send + Sync {
    /// The upload with attachment id `id`, if this provider issued it.
    fn hosted<'a>(&'a self, id: &'a str) -> HostedFuture<'a>;
}

/// A provider that has issued no uploads.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoUploads;

impl Uploads for NoUploads {
    fn hosted<'a>(&'a self, _id: &'a str) -> HostedFuture<'a> {
        Box::pin(async { Ok(None) })
    }
}
