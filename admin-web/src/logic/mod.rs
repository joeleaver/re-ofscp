//! The console's logic that isn't UI: building API requests, reading
//! problem responses, role gating, form validation, the restricted-session
//! flow, what an answer does to the session, time windows, the
//! federation policy form and the enrollment QR code.
//!
//! Nothing here touches the DOM, the network or a rinch signal, so it
//! compiles and is unit-tested natively (`cargo test` in `admin-web`),
//! while the same code runs in the wasm build.

pub mod federation;
pub mod flow;
pub mod forms;
pub mod problem;
pub mod qr;
pub mod request;
pub mod roles;
pub mod time;
pub mod transition;

/// A form value the console refuses to send, with a message for the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invalid(pub String);

impl Invalid {
    /// An error with `message`.
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl std::fmt::Display for Invalid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
