//! Enrolling a TOTP authenticator: the QR code and secret, then a code to
//! confirm it.

use re_ofscp_types::admin::TotpEnrollment;
use rinch::prelude::*;
use rinch::reactive::Effect;

use super::common::{CodeInput, CopyButton, ErrorAlert, Load, Loading, failure};
use crate::logic::{forms, qr, request};
use crate::session::Session;

/// A pending enrollment, ready to show.
#[derive(Debug, Clone, PartialEq)]
struct Shown {
    secret: String,
    uri: String,
    /// The QR code as an image URL, or why it couldn't be drawn (the
    /// secret can still be typed in).
    qr: Result<String, String>,
}

impl Shown {
    fn new(e: TotpEnrollment) -> Self {
        let qr = qr::data_url(&e.otpauth_uri).map_err(|i| i.0);
        Self {
            secret: e.secret,
            uri: e.otpauth_uri,
            qr,
        }
    }
}

/// Start (or restart) enrollment: the server makes a new pending secret,
/// replacing any earlier one that was never confirmed.
async fn enroll(session: Session, state: Signal<Load<Shown>>) {
    match session.call::<TotpEnrollment>(request::totp_enroll()).await {
        Ok(e) => state.set(Load::Ready(Shown::new(e))),
        Err(e) => {
            if let Some(m) = failure(&e) {
                state.set(Load::Failed(m));
            }
        }
    }
}

/// The enrollment step.
#[component]
pub fn TotpEnroll() -> NodeHandle {
    let session = use_store::<Session>();
    let state = Signal::new(Load::<Shown>::Loading);
    let typed = Signal::new(String::new());
    let busy = Signal::new(false);
    let error = Signal::new(None::<String>);
    // Each write starts enrollment over (the effect's first run is the
    // first enrollment), aborting one still in flight. "Try again" and
    // "Start over" sit in `match` arms that the restart replaces, so a task
    // their handlers spawned would end with the arm; spawned by this
    // component's effect, it belongs to the step.
    let restart = Signal::new(());
    let mut enrolling: Option<TaskHandle> = None;
    Effect::new(move || {
        restart.get();
        // Only the request signal is tracked. The writes below re-render
        // what shows the result, and those renders' reads must not become
        // this effect's dependencies (they made each request go out twice).
        untracked(|| {
            if let Some(previous) = enrolling.take() {
                previous.abort();
            }
            state.set(Load::Loading);
            enrolling = Some(spawn_local(enroll(session, state)));
        });
    });

    let confirm = move || {
        if busy.get() {
            return;
        }
        let req = match forms::totp_confirm(&typed.get()) {
            Ok(req) => req,
            Err(e) => return error.set(Some(e.0)),
        };
        let call = match request::totp_confirm(&req) {
            Ok(call) => call,
            Err(e) => return error.set(Some(e.message())),
        };
        error.set(None);
        busy.set(true);
        // Written in the `Ready` arm, so this task belongs to that arm: it
        // ends only if the arm goes, which takes a new secret (and "Start
        // over" is disabled while `busy`). Confirming a secret no longer
        // shown would be wrong anyway.
        spawn_local(async move {
            match session.call_empty(call).await {
                // The session is now full: refreshing it opens the console.
                Ok(()) => session.refresh().await,
                Err(e) => {
                    if let Some(m) = failure(&e) {
                        typed.set(String::new());
                        busy.set(false);
                        error.set(Some(m));
                    }
                }
            }
        });
    };

    rsx! {
        Stack { gap: "md",
            match state.get() {
                Load::Loading => Loading { caption: "Creating your secret…" },
                Load::Failed(why) => Stack { gap: "sm",
                    Alert { color: "red", variant: "light", {why} }
                    Group { Button { onclick: move || restart.set(()), "Try again" } }
                },
                Load::Ready(shown) => Stack { gap: "md",
                    Text { size: "sm",
                        "Scan this code with an authenticator app (any app that supports TOTP), or enter the secret by hand."
                    }
                    match shown.qr.clone() {
                        Ok(url) => img { class: "qr", src: url, alt: "QR code for your authenticator app" },
                        Err(why) => Alert { color: "orange", variant: "light", {why} },
                    }
                    div { class: "secret",
                        Text { size: "sm", weight: "600", "Secret (shown only now)" }
                        div { class: "secret-value",
                            code { {shown.secret.clone()} }
                            CopyButton { text: shown.secret.clone() }
                        }
                        div { class: "secret-value",
                            code { {shown.uri.clone()} }
                            CopyButton { text: shown.uri.clone() }
                        }
                    }
                    CodeInput {
                        label: "Code from your authenticator",
                        value: typed,
                        onsubmit: confirm,
                    }
                    ErrorAlert { message: error }
                    Group { gap: "sm",
                        Button { loading: {|| busy.get()}, onclick: confirm, "Confirm and finish" }
                        Button {
                            variant: "subtle",
                            disabled: {|| busy.get()},
                            onclick: move || restart.set(()),
                            "Start over with a new secret"
                        }
                    }
                },
            }
        }
    }
}
