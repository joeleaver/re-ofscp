//! Sign-in: username, password and, once enrolled, the authenticator code.

use re_ofscp_types::admin::AdminSessionInfo;
use rinch::prelude::*;

use super::common::{CodeInput, ErrorAlert};
use super::tasks::Tasks;
use crate::logic::{forms, request};
use crate::session::Session;

/// The sign-in screen.
#[component]
pub fn SignIn() -> NodeHandle {
    let session = use_store::<Session>();
    let tasks = Tasks::here();
    let username = Signal::new(String::new());
    let password = Signal::new(String::new());
    let code = Signal::new(String::new());
    let busy = Signal::new(false);
    let error = Signal::new(None::<String>);

    let submit = move || {
        if busy.get() {
            return;
        }
        let req = match forms::login(&username.get(), &password.get(), &code.get()) {
            Ok(req) => req,
            Err(e) => return error.set(Some(e.0)),
        };
        let call = match request::login(&req) {
            Ok(call) => call,
            Err(e) => return error.set(Some(e.message())),
        };
        // The previous notice ("You're signed out.") has been read.
        session.notice.set(None);
        error.set(None);
        busy.set(true);
        tasks.spawn(async move {
            match session.call::<AdminSessionInfo>(call).await {
                Ok(info) => {
                    // Clear the form first: signing in replaces this screen.
                    password.set(String::new());
                    code.set(String::new());
                    busy.set(false);
                    session.signed_in(info);
                }
                Err(e) => {
                    code.set(String::new());
                    busy.set(false);
                    error.set(Some(e.message()));
                }
            }
        });
    };

    rsx! {
        div { class: "centered",
            div { class: "card",
                Stack { gap: "md",
                    Title { order: 2, "re-ofscp admin" }
                    Text { size: "sm", color: "dimmed", "Sign in to manage this provider." }
                    if let Some(n) = session.notice.get() {
                        Alert { color: "blue", variant: "light", {n} }
                    }
                    TextInput {
                        label: "Username",
                        value_fn: move || username.get(),
                        oninput: move |v: String| username.set(v),
                        onsubmit: submit,
                        spellcheck: false,
                    }
                    TextInput {
                        label: "Password",
                        input_type: "password",
                        value_fn: move || password.get(),
                        oninput: move |v: String| password.set(v),
                        onsubmit: submit,
                    }
                    CodeInput {
                        label: "Authenticator code",
                        value: code,
                        onsubmit: submit,
                    }
                    Text { size: "xs", color: "dimmed",
                        "Leave the code empty if you haven't set up an authenticator yet; you'll be asked to next."
                    }
                    ErrorAlert { message: error }
                    Button { full_width: true, loading: {|| busy.get()}, onclick: submit, "Sign in" }
                }
            }
        }
    }
}
