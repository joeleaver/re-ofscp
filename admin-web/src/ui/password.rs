//! Changing one's own password: in the set-up flow (when another admin
//! chose it) and from the console.

use rinch::prelude::*;

use super::common::{ErrorAlert, SuccessAlert, failure};
use super::field::{Credential, CredentialInput};
use super::tasks::Tasks;
use crate::logic::{forms, request};
use crate::session::Session;

/// The password form. On success it clears itself, refreshes the session
/// (the change ends the admin's other sessions and may lift a
/// restriction) and, if `done_message` isn't empty, shows it.
#[component]
pub fn PasswordForm(done_message: String) -> NodeHandle {
    let session = use_store::<Session>();
    let tasks = Tasks::here();
    let current = Signal::new(String::new());
    let new = Signal::new(String::new());
    let confirm = Signal::new(String::new());
    let busy = Signal::new(false);
    let error = Signal::new(None::<String>);
    let done = Signal::new(None::<String>);

    let submit = move || {
        if busy.get() {
            return;
        }
        done.set(None);
        let req = match forms::password_change(&current.get(), &new.get(), &confirm.get()) {
            Ok(req) => req,
            Err(e) => return error.set(Some(e.0)),
        };
        let call = match request::change_password(&req) {
            Ok(call) => call,
            Err(e) => return error.set(Some(e.message())),
        };
        error.set(None);
        busy.set(true);
        let message = done_message.clone();
        tasks.spawn(async move {
            match session.call_empty(call).await {
                Ok(()) => {
                    current.set(String::new());
                    new.set(String::new());
                    confirm.set(String::new());
                    busy.set(false);
                    if !message.is_empty() {
                        done.set(Some(message));
                    }
                    // Last: in the set-up flow this moves to the next step.
                    session.refresh().await;
                }
                Err(e) => {
                    if let Some(m) = failure(&e) {
                        busy.set(false);
                        error.set(Some(m));
                    }
                }
            }
        });
    };

    rsx! {
        Stack { gap: "sm",
            CredentialInput {
                label: "Current password",
                kind: Credential::CurrentPassword,
                value: current,
                onsubmit: submit.clone(),
            }
            CredentialInput {
                label: "New password",
                description: "At least 8 characters.",
                kind: Credential::NewPassword,
                value: new,
                onsubmit: submit.clone(),
            }
            CredentialInput {
                label: "Repeat the new password",
                kind: Credential::NewPassword,
                value: confirm,
                onsubmit: submit.clone(),
            }
            ErrorAlert { message: error }
            SuccessAlert { message: done }
            Group {
                Button { loading: {|| busy.get()}, onclick: submit.clone(), "Change password" }
            }
        }
    }
}
