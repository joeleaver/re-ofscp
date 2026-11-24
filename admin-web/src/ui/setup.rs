//! The restricted session's set-up steps: a new password (if another admin
//! chose it), then TOTP enrollment. Nothing else is open until both are
//! done (docs/decisions/0005, "Restricted sessions").

use rinch::prelude::*;

use super::common::ErrorAlert;
use super::password::PasswordForm;
use super::totp::TotpEnroll;
use crate::logic::flow::{Stage, remaining_steps, stage};
use crate::logic::roles::role_label;
use crate::session::Session;

/// Who is signed in, and as what.
fn who(session: Session) -> String {
    session
        .info()
        .map(|i| format!("Signed in as {} ({})", i.username, role_label(i.role)))
        .unwrap_or_default()
}

/// How many set-up steps are left.
fn steps(session: Session) -> String {
    session
        .info()
        .map_or(String::new(), |i| match remaining_steps(&i) {
            1 => "One step left before the console opens.".to_owned(),
            n => format!("{n} steps left before the console opens."),
        })
}

/// The set-up screen for a restricted session.
#[component]
pub fn SetupFlow() -> NodeHandle {
    let session = use_store::<Session>();
    let current = derived(move || stage(session.info().as_ref()));
    let signing_out = Signal::new(false);
    let error = Signal::new(None::<String>);
    let sign_out = move || {
        signing_out.set(true);
        spawn_local(async move {
            if let Err(e) = session.sign_out().await {
                signing_out.set(false);
                error.set(Some(e.message()));
            }
        });
    };

    rsx! {
        div { class: "centered",
            div { class: "card wide",
                Stack { gap: "md",
                    Group { justify: "space-between",
                        Text { size: "sm", color: "dimmed", {move || who(session)} }
                        Button {
                            variant: "subtle",
                            size: "xs",
                            loading: {|| signing_out.get()},
                            onclick: sign_out,
                            "Sign out"
                        }
                    }
                    ErrorAlert { message: error }
                    match current.get() {
                        Stage::ChangePassword => Stack { gap: "md",
                            Title { order: 3, "Choose your own password" }
                            Text { size: "sm",
                                "Another admin set your password. Replace it with one only you know."
                            }
                            Text { size: "sm", color: "dimmed", {move || steps(session)} }
                            PasswordForm {}
                        },
                        Stage::EnrollTotp => Stack { gap: "md",
                            Title { order: 3, "Set up two-factor sign-in" }
                            Text { size: "sm",
                                "Every sign-in to the console needs a code from an authenticator app."
                            }
                            Text { size: "sm", color: "dimmed", {move || steps(session)} }
                            TotpEnroll {}
                        },
                        Stage::SignIn | Stage::Console => "",
                    }
                }
            }
        }
    }
}
