//! The console's screens. [`app`] picks one from the session's stage
//! (`logic::flow`): sign-in, the restricted set-up steps, or the console.

mod accounts;
mod admins;
mod audit;
mod common;
mod federation;
mod invites;
mod password;
mod setup;
mod shell;
mod sign_in;
mod style;
mod totp;

use rinch::prelude::*;
use rinch::reactive::Effect;

use crate::logic::flow::{Stage, stage};
use crate::session::{Session, Status};
use common::Loading;
use setup::SetupFlow;
use shell::Console;
use sign_in::SignIn;

/// The top-level screen. Kept separate from the session itself so that
/// refreshing the session (after a password change, say) does not rebuild
/// a screen whose stage hasn't changed.
#[derive(Debug, Clone, PartialEq)]
enum Screen {
    Checking,
    Unreachable(String),
    Stage(Stage),
}

/// The root: checks for an existing session, then shows the right screen.
#[component]
pub fn app() -> NodeHandle {
    let session = create_store(Session::default());
    // Each write asks for a session check; the effect's first run is the
    // check on load. "Try again" sits in a `match` arm that the check
    // replaces, and a task spawned by a handler there would end with that
    // arm; spawned by this component's effect, it lives as long as the app.
    let check = Signal::new(());
    Effect::new(move || {
        check.get();
        spawn_local(session.refresh());
    });
    let screen = derived(move || match session.status.get() {
        Status::Checking => Screen::Checking,
        Status::Unreachable(why) => Screen::Unreachable(why),
        Status::SignedOut => Screen::Stage(Stage::SignIn),
        Status::SignedIn(info) => Screen::Stage(stage(Some(&info))),
    });
    let retry = move || {
        session.status.set(Status::Checking);
        check.set(());
    };
    rsx! {
        div {
            style { {style::CSS} }
            match screen.get() {
                Screen::Checking => div { class: "centered",
                    Loading { caption: "Checking your session…" }
                },
                Screen::Unreachable(why) => div { class: "centered",
                    div { class: "card",
                        Stack { gap: "md",
                            Title { order: 3, "Can't reach the server" }
                            Alert { color: "red", variant: "light", {why} }
                            Button { onclick: retry, "Try again" }
                        }
                    }
                },
                Screen::Stage(Stage::SignIn) => SignIn {},
                Screen::Stage(Stage::ChangePassword | Stage::EnrollTotp) => SetupFlow {},
                Screen::Stage(Stage::Console) => Console {},
            }
        }
    }
}
