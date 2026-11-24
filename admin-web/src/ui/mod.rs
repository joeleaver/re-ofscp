//! The console's screens. [`app`] picks one from the session's stage
//! (`logic::flow`): sign-in, the restricted set-up steps, or the console.

mod accounts;
mod admins;
mod audit;
mod common;
mod field;
mod invites;
mod password;
mod setup;
mod shell;
mod sign_in;
mod style;
mod tasks;
mod totp;

use rinch::prelude::*;

use crate::logic::flow::{Stage, stage};
use crate::session::{Session, Status};
use common::Loading;
use setup::SetupFlow;
use shell::Console;
use sign_in::SignIn;
use tasks::Tasks;

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
    let tasks = Tasks::here();
    tasks.spawn(session.refresh());
    let screen = derived(move || match session.status.get() {
        Status::Checking => Screen::Checking,
        Status::Unreachable(why) => Screen::Unreachable(why),
        Status::SignedOut => Screen::Stage(Stage::SignIn),
        Status::SignedIn(info) => Screen::Stage(stage(Some(&info))),
    });
    let retry = move || {
        session.status.set(Status::Checking);
        tasks.spawn(session.refresh());
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
