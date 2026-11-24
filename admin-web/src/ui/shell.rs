//! The console: navigation gated by role, who's signed in, sign-out, and
//! the current section.

use re_ofscp_types::admin::AdminRole;
use rinch::prelude::*;

use super::accounts::AccountsScreen;
use super::admins::AdminsScreen;
use super::audit::AuditScreen;
use super::common::ErrorAlert;
use super::invites::InvitesScreen;
use super::password::PasswordForm;
use super::tasks::Tasks;
use crate::logic::roles::{SECTIONS, Section, role_label, unavailable_reason};
use crate::session::Session;

/// The signed-in admin's role. The console is only shown to a signed-in
/// admin; should the session vanish mid-render, the least role is the
/// safe answer.
pub fn current_role(session: Session) -> AdminRole {
    session.info().map_or(AdminRole::ReadOnly, |i| i.role)
}

/// The console.
#[component]
pub fn Console() -> NodeHandle {
    let session = use_store::<Session>();
    let tasks = Tasks::here();
    let section = Signal::new(Section::default());
    let signing_out = Signal::new(false);
    let error = Signal::new(None::<String>);
    let sign_out = move || {
        signing_out.set(true);
        tasks.spawn(async move {
            if let Err(e) = session.sign_out().await {
                signing_out.set(false);
                error.set(Some(e.message()));
            }
        });
    };
    let nav_items: Vec<NodeHandle> = SECTIONS
        .iter()
        .map(|&s| {
            rsx! {
                button {
                    class: {move || {
                        if !s.open_to(current_role(session)) {
                            "nav-item unavailable"
                        } else if section.get() == s {
                            "nav-item active"
                        } else {
                            "nav-item"
                        }
                    }},
                    aria-disabled: {move || (!s.open_to(current_role(session))).to_string()},
                    onclick: move || {
                        if s.open_to(current_role(session)) {
                            section.set(s);
                        }
                    },
                    {s.label()}
                    span { class: "hint",
                        {move || {
                            s.gate()
                                .and_then(|a| unavailable_reason(current_role(session), a))
                                .unwrap_or_default()
                        }}
                    }
                }
            }
        })
        .collect();

    rsx! {
        div { class: "shell",
            nav { class: "sidebar",
                div { class: "brand", "re-ofscp admin" }
                {nav_items}
            }
            div { class: "main",
                div { class: "topbar",
                    Text { size: "sm",
                        {|| session.info().map(|i| format!("Signed in as {}", i.username)).unwrap_or_default()}
                    }
                    Badge { variant: "light", {|| role_label(current_role(session))} }
                    Button {
                        variant: "default",
                        size: "xs",
                        loading: {|| signing_out.get()},
                        onclick: sign_out,
                        "Sign out"
                    }
                }
                div { class: "content",
                    ErrorAlert { message: error }
                    match section.get() {
                        Section::Accounts => AccountsScreen {},
                        Section::Invites => InvitesScreen {},
                        Section::Admins => AdminsScreen {},
                        Section::Audit => AuditScreen {},
                        Section::Profile => div { class: "panel",
                            Title { order: 3, "Change your password" }
                            Text { size: "sm", color: "dimmed",
                                "Changing it signs you out everywhere else."
                            }
                            PasswordForm { done_message: "Your password is changed." }
                        },
                    }
                }
            }
        }
    }
}
