//! The audit log: one time window (the last day by default, at most 31
//! days) and an optional admin filter.

use re_ofscp_types::admin::AuditList;
use rinch::prelude::*;

use super::common::{ErrorAlert, Load, Loading, StatusBadge, failure};
use super::tasks::Tasks;
use crate::browser;
use crate::logic::forms;
use crate::logic::problem::ApiError;
use crate::logic::request::{self, AuditFilter};
use crate::logic::time::{audit_window, default_window, display};
use crate::session::Session;

/// What to show for a failed listing. The server answers 400 when the
/// window holds more entries than one listing returns.
fn listing_failure(e: &ApiError) -> Option<String> {
    let m = failure(e)?;
    Some(if e.status() == Some(400) {
        format!("{m}. Narrow the window, or filter by one admin.")
    } else {
        m
    })
}

/// Fetch the entries matching `filter` into `list`.
fn load(tasks: Tasks, session: Session, filter: AuditFilter, list: Signal<Load<AuditList>>) {
    list.set(Load::Loading);
    tasks.spawn(async move {
        match session.call::<AuditList>(request::audit(&filter)).await {
            Ok(found) => list.set(Load::Ready(found)),
            Err(e) => {
                if let Some(m) = listing_failure(&e) {
                    list.set(Load::Failed(m));
                }
            }
        }
    });
}

/// A labelled UTC `datetime-local` field.
fn time_field(__scope: &mut RenderScope, label: &'static str, value: Signal<String>) -> NodeHandle {
    rsx! {
        div { class: "grow",
            label { class: "field-label", {label} }
            input {
                class: "native-input",
                r#type: "datetime-local",
                aria-label: label,
                value: {move || value.get()},
                oninput: move |v: String| value.set(v),
            }
        }
    }
}

/// The audit-log screen.
#[component]
pub fn AuditScreen() -> NodeHandle {
    let session = use_store::<Session>();
    let tasks = Tasks::here();
    let (start, end) = default_window(browser::now_unix());
    let since = Signal::new(start);
    let until = Signal::new(end);
    let admin = Signal::new(String::new());
    let form_error = Signal::new(None::<String>);
    let list = Signal::new(Load::<AuditList>::Loading);

    let run = move || {
        let filter = forms::audit_admin(&admin.get())
            .and_then(|who| audit_window(&since.get(), &until.get(), who));
        match filter {
            Ok(filter) => {
                form_error.set(None);
                load(tasks, session, filter, list);
            }
            Err(e) => form_error.set(Some(e.0)),
        }
    };
    let last_day = move || {
        let (start, end) = default_window(browser::now_unix());
        since.set(start);
        until.set(end);
        run();
    };
    run();

    rsx! {
        Stack { gap: "lg",
            Title { order: 2, "Audit log" }
            Text { size: "sm", color: "dimmed",
                "Times are UTC. One listing covers at most 31 days."
            }
            div { class: "row",
                {time_field(__scope, "From (UTC)", since)}
                {time_field(__scope, "To (UTC)", until)}
                div { class: "grow",
                    TextInput {
                        label: "Admin",
                        placeholder: "Every admin",
                        value_fn: move || admin.get(),
                        oninput: move |v: String| admin.set(v),
                        onsubmit: run,
                        spellcheck: false,
                    }
                }
                Button { onclick: run, "Show" }
                Button { variant: "default", onclick: last_day, "Last day" }
            }
            ErrorAlert { message: form_error }
            match list.get() {
                Load::Loading => Loading { caption: "Loading the audit log…" },
                Load::Failed(why) => Alert { color: "red", variant: "light", {why} },
                Load::Ready(found) => {
                    let empty = found.entries.is_empty();
                    let entries = found.entries;
                    div { class: "table-wrap",
                        if empty {
                            Text { color: "dimmed", "No entries in that window." }
                        }
                        table { class: "data",
                            thead { tr {
                                th { "Time" } th { "Admin" } th { "Action" } th { "Target" }
                                th { "Outcome" } th { "Source" } th { "Detail" }
                            } }
                            tbody {
                                for e in entries.clone() {
                                    tr {
                                        td { class: "nowrap", {display(&e.at)} }
                                        td { class: "mono nowrap", {e.admin.clone()} }
                                        td { class: "mono nowrap", {e.action.clone()} }
                                        td { class: "mono", {e.target.clone()} }
                                        td { StatusBadge { status: e.outcome.clone() } }
                                        td { class: "mono nowrap", {e.source.clone()} }
                                        td { {e.detail.clone()} }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refused_listing_says_to_narrow_the_window() {
        let too_many = ApiError::Status {
            status: 400,
            message: "more than 1000 entries in that window; narrow it".to_owned(),
        };
        let m = listing_failure(&too_many).unwrap_or_default();
        assert!(
            m.ends_with("Narrow the window, or filter by one admin."),
            "{m}"
        );
        let down = ApiError::Network("offline".to_owned());
        assert_eq!(listing_failure(&down), Some(down.message()));
    }

    #[test]
    fn an_ended_session_shows_nothing_here() {
        let gone = ApiError::Status {
            status: 401,
            message: "sign in".to_owned(),
        };
        assert_eq!(listing_failure(&gone), None);
    }
}
