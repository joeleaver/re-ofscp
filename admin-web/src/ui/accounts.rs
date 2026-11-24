//! OFSCP accounts: search by handle, view, create and disable.

use re_ofscp_types::admin::{AccountList, AccountView};
use rinch::prelude::*;

use super::common::{
    ErrorAlert, Load, Loading, Pending, StatusBadge, SuccessAlert, confirm_dialog, failure,
};
use super::field::{Credential, CredentialInput};
use super::shell::current_role;
use super::tasks::Tasks;
use crate::logic::roles::{Action, can, unavailable_reason};
use crate::logic::time::display;
use crate::logic::{forms, request};
use crate::session::Session;

/// Fetch the accounts matching `q` into `list`.
fn search(tasks: Tasks, session: Session, q: Option<String>, list: Signal<Load<AccountList>>) {
    list.set(Load::Loading);
    tasks.spawn(async move {
        match session
            .call::<AccountList>(request::list_accounts(q.as_deref()))
            .await
        {
            Ok(found) => list.set(Load::Ready(found)),
            Err(e) => {
                if let Some(m) = failure(&e) {
                    list.set(Load::Failed(m));
                }
            }
        }
    });
}

/// Fetch one account into `shown`.
fn view(tasks: Tasks, session: Session, handle: String, shown: Signal<Option<Load<AccountView>>>) {
    shown.set(Some(Load::Loading));
    tasks.spawn(async move {
        match session
            .call::<AccountView>(request::get_account(&handle))
            .await
        {
            Ok(a) => shown.set(Some(Load::Ready(a))),
            Err(e) => {
                if let Some(m) = failure(&e) {
                    shown.set(Some(Load::Failed(m)));
                }
            }
        }
    });
}

/// The accounts screen.
#[component]
pub fn AccountsScreen() -> NodeHandle {
    let session = use_store::<Session>();
    let tasks = Tasks::here();
    let query = Signal::new(String::new());
    let query_error = Signal::new(None::<String>);
    let list = Signal::new(Load::<AccountList>::Loading);
    let shown = Signal::new(None::<Load<AccountView>>);
    let notice = Signal::new(None::<String>);
    let creating = Signal::new(false);
    let pending = Signal::new(None::<Pending<String>>);
    let pending_busy = Signal::new(false);
    let pending_error = Signal::new(None::<String>);
    search(tasks, session, None, list);

    // Search for what the query field holds. It also reloads the list after
    // a change, so an invalid query is reported there too rather than
    // quietly listing every account.
    let run_search = move || match forms::account_query(&untracked(|| query.get())) {
        Ok(q) => {
            query_error.set(None);
            search(tasks, session, q, list);
        }
        Err(e) => query_error.set(Some(e.0)),
    };
    let disable = move |handle: String| {
        pending_busy.set(true);
        tasks.spawn(async move {
            match session.call_empty(request::disable_account(&handle)).await {
                Ok(()) => {
                    pending_busy.set(false);
                    pending.set(None);
                    notice.set(Some(format!("{handle} is disabled.")));
                    if untracked(|| shown.get()).is_some() {
                        view(tasks, session, handle, shown);
                    }
                    run_search();
                }
                Err(e) => {
                    if let Some(m) = failure(&e) {
                        pending_busy.set(false);
                        pending_error.set(Some(m));
                    }
                }
            }
        });
    };
    let ask_disable = move |handle: String| {
        pending_error.set(None);
        pending.set(Some(Pending {
            title: "Disable this account?".to_owned(),
            message: format!(
                "{handle} will no longer be able to sign in or act. The console has no way to \
                 re-enable an account."
            ),
            confirm: format!("Disable {handle}"),
            action: handle,
        }));
    };
    let may = move |a: Action| can(current_role(session), a);

    rsx! {
        Stack { gap: "lg",
            Group { justify: "space-between",
                Title { order: 2, "Accounts" }
                Group { gap: "xs",
                    Text { size: "xs", color: "dimmed",
                        {move || unavailable_reason(current_role(session), Action::CreateAccount).unwrap_or_default()}
                    }
                    Button {
                        disabled: {move || !may(Action::CreateAccount)},
                        onclick: move || creating.set(true),
                        "New account"
                    }
                }
            }
            SuccessAlert { message: notice }
            if creating.get() {
                CreateAccountForm {
                    on_close: move || creating.set(false),
                    on_created: move |handle: String| {
                        creating.set(false);
                        notice.set(Some(format!("Account {handle} created.")));
                        run_search();
                    },
                }
            }
            div { class: "row",
                div { class: "grow",
                    TextInput {
                        label: "Search handles",
                        placeholder: "Part of a handle; empty lists all",
                        value_fn: move || query.get(),
                        oninput: move |v: String| query.set(v),
                        onsubmit: run_search,
                        spellcheck: false,
                    }
                }
                Button { onclick: run_search, "Search" }
            }
            ErrorAlert { message: query_error }
            if let Some(detail) = shown.get() {
                div { class: "panel",
                    Group { justify: "space-between",
                        Title { order: 4, "Account" }
                        Button { variant: "subtle", size: "xs", onclick: move || shown.set(None), "Close" }
                    }
                    match detail.clone() {
                        Load::Loading => Loading { caption: "Loading the account…" },
                        Load::Failed(why) => Alert { color: "red", variant: "light", {why} },
                        Load::Ready(a) => table { class: "data",
                            tbody {
                                tr { th { "Handle" } td { class: "mono", {a.handle.clone()} } }
                                tr { th { "Display name" } td { {a.display_name.clone()} } }
                                tr { th { "Status" } td { StatusBadge { status: a.status.clone() } } }
                                tr { th { "Created" } td { {display(&a.created_at)} } }
                            }
                        },
                    }
                }
            }
            match list.get() {
                Load::Loading => Loading { caption: "Loading accounts…" },
                Load::Failed(why) => Alert { color: "red", variant: "light", {why} },
                Load::Ready(found) => {
                    let truncated = found.truncated;
                    let empty = found.accounts.is_empty();
                    let shown_count = found.accounts.len();
                    let accounts = found.accounts;
                    Stack { gap: "sm",
                        if truncated {
                            Alert { color: "yellow", variant: "light",
                                {format!("Showing the first {} matches; more accounts match. Refine the search to see them.", shown_count)}
                            }
                        }
                        if empty {
                            Text { color: "dimmed", "No accounts match." }
                        }
                        div { class: "table-wrap",
                            table { class: "data",
                                thead { tr {
                                    th { "Handle" } th { "Display name" } th { "Status" } th { "Created" } th { "" }
                                } }
                                tbody {
                                    for a in accounts.clone() {
                                        tr { key: a.handle.clone(),
                                            td { class: "mono",
                                                button {
                                                    class: "link-button",
                                                    onclick: {
                                                        let h = a.handle.clone();
                                                        move || view(tasks, session, h.clone(), shown)
                                                    },
                                                    {a.handle.clone()}
                                                }
                                            }
                                            td { {a.display_name.clone()} }
                                            td { StatusBadge { status: a.status.clone() } }
                                            td { {display(&a.created_at)} }
                                            td { class: "actions",
                                                if a.status == "active" {
                                                    Button {
                                                        variant: "light",
                                                        color: "red",
                                                        size: "xs",
                                                        disabled: {move || !may(Action::DisableAccount)},
                                                        onclick: {
                                                            let h = a.handle.clone();
                                                            move || ask_disable(h.clone())
                                                        },
                                                        "Disable"
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
            }
            {confirm_dialog(__scope, pending, pending_busy, pending_error, disable)}
        }
    }
}

/// The new-account form.
#[component]
fn CreateAccountForm(on_close: Callback, on_created: InputCallback) -> NodeHandle {
    let session = use_store::<Session>();
    let tasks = Tasks::here();
    let handle = Signal::new(String::new());
    let display_name = Signal::new(String::new());
    let password = Signal::new(String::new());
    let busy = Signal::new(false);
    let error = Signal::new(None::<String>);
    let submit = move || {
        if busy.get() {
            return;
        }
        let req = match forms::create_account(&handle.get(), &display_name.get(), &password.get()) {
            Ok(req) => req,
            Err(e) => return error.set(Some(e.0)),
        };
        let call = match request::create_account(&req) {
            Ok(call) => call,
            Err(e) => return error.set(Some(e.message())),
        };
        error.set(None);
        busy.set(true);
        let on_created = on_created.clone();
        tasks.spawn(async move {
            match session.call::<AccountView>(call).await {
                Ok(a) => {
                    busy.set(false);
                    on_created.invoke(a.handle);
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
        div { class: "panel",
            Title { order: 4, "New account" }
            TextInput {
                label: "Handle",
                description: "3 to 32 characters: lowercase letters, digits, '_' and '-'.",
                value_fn: move || handle.get(),
                oninput: move |v: String| handle.set(v),
                spellcheck: false,
            }
            TextInput {
                label: "Display name",
                description: "Optional; the handle is used when empty.",
                value_fn: move || display_name.get(),
                oninput: move |v: String| display_name.set(v),
            }
            CredentialInput {
                label: "Initial password",
                description: "At least 8 characters. Share it with the account's owner securely.",
                kind: Credential::NewPassword,
                value: password,
                onsubmit: submit.clone(),
            }
            ErrorAlert { message: error }
            Group { gap: "sm",
                Button { loading: {|| busy.get()}, onclick: submit.clone(), "Create account" }
                Button {
                    variant: "default",
                    disabled: {|| busy.get()},
                    onclick: {
                        let on_close = on_close.clone();
                        move || on_close.invoke()
                    },
                    "Cancel"
                }
            }
        }
    }
}
