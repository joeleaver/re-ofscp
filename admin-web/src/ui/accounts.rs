//! OFSCP accounts: search by handle, view, create and disable.

use re_ofscp_types::admin::{AccountList, AccountView};
use rinch::prelude::*;
use rinch::reactive::Effect;

use super::common::{
    ErrorAlert, Load, Loading, Pending, StatusBadge, SuccessAlert, confirm_dialog, failure,
};
use super::shell::current_role;
use crate::logic::roles::{Action, can, unavailable_reason};
use crate::logic::time::display;
use crate::logic::{forms, request};
use crate::session::Session;

/// Fetch the accounts matching `q` into `list`.
async fn search(session: Session, q: Option<String>, list: Signal<Load<AccountList>>) {
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
}

/// Fetch one account into `shown`.
async fn view(session: Session, handle: String, shown: Signal<Option<Load<AccountView>>>) {
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
}

/// Whether disabling `disabled` should reload the detail panel, which is
/// showing (or loading) `viewing`: only when it is that same account. The
/// panel may have moved on to another account while the disable ran, and
/// reloading the disabled one would replace the newer choice.
fn reload_panel_after_disable(viewing: Option<&str>, disabled: &str) -> bool {
    viewing == Some(disabled)
}

/// The accounts screen.
#[component]
pub fn AccountsScreen() -> NodeHandle {
    let session = use_store::<Session>();
    let query = Signal::new(String::new());
    let query_error = Signal::new(None::<String>);
    let list = Signal::new(Load::<AccountList>::Loading);
    let shown = Signal::new(None::<Load<AccountView>>);
    let notice = Signal::new(None::<String>);
    let creating = Signal::new(false);
    let pending = Signal::new(None::<Pending<String>>);
    let pending_busy = Signal::new(false);
    let pending_error = Signal::new(None::<String>);

    // The search last asked for, and the account the detail panel is for.
    // Each write starts its request and aborts the previous one of its
    // kind, so an older, slower answer never replaces a newer one. The
    // requests are spawned by this component's effects, so they belong to
    // the screen whichever handler asked (a table row, the new-account
    // form, a finished disable) and end when the screen does.
    let searched = Signal::new(None::<String>);
    let viewing = Signal::new(None::<String>);
    let mut searching: Option<TaskHandle> = None;
    Effect::new(move || {
        let q = searched.get();
        if let Some(previous) = searching.take() {
            previous.abort();
        }
        list.set(Load::Loading);
        searching = Some(spawn_local(search(session, q, list)));
    });
    let mut fetching: Option<TaskHandle> = None;
    Effect::new(move || {
        let handle = viewing.get();
        if let Some(previous) = fetching.take() {
            previous.abort();
        }
        match handle {
            Some(handle) => {
                shown.set(Some(Load::Loading));
                fetching = Some(spawn_local(view(session, handle, shown)));
            }
            None => shown.set(None),
        }
    });

    // Search for what the query field holds. It also reloads the list after
    // a change, so an invalid query is reported there too rather than
    // quietly listing every account.
    let run_search = move || match forms::account_query(&untracked(|| query.get())) {
        Ok(q) => {
            query_error.set(None);
            searched.set(q);
        }
        Err(e) => query_error.set(Some(e.0)),
    };
    let disable = move |handle: String| {
        pending_busy.set(true);
        spawn_local(async move {
            match session.call_empty(request::disable_account(&handle)).await {
                Ok(()) => {
                    pending_busy.set(false);
                    pending.set(None);
                    notice.set(Some(format!("{handle} is disabled.")));
                    if reload_panel_after_disable(untracked(|| viewing.get()).as_deref(), &handle) {
                        viewing.set(Some(handle));
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
                        Button { variant: "subtle", size: "xs", onclick: move || viewing.set(None), "Close" }
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
                                                        move || viewing.set(Some(h.clone()))
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
        spawn_local(async move {
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
            TextInput {
                label: "Initial password",
                description: "At least 8 characters. Share it with the account's owner securely.",
                input_type: "password",
                autocomplete: "new-password",
                spellcheck: false,
                value_fn: move || password.get(),
                oninput: move |v: String| password.set(v),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_disable_reloads_the_panel_only_for_the_account_it_shows() {
        assert!(reload_panel_after_disable(Some("alice"), "alice"));
        // The admin opened another account while the disable ran.
        assert!(!reload_panel_after_disable(Some("bob"), "alice"));
        // The panel is closed.
        assert!(!reload_panel_after_disable(None, "alice"));
    }
}
