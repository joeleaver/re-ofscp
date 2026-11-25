//! Account invites: list the usable ones, issue (the token and link are
//! shown once), and revoke.

use re_ofscp_types::admin::{InviteCreated, InviteList};
use rinch::prelude::*;
use rinch::reactive::Effect;

use super::common::{
    CopyButton, ErrorAlert, Load, Loading, Pending, SuccessAlert, confirm_dialog, failure,
};
use super::shell::current_role;
use crate::logic::roles::{Action, can, unavailable_reason};
use crate::logic::time::display;
use crate::logic::{forms, request};
use crate::session::Session;

/// Who an issued invite is for, and until when.
fn issued_for(inv: &InviteCreated) -> String {
    let expires = display(&inv.expires_at);
    match &inv.handle {
        Some(h) => format!("For handle {h}; expires {expires}."),
        None => format!("For any handle; expires {expires}."),
    }
}

/// Fetch the usable invites into `list`.
async fn load(session: Session, list: Signal<Load<InviteList>>) {
    match session.call::<InviteList>(request::list_invites()).await {
        Ok(found) => list.set(Load::Ready(found)),
        Err(e) => {
            if let Some(m) = failure(&e) {
                list.set(Load::Failed(m));
            }
        }
    }
}

/// The invites screen.
#[component]
pub fn InvitesScreen() -> NodeHandle {
    let session = use_store::<Session>();
    let list = Signal::new(Load::<InviteList>::Loading);
    let issued = Signal::new(None::<InviteCreated>);
    let notice = Signal::new(None::<String>);
    let handle = Signal::new(String::new());
    let ttl_days = Signal::new(String::new());
    let busy = Signal::new(false);
    let error = Signal::new(None::<String>);
    let pending = Signal::new(None::<Pending<String>>);
    let pending_busy = Signal::new(false);
    let pending_error = Signal::new(None::<String>);
    // Each write reloads the list (the effect's first run is the initial
    // load), aborting a listing still in flight so that an older answer
    // never replaces a newer one. The listing is this component's.
    let reload = Signal::new(());
    let mut loading: Option<TaskHandle> = None;
    Effect::new(move || {
        reload.get();
        if let Some(previous) = loading.take() {
            previous.abort();
        }
        list.set(Load::Loading);
        loading = Some(spawn_local(load(session, list)));
    });

    let may = move |a: Action| can(current_role(session), a);
    let create = move || {
        if busy.get() || !may(Action::CreateInvite) {
            return;
        }
        let req = match forms::create_invite(&handle.get(), &ttl_days.get()) {
            Ok(req) => req,
            Err(e) => return error.set(Some(e.0)),
        };
        let call = match request::create_invite(&req) {
            Ok(call) => call,
            Err(e) => return error.set(Some(e.message())),
        };
        error.set(None);
        notice.set(None);
        busy.set(true);
        spawn_local(async move {
            match session.call::<InviteCreated>(call).await {
                Ok(created) => {
                    busy.set(false);
                    handle.set(String::new());
                    ttl_days.set(String::new());
                    issued.set(Some(created));
                    reload.set(());
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
    let revoke = move |id: String| {
        pending_busy.set(true);
        spawn_local(async move {
            match session.call_empty(request::revoke_invite(&id)).await {
                Ok(()) => {
                    pending_busy.set(false);
                    pending.set(None);
                    notice.set(Some("The invite is revoked.".to_owned()));
                    reload.set(());
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
    let ask_revoke = move |id: String, label: String| {
        pending_error.set(None);
        pending.set(Some(Pending {
            title: "Revoke this invite?".to_owned(),
            message: format!("{label} will stop working at once. This can't be undone."),
            confirm: "Revoke invite".to_owned(),
            action: id,
        }));
    };

    rsx! {
        Stack { gap: "lg",
            Title { order: 2, "Invites" }
            SuccessAlert { message: notice }
            if let Some(inv) = issued.get() {
                div { class: "secret",
                    Text { weight: "600", "Invite issued. Copy it now: the token is never shown again." }
                    Text { size: "sm", {issued_for(&inv)} }
                    Text { size: "sm", weight: "500", "Registration link" }
                    div { class: "secret-value",
                        code { {inv.link.clone()} }
                        CopyButton { text: inv.link.clone() }
                    }
                    Text { size: "sm", weight: "500", "Token" }
                    div { class: "secret-value",
                        code { {inv.token.clone()} }
                        CopyButton { text: inv.token.clone() }
                    }
                    Group {
                        Button { variant: "default", size: "xs", onclick: move || issued.set(None),
                            "I've copied it; hide it"
                        }
                    }
                }
            }
            div { class: "panel",
                Title { order: 4, "Issue an invite" }
                Text { size: "xs", color: "dimmed",
                    {move || unavailable_reason(current_role(session), Action::CreateInvite).unwrap_or_default()}
                }
                div { class: "row",
                    div { class: "grow",
                        TextInput {
                            label: "Handle",
                            description: "Optional: only this handle can register with it.",
                            disabled: {move || !may(Action::CreateInvite)},
                            value_fn: move || handle.get(),
                            oninput: move |v: String| handle.set(v),
                            spellcheck: false,
                        }
                    }
                    div { class: "grow",
                        TextInput {
                            label: "Lifetime (days)",
                            description: "1 to 30; empty for 7.",
                            disabled: {move || !may(Action::CreateInvite)},
                            value_fn: move || ttl_days.get(),
                            oninput: move |v: String| ttl_days.set(v),
                            onsubmit: create,
                        }
                    }
                    Button {
                        loading: {|| busy.get()},
                        disabled: {move || !may(Action::CreateInvite)},
                        onclick: create,
                        "Issue invite"
                    }
                }
                ErrorAlert { message: error }
            }
            match list.get() {
                Load::Loading => Loading { caption: "Loading invites…" },
                Load::Failed(why) => Alert { color: "red", variant: "light", {why} },
                Load::Ready(found) => {
                    let empty = found.invites.is_empty();
                    let invites = found.invites;
                    div { class: "table-wrap",
                        if empty {
                            Text { color: "dimmed", "No usable invites." }
                        }
                        table { class: "data",
                            thead { tr {
                                th { "Id" } th { "Handle" } th { "Issued by" } th { "Issued" } th { "Expires" } th { "" }
                            } }
                            tbody {
                                for inv in invites.clone() {
                                    tr { key: inv.id.clone(),
                                        td { class: "mono", {inv.id.clone()} }
                                        td { {inv.handle.clone().unwrap_or_else(|| "any".to_owned())} }
                                        td { {inv.created_by.clone()} }
                                        td { {display(&inv.created_at)} }
                                        td { {display(&inv.expires_at)} }
                                        td { class: "actions",
                                            Button {
                                                variant: "light",
                                                color: "red",
                                                size: "xs",
                                                disabled: {move || !may(Action::RevokeInvite)},
                                                onclick: {
                                                    let id = inv.id.clone();
                                                    let label = match &inv.handle {
                                                        Some(h) => format!("The invite for {h}"),
                                                        None => "The invite".to_owned(),
                                                    };
                                                    move || ask_revoke(id.clone(), label.clone())
                                                },
                                                "Revoke"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            {confirm_dialog(__scope, pending, pending_busy, pending_error, revoke)}
        }
    }
}
