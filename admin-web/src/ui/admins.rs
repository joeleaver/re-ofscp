//! Admins (owners only): list, create, change a role, disable (final) and
//! reset another admin's TOTP. Every change is confirmed first.

use re_ofscp_types::admin::{AdminList, AdminRole, AdminView, UpdateAdmin};
use rinch::prelude::*;
use rinch::reactive::Effect;

use super::common::{
    ErrorAlert, Load, Loading, Pending, StatusBadge, SuccessAlert, confirm_dialog, failure,
};
use super::shell::current_role;
use crate::logic::roles::{Action, ROLES, can, role_label, unavailable_reason};
use crate::logic::time::display;
use crate::logic::{forms, request};
use crate::session::Session;

/// A change to one admin, waiting for confirmation.
#[derive(Debug, Clone, PartialEq)]
enum Change {
    /// Give the admin this role.
    Role(String, AdminRole),
    /// Disable the admin, for good.
    Disable(String),
    /// Remove the admin's TOTP enrollment.
    ResetTotp(String),
}

impl Change {
    fn username(&self) -> &str {
        match self {
            Self::Role(u, _) | Self::Disable(u) | Self::ResetTotp(u) => u,
        }
    }

    /// The confirmation to show before making the change.
    fn pending(self) -> Pending<Self> {
        let (title, message, confirm) = match &self {
            Self::Role(u, r) => (
                format!("Make {u} {}?", role_label(*r)),
                format!(
                    "{u} will have the {} role from their next request.",
                    role_label(*r)
                ),
                "Change role".to_owned(),
            ),
            Self::Disable(u) => (
                format!("Disable {u}?"),
                format!(
                    "{u} is signed out everywhere and can never sign in again. Disabling is \
                     final: to give them access later, create a new admin."
                ),
                format!("Disable {u}"),
            ),
            Self::ResetTotp(u) => (
                format!("Reset {u}'s two-factor sign-in?"),
                format!(
                    "{u} is signed out everywhere and must set up an authenticator again at \
                     their next sign-in."
                ),
                "Reset two-factor".to_owned(),
            ),
        };
        Pending {
            title,
            message,
            confirm,
            action: self,
        }
    }

    /// What to say once the change is made.
    fn done(&self) -> String {
        match self {
            Self::Role(u, r) => format!("{u} is now {}.", role_label(*r)),
            Self::Disable(u) => format!("{u} is disabled."),
            Self::ResetTotp(u) => format!("{u}'s two-factor sign-in is reset."),
        }
    }
}

/// One admin as the table shows it.
#[derive(Debug, Clone, PartialEq)]
struct Row {
    admin: AdminView,
    /// This is the signed-in admin.
    mine: bool,
    /// Still active, so it can be changed.
    active: bool,
    /// Has a TOTP enrollment to reset (never one's own: the server refuses).
    resettable: bool,
}

impl Row {
    /// Changes whenever anything the row shows changes, so the row is
    /// rebuilt then.
    fn key(&self) -> String {
        let a = &self.admin;
        format!(
            "{}|{}|{}|{}|{}",
            a.username,
            a.role.as_str(),
            a.status,
            a.totp_enabled,
            a.password_change_required
        )
    }
}

/// The table's rows; `me` is the signed-in admin.
fn rows(admins: &[AdminView], me: &str) -> Vec<Row> {
    admins
        .iter()
        .map(|a| Row {
            mine: a.username == me,
            active: a.status == "active",
            resettable: a.totp_enabled && a.username != me,
            admin: a.clone(),
        })
        .collect()
}

/// An admin's two-factor state, for the table.
fn totp_label(a: &AdminView) -> &'static str {
    if a.totp_enabled {
        "enabled"
    } else if a.password_change_required {
        "not yet (new admin)"
    } else {
        "not set up"
    }
}

/// The role picker's options.
fn role_options() -> Vec<SelectOption> {
    ROLES
        .iter()
        .map(|r| SelectOption::new(r.as_str(), role_label(*r)))
        .collect()
}

/// Fetch every admin into `list`.
async fn load(session: Session, list: Signal<Load<AdminList>>) {
    match session.call::<AdminList>(request::list_admins()).await {
        Ok(found) => list.set(Load::Ready(found)),
        Err(e) => {
            if let Some(m) = failure(&e) {
                list.set(Load::Failed(m));
            }
        }
    }
}

/// The admins screen.
#[component]
pub fn AdminsScreen() -> NodeHandle {
    let session = use_store::<Session>();
    let list = Signal::new(Load::<AdminList>::Loading);
    let notice = Signal::new(None::<String>);
    let creating = Signal::new(false);
    // The admin whose role is being edited, and the role picked for them.
    let editing = Signal::new(None::<AdminView>);
    let picked = Signal::new(String::new());
    let pending = Signal::new(None::<Pending<Change>>);
    let pending_busy = Signal::new(false);
    let pending_error = Signal::new(None::<String>);
    // Each write reloads the list (the effect's first run is the initial
    // load), aborting a listing still in flight so that an older answer
    // never replaces a newer one. Spawned by this component's effect, the
    // listing belongs to the screen even when the new-admin form, which
    // closes as it asks, is what asked.
    let reload = Signal::new(());
    let mut loading: Option<TaskHandle> = None;
    Effect::new(move || {
        reload.get();
        // Only the request signal is tracked. The writes below re-render
        // what shows the result, and those renders' reads must not become
        // this effect's dependencies (they made each request go out twice).
        untracked(|| {
            if !can(current_role(session), Action::ManageAdmins) {
                return;
            }
            if let Some(previous) = loading.take() {
                previous.abort();
            }
            list.set(Load::Loading);
            loading = Some(spawn_local(load(session, list)));
        });
    });

    let me = move || session.info().map(|i| i.username).unwrap_or_default();
    let apply = move |change: Change| {
        let call = match &change {
            Change::Role(u, r) => request::update_admin(
                u,
                &UpdateAdmin {
                    role: Some(*r),
                    disabled: None,
                },
            ),
            Change::Disable(u) => request::update_admin(
                u,
                &UpdateAdmin {
                    role: None,
                    disabled: Some(true),
                },
            ),
            Change::ResetTotp(u) => Ok(request::reset_totp(u)),
        };
        let call = match call {
            Ok(call) => call,
            Err(e) => return pending_error.set(Some(e.message())),
        };
        pending_busy.set(true);
        spawn_local(async move {
            match session.call_empty(call).await {
                Ok(()) => {
                    pending_busy.set(false);
                    pending.set(None);
                    editing.set(None);
                    notice.set(Some(change.done()));
                    if change.username() == untracked(me) {
                        // The signed-in admin changed themselves: their
                        // role (or their session) is different now.
                        session.refresh().await;
                    }
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
    let ask = move |change: Change| {
        pending_error.set(None);
        pending.set(Some(change.pending()));
    };
    let ask_role = move || {
        let Some(a) = editing.get() else { return };
        match AdminRole::parse(&picked.get()) {
            Some(r) if r != a.role => ask(Change::Role(a.username, r)),
            Some(_) => editing.set(None),
            None => {}
        }
    };

    rsx! {
        Stack { gap: "lg",
            Group { justify: "space-between",
                Title { order: 2, "Admins" }
                Button {
                    disabled: {move || !can(current_role(session), Action::ManageAdmins)},
                    onclick: move || creating.set(true),
                    "New admin"
                }
            }
            if !can(current_role(session), Action::ManageAdmins) {
                Alert { color: "gray", variant: "light",
                    {unavailable_reason(current_role(session), Action::ManageAdmins).unwrap_or_default()}
                }
            }
            SuccessAlert { message: notice }
            if creating.get() {
                CreateAdminForm {
                    on_close: move || creating.set(false),
                    on_created: move |username: String| {
                        creating.set(false);
                        notice.set(Some(format!(
                            "Admin {username} created. They choose their own password and set up \
                             two-factor sign-in when they first sign in."
                        )));
                        reload.set(());
                    },
                }
            }
            if let Some(a) = editing.get() {
                div { class: "panel",
                    Title { order: 4, {format!("Change {}'s role", a.username)} }
                    Select {
                        label: "Role",
                        data: role_options(),
                        value_fn: move || picked.get(),
                        onchange: move |v: String| picked.set(v),
                    }
                    Group { gap: "sm",
                        Button { onclick: ask_role, "Save role" }
                        Button { variant: "default", onclick: move || editing.set(None), "Cancel" }
                    }
                }
            }
            match list.get() {
                Load::Loading => Loading { caption: "Loading admins…" },
                Load::Failed(why) => Alert { color: "red", variant: "light", {why} },
                Load::Ready(found) => div { class: "table-wrap",
                    table { class: "data",
                        thead { tr {
                            th { "Username" } th { "Role" } th { "Status" } th { "Two-factor" }
                            th { "Created" } th { "" }
                        } }
                        tbody {
                            for row in rows(&found.admins, &untracked(me)) {
                                tr { key: row.key(),
                                    td { class: "mono nowrap",
                                        {row.admin.username.clone()}
                                        if row.mine {
                                            Text { size: "xs", color: "dimmed", "(you)" }
                                        }
                                    }
                                    td { {role_label(row.admin.role)} }
                                    td { StatusBadge { status: row.admin.status.clone() } }
                                    td { {totp_label(&row.admin)} }
                                    td { {format!("{} by {}", display(&row.admin.created_at), row.admin.created_by)} }
                                    td { class: "actions",
                                        if row.active {
                                            Group { gap: "xs", justify: "flex-end",
                                                Button {
                                                    variant: "light",
                                                    size: "xs",
                                                    onclick: {
                                                        let a = row.admin.clone();
                                                        move || {
                                                            picked.set(a.role.as_str().to_owned());
                                                            editing.set(Some(a.clone()));
                                                        }
                                                    },
                                                    "Change role"
                                                }
                                                if row.resettable {
                                                    Button {
                                                        variant: "light",
                                                        color: "orange",
                                                        size: "xs",
                                                        onclick: {
                                                            let u = row.admin.username.clone();
                                                            move || ask(Change::ResetTotp(u.clone()))
                                                        },
                                                        "Reset two-factor"
                                                    }
                                                }
                                                Button {
                                                    variant: "light",
                                                    color: "red",
                                                    size: "xs",
                                                    onclick: {
                                                        let u = row.admin.username.clone();
                                                        move || ask(Change::Disable(u.clone()))
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
                },
            }
            {confirm_dialog(__scope, pending, pending_busy, pending_error, apply)}
        }
    }
}

/// The new-admin form.
#[component]
fn CreateAdminForm(on_close: Callback, on_created: InputCallback) -> NodeHandle {
    let session = use_store::<Session>();
    let username = Signal::new(String::new());
    let password = Signal::new(String::new());
    let role = Signal::new(AdminRole::Operator.as_str().to_owned());
    let busy = Signal::new(false);
    let error = Signal::new(None::<String>);
    let submit = move || {
        if busy.get() {
            return;
        }
        let req = match forms::create_admin(&username.get(), &password.get(), &role.get()) {
            Ok(req) => req,
            Err(e) => return error.set(Some(e.0)),
        };
        let call = match request::create_admin(&req) {
            Ok(call) => call,
            Err(e) => return error.set(Some(e.message())),
        };
        error.set(None);
        busy.set(true);
        let on_created = on_created.clone();
        spawn_local(async move {
            match session.call::<AdminView>(call).await {
                Ok(a) => {
                    busy.set(false);
                    on_created.invoke(a.username);
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
            Title { order: 4, "New admin" }
            TextInput {
                label: "Username",
                description: "3 to 64 characters: lowercase letters, digits, '.', '_' and '-'.",
                value_fn: move || username.get(),
                oninput: move |v: String| username.set(v),
                spellcheck: false,
                autocomplete: "off",
            }
            TextInput {
                label: "Initial password",
                description: "At least 8 characters. They must replace it at first sign-in.",
                input_type: "password",
                autocomplete: "new-password",
                spellcheck: false,
                value_fn: move || password.get(),
                oninput: move |v: String| password.set(v),
                onsubmit: submit.clone(),
            }
            Select {
                label: "Role",
                data: role_options(),
                value_fn: move || role.get(),
                onchange: move |v: String| role.set(v),
            }
            ErrorAlert { message: error }
            Group { gap: "sm",
                Button { loading: {|| busy.get()}, onclick: submit.clone(), "Create admin" }
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

    fn admin(username: &str, status: &str, totp: bool) -> AdminView {
        AdminView {
            username: username.to_owned(),
            role: AdminRole::Operator,
            status: status.to_owned(),
            totp_enabled: totp,
            password_change_required: false,
            created_by: "root".to_owned(),
            created_at: "2026-11-24T00:00:00Z".to_owned(),
        }
    }

    #[test]
    fn rows_never_offer_resetting_your_own_two_factor() {
        let list = [
            admin("me", "active", true),
            admin("ops", "active", true),
            admin("new", "active", false),
            admin("gone", "disabled", true),
        ];
        let r = rows(&list, "me");
        assert!(r[0].mine && !r[0].resettable);
        assert!(!r[1].mine && r[1].resettable && r[1].active);
        assert!(!r[2].resettable);
        assert!(!r[3].active);
    }

    #[test]
    fn a_row_key_changes_with_what_the_row_shows() {
        let a = rows(&[admin("ops", "active", true)], "me").remove(0);
        let b = rows(&[admin("ops", "disabled", true)], "me").remove(0);
        assert_ne!(a.key(), b.key());
        // `totp_label` shows `password_change_required` for an admin
        // without TOTP, so the key must change with it too.
        let new = admin("ops", "active", false);
        let settled = AdminView {
            password_change_required: false,
            ..new.clone()
        };
        let fresh = AdminView {
            password_change_required: true,
            ..new
        };
        assert_ne!(totp_label(&settled), totp_label(&fresh));
        let settled = rows(&[settled], "me").remove(0);
        let fresh = rows(&[fresh], "me").remove(0);
        assert_ne!(settled.key(), fresh.key());
    }

    #[test]
    fn changes_name_their_admin() {
        let c = Change::Role("ops".to_owned(), AdminRole::Owner);
        assert_eq!(c.username(), "ops");
        assert_eq!(c.done(), "ops is now owner.");
        assert_eq!(
            Change::Disable("ops".to_owned()).pending().confirm,
            "Disable ops"
        );
    }
}
