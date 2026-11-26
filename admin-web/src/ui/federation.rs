//! The federation allow/deny policy (docs/decisions/0008): the mode
//! (owners switch it), and the allowlist and denylist (operators add and
//! remove rules). Both lists are always kept; the mode picks the one in
//! force.

use re_ofscp_types::federation::{
    FederationMode, FederationPolicyView, FederationRuleView, RuleList, RuleScope,
    SetFederationMode,
};
use rinch::prelude::*;
use rinch::reactive::Effect;

use super::common::{ErrorAlert, Load, Loading, Pending, SuccessAlert, confirm_dialog, failure};
use super::shell::current_role;
use crate::logic::federation::{
    MODES, add_rule, in_force, list_label, mode_effect, mode_label, scope_label, switch_warning,
};
use crate::logic::request;
use crate::logic::roles::{Action, can, unavailable_reason};
use crate::logic::time::display;
use crate::session::Session;

fn options(pairs: &[(&str, &str)]) -> Vec<SelectOption> {
    pairs
        .iter()
        .map(|(v, l)| SelectOption::new(*v, *l))
        .collect()
}

fn mode_options() -> Vec<SelectOption> {
    MODES
        .iter()
        .map(|m| SelectOption::new(m.as_str(), mode_label(*m)))
        .collect()
}

/// Fetch the policy into `policy`, and point the mode picker at its mode.
async fn load(
    session: Session,
    policy: Signal<Load<FederationPolicyView>>,
    picked: Signal<String>,
) {
    match session
        .call::<FederationPolicyView>(request::get_federation())
        .await
    {
        Ok(found) => {
            picked.set(found.mode.as_str().to_owned());
            policy.set(Load::Ready(found));
        }
        Err(e) => {
            if let Some(m) = failure(&e) {
                policy.set(Load::Failed(m));
            }
        }
    }
}

/// One list's rules, with a remove button for operators.
#[component]
fn RuleTable(
    title: String,
    active: bool,
    rules: Vec<FederationRuleView>,
    pending: Signal<Option<Pending<String>>>,
    pending_error: Signal<Option<String>>,
) -> NodeHandle {
    let session = use_store::<Session>();
    let may_remove = move || can(current_role(session), Action::EditFederationRules);
    let empty = rules.is_empty();
    rsx! {
        div { class: "panel",
            Group { gap: "sm",
                Title { order: 4, {title.clone()} }
                if active {
                    Badge { variant: "filled", color: "blue", "In force" }
                } else {
                    Badge { variant: "light", color: "gray", "Not in force" }
                }
            }
            if empty {
                Text { size: "sm", color: "dimmed", "No rules." }
            } else {
                div { class: "table-wrap",
                    table { class: "data",
                        thead { tr {
                            th { "Provider or domain" } th { "Matches" } th { "Note" } th { "Added by" } th { "Added" } th { "" }
                        } }
                        tbody {
                            for rule in rules.clone() {
                                tr { key: rule.id.clone(),
                                    td { class: "mono", {rule.value.clone()} }
                                    td { {scope_label(rule.scope)} }
                                    td { {rule.note.clone()} }
                                    td { {rule.created_by.clone()} }
                                    td { {display(&rule.created_at)} }
                                    td { class: "actions",
                                        Button {
                                            variant: "light",
                                            color: "red",
                                            size: "xs",
                                            disabled: {move || !may_remove()},
                                            onclick: {
                                                let id = rule.id.clone();
                                                let what = format!(
                                                    "{} ({}) will be removed from the {}.",
                                                    rule.value,
                                                    scope_label(rule.scope).to_lowercase(),
                                                    list_label(rule.list).to_lowercase(),
                                                );
                                                move || {
                                                    pending_error.set(None);
                                                    pending.set(Some(Pending {
                                                        title: "Remove this rule?".to_owned(),
                                                        message: what.clone(),
                                                        confirm: "Remove rule".to_owned(),
                                                        action: id.clone(),
                                                    }));
                                                }
                                            },
                                            "Remove"
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

/// The federation screen.
#[component]
pub fn FederationScreen() -> NodeHandle {
    let session = use_store::<Session>();
    let policy = Signal::new(Load::<FederationPolicyView>::Loading);
    let notice = Signal::new(None::<String>);
    let picked = Signal::new(String::new());
    let list = Signal::new(RuleList::Deny.as_str().to_owned());
    let scope = Signal::new(RuleScope::Domain.as_str().to_owned());
    let value = Signal::new(String::new());
    let note = Signal::new(String::new());
    let busy = Signal::new(false);
    let error = Signal::new(None::<String>);
    let mode_error = Signal::new(None::<String>);
    let removing = Signal::new(None::<Pending<String>>);
    let removing_busy = Signal::new(false);
    let removing_error = Signal::new(None::<String>);
    let switching = Signal::new(None::<Pending<FederationMode>>);
    let switching_busy = Signal::new(false);
    let switching_error = Signal::new(None::<String>);
    // Each write reloads the policy (the effect's first run is the initial
    // load), aborting a load still in flight so that an older answer never
    // replaces a newer one.
    let reload = Signal::new(());
    let mut loading: Option<TaskHandle> = None;
    Effect::new(move || {
        reload.get();
        if let Some(previous) = loading.take() {
            previous.abort();
        }
        loading = Some(spawn_local(load(session, policy, picked)));
    });

    let may = move |a: Action| can(current_role(session), a);
    let add = move || {
        if busy.get() || !may(Action::EditFederationRules) {
            return;
        }
        let req = match add_rule(&list.get(), &scope.get(), &value.get(), &note.get()) {
            Ok(req) => req,
            Err(e) => return error.set(Some(e.0)),
        };
        let call = match request::add_federation_rule(&req) {
            Ok(call) => call,
            Err(e) => return error.set(Some(e.message())),
        };
        error.set(None);
        notice.set(None);
        busy.set(true);
        spawn_local(async move {
            match session.call::<FederationRuleView>(call).await {
                Ok(rule) => {
                    busy.set(false);
                    value.set(String::new());
                    note.set(String::new());
                    notice.set(Some(format!(
                        "{} is on the {}.",
                        rule.value,
                        list_label(rule.list).to_lowercase()
                    )));
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
    let remove = move |id: String| {
        removing_busy.set(true);
        spawn_local(async move {
            match session
                .call_empty(request::remove_federation_rule(&id))
                .await
            {
                Ok(()) => {
                    removing_busy.set(false);
                    removing.set(None);
                    notice.set(Some("The rule is removed.".to_owned()));
                    reload.set(());
                }
                Err(e) => {
                    if let Some(m) = failure(&e) {
                        removing_busy.set(false);
                        removing_error.set(Some(m));
                    }
                }
            }
        });
    };
    let ask_switch = move || {
        let Load::Ready(current) = policy.get() else {
            return;
        };
        let Some(to) = FederationMode::parse(&picked.get()) else {
            return mode_error.set(Some("Choose a mode.".to_owned()));
        };
        if to == current.mode {
            return mode_error.set(Some(format!("The mode is already {}.", mode_label(to))));
        }
        mode_error.set(None);
        switching_error.set(None);
        switching.set(Some(Pending {
            title: format!("Switch to {}?", mode_label(to)),
            message: switch_warning(current.mode, to, current.allow.len()),
            confirm: format!("Switch to {}", mode_label(to)),
            action: to,
        }));
    };
    let switch = move |to: FederationMode| {
        let call = match request::set_federation_mode(&SetFederationMode { mode: to }) {
            Ok(call) => call,
            Err(e) => return switching_error.set(Some(e.message())),
        };
        switching_busy.set(true);
        spawn_local(async move {
            match session.call_empty(call).await {
                Ok(()) => {
                    switching_busy.set(false);
                    switching.set(None);
                    notice.set(Some(format!("The mode is now {}.", mode_label(to))));
                    reload.set(());
                }
                Err(e) => {
                    if let Some(m) = failure(&e) {
                        switching_busy.set(false);
                        switching_error.set(Some(m));
                    }
                }
            }
        });
    };

    rsx! {
        Stack { gap: "lg",
            Title { order: 2, "Federation" }
            Text { size: "sm", color: "dimmed",
                "Which other providers this one federates with. A refused provider's signed requests get 403, and nothing is sent to it. This provider's own accounts are never affected."
            }
            SuccessAlert { message: notice }
            match policy.get() {
                Load::Loading => Loading { caption: "Loading the federation policy…" },
                Load::Failed(why) => Alert { color: "red", variant: "light", {why} },
                Load::Ready(current) => {
                    let mode = current.mode;
                    let set = match (&current.mode_set_by, &current.mode_set_at) {
                        (Some(by), Some(at)) => format!("Set by {by}, {}.", display(at)),
                        _ => "Never changed.".to_owned(),
                    };
                    let allow = current.allow.clone();
                    let deny = current.deny.clone();
                    Stack { gap: "lg",
                        div { class: "panel",
                            Group { gap: "sm",
                                Title { order: 4, "Mode" }
                                Badge { variant: "filled", {mode_label(mode)} }
                            }
                            Text { size: "sm", {mode_effect(mode)} }
                            Text { size: "xs", color: "dimmed", {set} }
                            div { class: "row",
                                div { class: "grow",
                                    Select {
                                        label: "Switch to",
                                        data: mode_options(),
                                        disabled: {move || !may(Action::SetFederationMode)},
                                        value_fn: move || picked.get(),
                                        onchange: move |v: String| picked.set(v),
                                    }
                                }
                                Button {
                                    disabled: {move || !may(Action::SetFederationMode)},
                                    onclick: ask_switch,
                                    "Change mode"
                                }
                            }
                            Text { size: "xs", color: "dimmed",
                                {move || unavailable_reason(current_role(session), Action::SetFederationMode).unwrap_or_default()}
                            }
                            ErrorAlert { message: mode_error }
                        }
                        RuleTable {
                            title: list_label(RuleList::Deny),
                            active: in_force(mode, RuleList::Deny),
                            rules: deny,
                            pending: removing,
                            pending_error: removing_error,
                        }
                        RuleTable {
                            title: list_label(RuleList::Allow),
                            active: in_force(mode, RuleList::Allow),
                            rules: allow,
                            pending: removing,
                            pending_error: removing_error,
                        }
                    }
                }
            }
            div { class: "panel",
                Title { order: 4, "Add a rule" }
                Text { size: "xs", color: "dimmed",
                    {move || unavailable_reason(current_role(session), Action::EditFederationRules).unwrap_or_default()}
                }
                div { class: "row",
                    Select {
                        label: "List",
                        data: options(&[("deny", "Denylist"), ("allow", "Allowlist")]),
                        disabled: {move || !may(Action::EditFederationRules)},
                        value_fn: move || list.get(),
                        onchange: move |v: String| list.set(v),
                    }
                    Select {
                        label: "Matches",
                        data: options(&[
                            ("domain", scope_label(RuleScope::Domain)),
                            ("authority", scope_label(RuleScope::Authority)),
                        ]),
                        disabled: {move || !may(Action::EditFederationRules)},
                        value_fn: move || scope.get(),
                        onchange: move |v: String| scope.set(v),
                    }
                    div { class: "grow",
                        TextInput {
                            label: "Provider or domain",
                            description: "A domain (evil.example, with its subdomains), or a host: host on every port, host:port for one port.",
                            disabled: {move || !may(Action::EditFederationRules)},
                            value_fn: move || value.get(),
                            oninput: move |v: String| value.set(v),
                            spellcheck: false,
                        }
                    }
                    div { class: "grow",
                        TextInput {
                            label: "Note",
                            description: "Optional: why (shown here and in the audit log).",
                            disabled: {move || !may(Action::EditFederationRules)},
                            value_fn: move || note.get(),
                            oninput: move |v: String| note.set(v),
                            onsubmit: add,
                        }
                    }
                    Button {
                        loading: {|| busy.get()},
                        disabled: {move || !may(Action::EditFederationRules)},
                        onclick: add,
                        "Add rule"
                    }
                }
                ErrorAlert { message: error }
            }
            {confirm_dialog(__scope, removing, removing_busy, removing_error, remove)}
            {confirm_dialog(__scope, switching, switching_busy, switching_error, switch)}
        }
    }
}
