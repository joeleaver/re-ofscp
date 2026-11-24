//! Pieces every screen uses: load state, error and success messages, the
//! confirmation dialog, the copy button and the TOTP code field.

use std::rc::Rc;
use std::time::Duration;

use rinch::prelude::*;

use crate::browser;
use crate::logic::problem::ApiError;

/// Data a screen fetches.
#[derive(Debug, Clone, PartialEq)]
pub enum Load<T> {
    /// Waiting for the server.
    Loading,
    /// Here it is.
    Ready(T),
    /// It couldn't be fetched; the message says why.
    Failed(String),
}

/// A red alert while `message` holds something.
#[component]
pub fn ErrorAlert(message: Signal<Option<String>>) -> NodeHandle {
    rsx! {
        div {
            if let Some(m) = message.get() {
                Alert { color: "red", variant: "light", {m} }
            }
        }
    }
}

/// A green alert while `message` holds something.
#[component]
pub fn SuccessAlert(message: Signal<Option<String>>) -> NodeHandle {
    rsx! {
        div {
            if let Some(m) = message.get() {
                Alert { color: "green", variant: "light", {m} }
            }
        }
    }
}

/// A spinner with a caption.
#[component]
pub fn Loading(caption: String) -> NodeHandle {
    rsx! {
        Group { gap: "sm", align: "center",
            Loader { size: "sm" }
            Text { size: "sm", color: "dimmed", {caption.clone()} }
        }
    }
}

/// A destructive action waiting for confirmation.
#[derive(Debug, Clone, PartialEq)]
pub struct Pending<A> {
    /// The dialog's title.
    pub title: String,
    /// What will happen, plainly.
    pub message: String,
    /// The confirm button's label.
    pub confirm: String,
    /// What to do on confirmation.
    pub action: A,
}

/// The dialog that asks before a destructive action. It is open while
/// `pending` holds an action; confirming calls `on_confirm` with it, which
/// is expected to set `busy` while it works and clear `pending` when done.
/// While `busy`, the dialog can't be dismissed.
pub fn confirm_dialog<A: Clone + PartialEq + 'static>(
    __scope: &mut RenderScope,
    pending: Signal<Option<Pending<A>>>,
    busy: Signal<bool>,
    error: Signal<Option<String>>,
    on_confirm: impl Fn(A) + 'static,
) -> NodeHandle {
    // Shared by the confirm button's handler, which the dialog may build
    // more than once.
    let on_confirm = Rc::new(on_confirm);
    let close = move || {
        if !busy.get() {
            error.set(None);
            pending.set(None);
        }
    };
    rsx! {
        Modal {
            opened_fn: move || pending.with(Option::is_some),
            onclose: close,
            title: {|| pending.get().map(|p| p.title).unwrap_or_default()},
            size: "md",
            Stack { gap: "md",
                Text { {|| pending.get().map(|p| p.message).unwrap_or_default()} }
                ErrorAlert { message: error }
                Group { justify: "flex-end", gap: "sm",
                    Button { variant: "default", disabled: {|| busy.get()}, onclick: close, "Cancel" }
                    Button {
                        color: "red",
                        loading: {|| busy.get()},
                        onclick: {
                            let on_confirm = Rc::clone(&on_confirm);
                            move || {
                                if let Some(p) = pending.get() {
                                    on_confirm(p.action);
                                }
                            }
                        },
                        {|| pending.get().map(|p| p.confirm).unwrap_or_default()}
                    }
                }
            }
        }
    }
}

/// What a copy button last did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Copied {
    Idle,
    Done,
    Failed,
}

/// How long a copy button says what it did before it reads "Copy" again.
const COPIED_SHOWN_FOR: Duration = Duration::from_secs(2);

/// A button that copies `text` to the clipboard. It says whether the copy
/// worked for [`COPIED_SHOWN_FOR`], then offers to copy again.
#[component]
pub fn CopyButton(text: String) -> NodeHandle {
    let state = Signal::new(Copied::Idle);
    // Counts clicks, so only the latest click's timer resets the label: an
    // earlier one must not cut a later "Copied" short.
    let clicks = Signal::new(0u64);
    rsx! {
        Button {
            variant: "light",
            size: "xs",
            onclick: move || {
                let text = text.clone();
                let click = untracked(|| clicks.get()).wrapping_add(1);
                clicks.set(click);
                spawn_local(async move {
                    let done = browser::copy_text(&text).await;
                    state.set(if done.is_ok() { Copied::Done } else { Copied::Failed });
                    sleep(COPIED_SHOWN_FOR).await;
                    if untracked(|| clicks.get()) == click {
                        state.set(Copied::Idle);
                    }
                });
            },
            {|| match state.get() {
                Copied::Idle => "Copy",
                Copied::Done => "Copied",
                Copied::Failed => "Copy failed: select and copy by hand",
            }}
        }
    }
}

/// The six-digit authenticator code field. Its `autocomplete` token lets
/// the browser offer a code it has received. rinch's `TextInput` has no
/// `inputmode` prop, so phones show their full keyboard here rather than a
/// numeric keypad.
#[component]
pub fn CodeInput(label: String, value: Signal<String>, onsubmit: Callback) -> NodeHandle {
    rsx! {
        TextInput {
            label: label.clone(),
            placeholder: "123 456",
            autocomplete: "one-time-code",
            spellcheck: false,
            value_fn: move || value.get(),
            oninput: move |v: String| value.set(v),
            onsubmit: move || onsubmit.invoke(),
        }
    }
}

/// A status as a coloured badge (`active`, `disabled`, audit outcomes).
#[component]
pub fn StatusBadge(status: String) -> NodeHandle {
    let color = match status.as_str() {
        "active" | "ok" => "green",
        "disabled" | "failed" => "red",
        "denied" => "orange",
        _ => "gray",
    };
    rsx! {
        Badge { variant: "light", color: color, {status.clone()} }
    }
}

/// What to show for a failed request, or `None` when the session has
/// ended: the console is then already back at sign-in with its own notice,
/// and the screen that asked is gone.
pub fn failure(e: &ApiError) -> Option<String> {
    (!e.is_unauthorized()).then(|| e.message())
}
