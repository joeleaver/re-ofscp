//! Credential fields: usernames, passwords and authenticator codes, with
//! the `autocomplete` token that tells the browser and password managers
//! what each one holds.
//!
//! rinch's `TextInput` (at the pinned commit) has no `autocomplete` prop,
//! so these fields are written here in `rsx!`, with the same markup and
//! classes `TextInput` renders (and so the same look), and the same
//! label/description association by id.

use std::sync::atomic::{AtomicU64, Ordering};

use rinch::prelude::*;

/// Numbers the fields, for their ids.
static NEXT_FIELD: AtomicU64 = AtomicU64::new(1);

/// What a credential field holds: its `autocomplete` token and input type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Credential {
    /// The signed-in admin's username.
    #[default]
    Username,
    /// The signed-in admin's current password.
    CurrentPassword,
    /// A password being chosen: the admin's own, or one an admin sets for
    /// someone else (so the browser can offer to generate it).
    NewPassword,
    /// A code from an authenticator app.
    OneTimeCode,
}

impl Credential {
    /// The `autocomplete` attribute's token.
    pub fn autocomplete(self) -> &'static str {
        match self {
            Self::Username => "username",
            Self::CurrentPassword => "current-password",
            Self::NewPassword => "new-password",
            Self::OneTimeCode => "one-time-code",
        }
    }

    /// The input's `type`.
    pub fn input_type(self) -> &'static str {
        match self {
            Self::CurrentPassword | Self::NewPassword => "password",
            Self::Username | Self::OneTimeCode => "text",
        }
    }

    /// The input's `inputmode`: a numeric keypad for codes.
    pub fn input_mode(self) -> &'static str {
        match self {
            Self::OneTimeCode => "numeric",
            Self::Username | Self::CurrentPassword | Self::NewPassword => "text",
        }
    }
}

/// A labelled credential field bound to `value`. `description`, when not
/// empty, is shown under it; Enter calls `onsubmit`.
#[component]
pub fn CredentialInput(
    label: String,
    description: String,
    placeholder: String,
    kind: Credential,
    value: Signal<String>,
    onsubmit: Callback,
) -> NodeHandle {
    let id = format!("admin-field-{}", NEXT_FIELD.fetch_add(1, Ordering::Relaxed));
    let label_id = format!("{id}-label");
    let label_for = id.clone();
    let description_id = format!("{id}-description");
    let described_by = if description.is_empty() {
        String::new()
    } else {
        description_id.clone()
    };
    let note: Option<NodeHandle> = (!description.is_empty()).then(|| {
        rsx! {
            div { class: "rinch-text-input__description", id: description_id, {description.clone()} }
        }
    });
    rsx! {
        div { class: "rinch-text-input rinch-text-input--md",
            label { class: "rinch-text-input__label", id: label_id, r#for: label_for, {label.clone()} }
            input {
                class: "rinch-text-input__input",
                id: id,
                r#type: kind.input_type(),
                autocomplete: kind.autocomplete(),
                inputmode: kind.input_mode(),
                placeholder: placeholder.clone(),
                spellcheck: "false",
                aria-describedby: described_by,
                value: {move || value.get()},
                oninput: move |v: String| value.set(v),
                onsubmit: move || onsubmit.invoke(),
            }
            {note}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_credential_names_its_autocomplete_token() {
        assert_eq!(Credential::Username.autocomplete(), "username");
        assert_eq!(
            Credential::CurrentPassword.autocomplete(),
            "current-password"
        );
        assert_eq!(Credential::NewPassword.autocomplete(), "new-password");
        assert_eq!(Credential::OneTimeCode.autocomplete(), "one-time-code");
    }

    #[test]
    fn only_passwords_are_masked() {
        assert_eq!(Credential::CurrentPassword.input_type(), "password");
        assert_eq!(Credential::NewPassword.input_type(), "password");
        assert_eq!(Credential::Username.input_type(), "text");
        assert_eq!(Credential::OneTimeCode.input_type(), "text");
        assert_eq!(Credential::OneTimeCode.input_mode(), "numeric");
    }
}
