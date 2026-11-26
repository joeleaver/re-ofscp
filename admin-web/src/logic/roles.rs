//! What each admin role may do (docs/decisions/0005, "Roles"). The console
//! shows what a role can't do as unavailable; the server enforces it.

use re_ofscp_types::admin::AdminRole;

/// Something an admin can do in the console.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// List, search and view accounts.
    ViewAccounts,
    /// Create an account.
    CreateAccount,
    /// Disable an account.
    DisableAccount,
    /// List outstanding invites.
    ViewInvites,
    /// Issue an invite.
    CreateInvite,
    /// Revoke an invite.
    RevokeInvite,
    /// Read the audit log.
    ViewAudit,
    /// List, create, change and disable admins; reset their TOTP.
    ManageAdmins,
    /// Read the federation policy.
    ViewFederation,
    /// Add and remove federation allow/deny rules.
    EditFederationRules,
    /// Switch the federation mode (open, allowlist, denylist).
    SetFederationMode,
}

impl Action {
    /// The least role that may do this.
    pub fn required(self) -> AdminRole {
        match self {
            Self::ViewAccounts | Self::ViewInvites | Self::ViewAudit | Self::ViewFederation => {
                AdminRole::ReadOnly
            }
            Self::CreateAccount
            | Self::DisableAccount
            | Self::CreateInvite
            | Self::RevokeInvite
            | Self::EditFederationRules => AdminRole::Operator,
            Self::ManageAdmins | Self::SetFederationMode => AdminRole::Owner,
        }
    }
}

/// Whether `role` may do `action`.
pub fn can(role: AdminRole, action: Action) -> bool {
    role >= action.required()
}

/// Why `role` can't do `action`, for a hint beside the unavailable control.
pub fn unavailable_reason(role: AdminRole, action: Action) -> Option<String> {
    (!can(role, action)).then(|| format!("Needs the {} role", role_label(action.required())))
}

/// A role as people read it.
pub fn role_label(role: AdminRole) -> &'static str {
    match role {
        AdminRole::ReadOnly => "read-only",
        AdminRole::Operator => "operator",
        AdminRole::Owner => "owner",
    }
}

/// Every role, most powerful first (for pickers).
pub const ROLES: [AdminRole; 3] = [AdminRole::Owner, AdminRole::Operator, AdminRole::ReadOnly];

/// A screen of the console.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Section {
    /// OFSCP accounts.
    #[default]
    Accounts,
    /// Account invites.
    Invites,
    /// Admins (owners only).
    Admins,
    /// The federation allow/deny policy.
    Federation,
    /// The audit log.
    Audit,
    /// The signed-in admin's own settings.
    Profile,
}

/// The navigation, in order.
pub const SECTIONS: [Section; 6] = [
    Section::Accounts,
    Section::Invites,
    Section::Admins,
    Section::Federation,
    Section::Audit,
    Section::Profile,
];

impl Section {
    /// The navigation label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Accounts => "Accounts",
            Self::Invites => "Invites",
            Self::Admins => "Admins",
            Self::Federation => "Federation",
            Self::Audit => "Audit log",
            Self::Profile => "Your password",
        }
    }

    /// What opening this section needs, if anything beyond a session.
    pub fn gate(self) -> Option<Action> {
        match self {
            Self::Accounts => Some(Action::ViewAccounts),
            Self::Invites => Some(Action::ViewInvites),
            Self::Admins => Some(Action::ManageAdmins),
            Self::Federation => Some(Action::ViewFederation),
            Self::Audit => Some(Action::ViewAudit),
            Self::Profile => None,
        }
    }

    /// Whether `role` may open this section.
    pub fn open_to(self, role: AdminRole) -> bool {
        self.gate().is_none_or(|a| can(role, a))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_role_ladder() {
        use Action::*;
        let all = [
            ViewAccounts,
            CreateAccount,
            DisableAccount,
            ViewInvites,
            CreateInvite,
            RevokeInvite,
            ViewAudit,
            ManageAdmins,
            ViewFederation,
            EditFederationRules,
            SetFederationMode,
        ];
        let allowed = |role| all.iter().filter(|a| can(role, **a)).count();
        assert_eq!(allowed(AdminRole::ReadOnly), 4);
        assert_eq!(allowed(AdminRole::Operator), 9);
        assert_eq!(allowed(AdminRole::Owner), 11);
        assert!(can(AdminRole::ReadOnly, ViewFederation));
        assert!(can(AdminRole::Operator, EditFederationRules));
        assert!(!can(AdminRole::ReadOnly, EditFederationRules));
        assert!(!can(AdminRole::Operator, SetFederationMode));
        assert!(can(AdminRole::ReadOnly, ViewAudit));
        assert!(!can(AdminRole::ReadOnly, CreateInvite));
        assert!(can(AdminRole::Operator, DisableAccount));
        assert!(!can(AdminRole::Operator, ManageAdmins));
    }

    #[test]
    fn reasons_name_the_needed_role() {
        assert_eq!(
            unavailable_reason(AdminRole::ReadOnly, Action::CreateAccount).as_deref(),
            Some("Needs the operator role")
        );
        assert_eq!(
            unavailable_reason(AdminRole::Operator, Action::ManageAdmins).as_deref(),
            Some("Needs the owner role")
        );
        assert_eq!(
            unavailable_reason(AdminRole::Owner, Action::ManageAdmins),
            None
        );
    }

    #[test]
    fn sections_by_role() {
        let open = |role| {
            SECTIONS
                .iter()
                .filter(|s| s.open_to(role))
                .copied()
                .collect::<Vec<_>>()
        };
        assert_eq!(
            open(AdminRole::ReadOnly),
            vec![
                Section::Accounts,
                Section::Invites,
                Section::Federation,
                Section::Audit,
                Section::Profile
            ]
        );
        assert_eq!(open(AdminRole::Operator), open(AdminRole::ReadOnly));
        assert_eq!(open(AdminRole::Owner), SECTIONS.to_vec());
    }
}
