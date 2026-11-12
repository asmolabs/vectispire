//! Four-eyes: who may settle a triage decision, and who may approve one.
//!
//! **Two levels, worth stating.** Recording a decision is one permission (`canCauseEffects`, the route's marker);
//! having it settle rather than queue is another (`canApproveTriage`, here). A developer holds the first and not
//! the second; an auditor holds neither; the platform governor holds neither either — it decides the rules the
//! others act under, and may not act under them.
//!
//! **The Java code has two answers for a caller with no readable role, and both are ported as they are.** A
//! decision taken by hand (`IssueDecisionService.canApprove`) settles when the caller is not an account or its
//! role is unreadable — "a caller that is not an account keeps the permissive answer it always had"; a VEX import
//! (`VexIngestorService.canApprove`, whose comment says "exactly as IssueDecisionService applies it") queues it.
//! `tests/reference_set.rs` holds both to the Java methods themselves. An unreadable role passes no marker, so
//! neither reaches a route today; the difference is recorded in the crate's README rather than resolved here.

use crate::roles::{Role, role_of};
use crate::visibility::java_trim;

/// The setting's key, `Setting.FOUR_EYES_APPROVAL_REQUIRED`.
pub const SETTING_KEY: &str = "triage_four_eyes_required";

/// Its catalog default: **on**. An installation that never saved the setting requires four-eyes.
pub const DEFAULT: &str = "true";

/// `SettingsService.isEnabled(FOUR_EYES_APPROVAL_REQUIRED)`: the stored value, or the default when there is no row,
/// **compared to `true` exactly**. `row` is `None` when the key has no row; a row holding `NULL` is `Some("")`, as
/// `SettingsService.get` reads it — the stored value wins even when empty, so a cleared row is *off*, not the
/// default. `TRUE` or ` true` stored reads as off: validation lets only `true` and `false` in.
pub fn required(row: Option<&str>) -> bool {
    row.unwrap_or(DEFAULT) == "true"
}

/// `SettingsAdministrationService.isTruthy`, on the value as the save trims it (`String.trim`): what counts as
/// *switching on* for the guards below — wider than what validation then accepts, so `1` or `TRUE` is refused by a
/// guard first when no approver exists, and by the type's validation otherwise (`four-eyes-switch.json`).
///
/// ASCII case folding is `equalsIgnoreCase` here: no character outside ASCII folds to any letter of `true`.
pub fn is_truthy(value: &str) -> bool {
    let value = java_trim(value);
    value.eq_ignore_ascii_case("true") || value == "1"
}

/// Why four-eyes may not be switched on now — the three guards of `SettingsAdministrationService.update`, in their
/// order, each a 422 with the Java sentence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwitchOnRefusal {
    /// No active account may approve: every decision would wait in a queue nobody can empty.
    NoApprover,
    /// Fewer than two may publish a checklist template: under four-eyes its author may not publish it.
    OnePublisher,
    /// Fewer than two may sign off a project checklist: none of its authors may sign it off.
    OneSignatory,
}

impl SwitchOnRefusal {
    pub fn message(self) -> &'static str {
        match self {
            SwitchOnRefusal::NoApprover => {
                "No active account can approve a triage: switching four-eyes on would put every decision in a queue \
                 nobody can empty. Create an administrator, a CISO or a security lead first."
            }
            SwitchOnRefusal::OnePublisher => {
                "Fewer than two active accounts can publish a checklist template: under four-eyes its author may not \
                 publish it, so no draft could ever be published. Create a second platform governor, administrator or \
                 CISO first."
            }
            SwitchOnRefusal::OneSignatory => {
                "Fewer than two active accounts can sign off a project checklist: under four-eyes none of its authors \
                 may sign it off, so a checklist its only approver filled in could never be signed off. Create a \
                 second administrator, CISO or security champion first."
            }
        }
    }
}

/// What [`crate::TriageApprovers`] answered, for [`switch_on_refusal`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApproverCounts {
    pub any_active: bool,
    pub two_can_publish_templates: bool,
    pub two_can_sign_off_checklists: bool,
}

/// **Switching on a two-person control requires that there be two.** `None` when the value does not switch it on,
/// or when it could be honoured; otherwise the first guard that refuses, in the Java order. Switching *off* is never
/// refused: a guard that stops a control being lifted belongs to whoever may lift it (the platform governor, which
/// the settings module checks).
pub fn switch_on_refusal(value: &str, approvers: ApproverCounts) -> Option<SwitchOnRefusal> {
    if !is_truthy(value) {
        None
    } else if !approvers.any_active {
        Some(SwitchOnRefusal::NoApprover)
    } else if !approvers.two_can_publish_templates {
        Some(SwitchOnRefusal::OnePublisher)
    } else if !approvers.two_can_sign_off_checklists {
        Some(SwitchOnRefusal::OneSignatory)
    } else {
        None
    }
}

/// Who took the decision, as the four-eyes rule reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decider {
    /// No account: the system itself, an import with no user.
    NotAnAccount,
    /// An account, with its stored role — possibly unreadable.
    Account { role: String },
}

impl Decider {
    fn role(&self) -> Option<Option<Role>> {
        match self {
            Decider::NotAnAccount => None,
            Decider::Account { role } => Some(role_of(Some(role))),
        }
    }
}

/// `IssueDecisionService.canApprove`: with four-eyes on, only a role that may approve settles a dismissal
/// directly; anybody else's lands as pending. A caller that is not an account, or whose role is unreadable, settles.
pub fn settles_by_hand(four_eyes_required: bool, decider: &Decider) -> bool {
    !four_eyes_required
        || match decider.role() {
            None | Some(None) => true,
            Some(Some(role)) => role.can_approve_triage(),
        }
}

/// `VexIngestorService.canApprove`: the same rule for a VEX import, with the opposite answer for a caller with no
/// readable role — it queues.
pub fn settles_by_import(four_eyes_required: bool, decider: &Decider) -> bool {
    !four_eyes_required
        || match decider.role() {
            None | Some(None) => false,
            Some(Some(role)) => role.can_approve_triage(),
        }
}

/// Why a role may not give an approval — an exception review, a checklist sign-off. Refused before anything is
/// read, so the answer depends on nothing but the role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalRefusal {
    /// The platform governor: it decides the rules and takes no decision under them.
    Governor,
    /// Any other role that may not approve, an unreadable one included.
    NotAnApprover,
}

/// `ExceptionReviewService` and `ProjectChecklistService.signOff`'s first check: `None` when the role may approve.
pub fn approval_refusal(role: Option<Role>) -> Option<ApprovalRefusal> {
    match role {
        Some(role) if role.can_approve_triage() => None,
        Some(role) if role.governs_platform() => Some(ApprovalRefusal::Governor),
        _ => Some(ApprovalRefusal::NotAnApprover),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(role: &str) -> Decider {
        Decider::Account { role: role.into() }
    }

    #[test]
    fn with_four_eyes_off_everybody_settles() {
        for decider in [Decider::NotAnAccount, account("USER"), account("AUDITOR"), account("??")] {
            assert!(settles_by_hand(false, &decider));
            assert!(settles_by_import(false, &decider));
        }
    }

    #[test]
    fn with_four_eyes_on_only_approvers_settle() {
        assert!(settles_by_hand(true, &account("CISO")));
        assert!(settles_by_hand(true, &account("SECURITY_CHAMPION")));
        assert!(!settles_by_hand(true, &account("USER")));
        assert!(!settles_by_hand(true, &account("SUPERUSER")));
        assert!(!settles_by_import(true, &account("AUDITOR")));
    }

    #[test]
    fn the_two_java_answers_for_no_readable_role_differ() {
        assert!(settles_by_hand(true, &Decider::NotAnAccount));
        assert!(settles_by_hand(true, &account("admin")));
        assert!(!settles_by_import(true, &Decider::NotAnAccount));
        assert!(!settles_by_import(true, &account("admin")));
    }

    #[test]
    fn an_absent_row_is_on_and_a_cleared_one_is_off() {
        assert!(required(None));
        assert!(required(Some("true")));
        assert!(!required(Some("")));
        assert!(!required(Some("TRUE")));
    }

    #[test]
    fn switching_off_is_never_refused() {
        let nobody =
            ApproverCounts { any_active: false, two_can_publish_templates: false, two_can_sign_off_checklists: false };
        assert_eq!(switch_on_refusal("false", nobody), None);
        assert_eq!(switch_on_refusal(" TRUE ", nobody), Some(SwitchOnRefusal::NoApprover));
    }

    #[test]
    fn the_governor_is_told_why() {
        assert_eq!(approval_refusal(Some(Role::Superuser)), Some(ApprovalRefusal::Governor));
        assert_eq!(approval_refusal(Some(Role::Auditor)), Some(ApprovalRefusal::NotAnApprover));
        assert_eq!(approval_refusal(None), Some(ApprovalRefusal::NotAnApprover));
        assert_eq!(approval_refusal(Some(Role::SecurityChampion)), None);
    }
}
