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

use crate::roles::{Role, RoleFlags, role_of};

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
    fn the_governor_is_told_why() {
        assert_eq!(approval_refusal(Some(Role::Superuser)), Some(ApprovalRefusal::Governor));
        assert_eq!(approval_refusal(Some(Role::Auditor)), Some(ApprovalRefusal::NotAnApprover));
        assert_eq!(approval_refusal(None), Some(ApprovalRefusal::NotAnApprover));
        assert_eq!(approval_refusal(Some(Role::SecurityChampion)), None);
    }
}
