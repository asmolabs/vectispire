//! The role model: `common.domain.users.Role` and its six flags.
//!
//! **One `Role` type, the chain's.** `vectispire-cp-http` already names the six roles, because the chain
//! decides the markers before any module is reached; a second enum here would be two lists over one set,
//! and "two lists of administrators disagree the day somebody adds a role to one of them" (`Role.java`).
//! What this module adds is the flags, as a table with **no default arm**: a seventh role does not compile
//! until whoever adds it has answered all six questions.
//!
//! `tests/reference_set.rs` holds the table to what the Java enum answers, and the markers' role lists to the
//! flags they are named after — the Rust of `RouteAuthorizationTest`'s "… agree" tests.

pub use vectispire_cp_http::principal::Role;

/// Every role, in the Java enum's declaration order — the order `Role.values()` iterates in, which decides
/// the order of [`approver_roles`] and [`publisher_roles`] as `TriageApprovers` builds them.
pub const ALL: [Role; 6] =
    [Role::Superuser, Role::Admin, Role::Ciso, Role::SecurityChampion, Role::Auditor, Role::User];

/// The six flags a role carries, positional as the Java constructor takes them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Flags {
    pub administrative: bool,
    pub global_security_scope: bool,
    pub can_approve_triage: bool,
    pub can_write_governance: bool,
    pub can_cause_effects: bool,
    pub governs_platform: bool,
}

const fn flags(
    administrative: bool,
    global_security_scope: bool,
    can_approve_triage: bool,
    can_write_governance: bool,
    can_cause_effects: bool,
    governs_platform: bool,
) -> Flags {
    Flags {
        administrative,
        global_security_scope,
        can_approve_triage,
        can_write_governance,
        can_cause_effects,
        governs_platform,
    }
}

/// The flags of `role` — `Role.java`'s constructor arguments, row for row.
///
/// - `SUPERUSER` governs the platform **and operates nothing**: it may lift four-eyes and cannot act under
///   it, which is what breaks the conjunction "disable, settle alone, switch back on".
/// - `AUDITOR` sees the whole estate and causes no effect, anywhere.
/// - `SECURITY_CHAMPION` approves triage within the scope its teams give it.
pub const fn flags_of(role: Role) -> Flags {
    match role {
        Role::Superuser => flags(true, true, false, true, false, true),
        Role::Admin => flags(true, true, true, true, true, false),
        Role::Ciso => flags(false, true, true, true, true, false),
        Role::SecurityChampion => flags(false, false, true, false, true, false),
        Role::Auditor => flags(false, true, false, false, false, false),
        Role::User => flags(false, false, false, false, true, false),
    }
}

/// The flags as methods, so a check reads `role.has_global_security_scope()` as the Java code does.
pub trait RoleFlags: Copy {
    fn flags(self) -> Flags;

    /// `isAdministrative()`.
    fn administers(self) -> bool {
        self.flags().administrative
    }

    /// `hasGlobalSecurityScope()`: sees the whole estate without being assigned to any of it, **and may read its
    /// governance** — the two travel together on purpose.
    fn has_global_security_scope(self) -> bool {
        self.flags().global_security_scope
    }

    /// `canApproveTriage()`.
    fn can_approve_triage(self) -> bool {
        self.flags().can_approve_triage
    }

    /// `canWriteGovernance()`: may *change* the gate policy, the rule sets, the SIEM destination.
    fn can_write_governance(self) -> bool {
        self.flags().can_write_governance
    }

    /// `canCauseEffects()`: may do something that leaves a trace. False for `AUDITOR` and `SUPERUSER`.
    fn causes_effects(self) -> bool {
        self.flags().can_cause_effects
    }

    /// `governsPlatform()`: may change who sees which targets and whether a write-off needs a second person.
    fn governs_platform(self) -> bool {
        self.flags().governs_platform
    }
}

impl RoleFlags for Role {
    fn flags(self) -> Flags {
        flags_of(self)
    }
}

/// `Role.of`: **case-sensitive**, and `None` for anything else — including `admin` for `ADMIN`. An unreadable
/// stored role authorizes nothing; it is never read as the least privileged role.
pub fn role_of(value: Option<&str>) -> Option<Role> {
    value.and_then(Role::parse)
}

/// The wire spelling of a role, as stored in `t_user.role` and named in a `hasAnyRole` expression.
pub fn name_of(role: Role) -> &'static str {
    match role {
        Role::Superuser => "SUPERUSER",
        Role::Admin => "ADMIN",
        Role::Ciso => "CISO",
        Role::SecurityChampion => "SECURITY_CHAMPION",
        Role::Auditor => "AUDITOR",
        Role::User => "USER",
    }
}

/// `Role.administrative()`: derived from the flag, never listed again.
pub fn administrative_roles() -> Vec<Role> {
    ALL.into_iter().filter(|role| role.administers()).collect()
}

/// `TriageApprovers.APPROVER_ROLES`: the roles that may approve a triage, in enum order.
pub fn approver_roles() -> Vec<Role> {
    ALL.into_iter().filter(|role| role.can_approve_triage()).collect()
}

/// `TriageApprovers.PUBLISHER_ROLES`: the roles that write governance, and so may publish a checklist template.
pub fn publisher_roles() -> Vec<Role> {
    ALL.into_iter().filter(|role| role.can_write_governance()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_governor_can_lift_the_rule_and_cannot_act_under_it() {
        // RouteAuthorizationTest.theGovernorCausesNoEffects: the conjunction is what is broken.
        for role in ALL {
            if role.governs_platform() {
                assert!(!role.causes_effects(), "{role:?} governs and causes effects");
                assert!(!role.can_approve_triage(), "{role:?} governs and approves");
            }
        }
        assert_eq!(ALL.iter().filter(|role| role.governs_platform()).count(), 1);
    }

    #[test]
    fn the_chain_and_the_flags_agree_on_administration_and_effects() {
        // cp-http names `is_administrative` and `can_cause_effects` itself, for the chain; one set, two readers.
        for role in ALL {
            assert_eq!(role.is_administrative(), role.administers(), "{role:?}");
            assert_eq!(role.can_cause_effects(), role.causes_effects(), "{role:?}");
        }
    }

    #[test]
    fn parsing_is_case_sensitive_and_unreadable_is_nothing() {
        assert_eq!(role_of(Some("ADMIN")), Some(Role::Admin));
        assert_eq!(role_of(Some("admin")), None);
        assert_eq!(role_of(Some(" ADMIN")), None);
        assert_eq!(role_of(Some("")), None);
        assert_eq!(role_of(None), None);
        for role in ALL {
            assert_eq!(role_of(Some(name_of(role))), Some(role));
        }
    }
}
