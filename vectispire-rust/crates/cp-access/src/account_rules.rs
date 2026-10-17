//! The rules that stop an administrator from locking themselves out, and the grammar of names and passwords —
//! `common.domain.users.AccountRules` and `Role`, ported with their messages word for word.
//!
//! Pure, as in Java: each describes a situation the interface would happily accept and nobody could come back
//! from. **There is no rescue screen** — with no active administrator left, recovery means a database session.
//! `tests/rules.rs` holds every decision and message to what the Java side answers for the same inputs
//! (`vectispire-rust/reference/accounts/rules.json`).

/// A role and the six flags it carries — `common.domain.users.Role`.
///
/// Here because the account rules read it; the authorization task (Phase 1, 1.5) owns what the flags grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Role {
    Superuser,
    Admin,
    Ciso,
    SecurityChampion,
    Auditor,
    User,
}

impl Role {
    pub const ALL: [Role; 6] =
        [Role::Superuser, Role::Admin, Role::Ciso, Role::SecurityChampion, Role::Auditor, Role::User];

    /// The name stored in `t_user.role` and sent on the wire.
    pub const fn name(self) -> &'static str {
        match self {
            Role::Superuser => "SUPERUSER",
            Role::Admin => "ADMIN",
            Role::Ciso => "CISO",
            Role::SecurityChampion => "SECURITY_CHAMPION",
            Role::Auditor => "AUDITOR",
            Role::User => "USER",
        }
    }

    /// `Role.of`: the exact name, case included; anything else is no role.
    pub fn of(value: Option<&str>) -> Option<Role> {
        let value = value?;
        Role::ALL.into_iter().find(|role| role.name() == value)
    }

    /// `(administrative, globalSecurityScope, canApproveTriage, canWriteGovernance, canCauseEffects,
    /// governsPlatform)`, in `Role`'s constructor order.
    const fn flags(self) -> (bool, bool, bool, bool, bool, bool) {
        match self {
            Role::Superuser => (true, true, false, true, false, true),
            Role::Admin => (true, true, true, true, true, false),
            Role::Ciso => (false, true, true, true, true, false),
            Role::SecurityChampion => (false, false, true, false, true, false),
            Role::Auditor => (false, true, false, false, false, false),
            Role::User => (false, false, false, false, true, false),
        }
    }

    pub const fn is_administrative(self) -> bool {
        self.flags().0
    }
    pub const fn has_global_security_scope(self) -> bool {
        self.flags().1
    }
    pub const fn can_approve_triage(self) -> bool {
        self.flags().2
    }
    pub const fn can_write_governance(self) -> bool {
        self.flags().3
    }
    pub const fn can_cause_effects(self) -> bool {
        self.flags().4
    }
    pub const fn governs_platform(self) -> bool {
        self.flags().5
    }

    /// `Role.administrative()`, in declaration order.
    pub fn administrative() -> Vec<Role> {
        Role::ALL.into_iter().filter(|role| role.is_administrative()).collect()
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.name())
    }
}

pub const MINIMUM_PASSWORD_LENGTH: usize = 12;

/// Whether an account could carry this name — `^[A-Za-z0-9._-]{2,64}$`, matched whole.
///
/// Asked of a name typed at sign-in before the database is: MySQL's `utf8mb4_0900_ai_ci` ignores characters no
/// account name holds — a soft hyphen, the zero-width spaces and joiners, a byte-order mark — so `ali\u{AD}ce`
/// opened `alice`.
pub fn is_well_formed_username(username: Option<&str>) -> bool {
    username.is_some_and(|name| {
        (2..=64).contains(&name.len())
            && name.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    })
}

/// `None` if the name is acceptable, otherwise the message to show.
pub fn validate_username(username: Option<&str>) -> Option<String> {
    match username {
        None | Some("") => Some("A username is required.".to_owned()),
        Some(_) if !is_well_formed_username(username) => {
            Some("Invalid username: 2 to 64 characters, letters, digits, \". _ -\".".to_owned())
        }
        Some(_) => None,
    }
}

/// A minimum length, and nothing else: no composition rule, and no ceiling — bcrypt's 72-byte limit went with
/// bcrypt. The length is Java's `String.length()`, UTF-16 units, so a password of twelve emoji is long enough on
/// both sides and one of six is not.
pub fn validate_password(password: Option<&str>) -> Option<String> {
    match password {
        None | Some("") => Some("A password is required.".to_owned()),
        Some(text) if java_length(text) < MINIMUM_PASSWORD_LENGTH => {
            Some(format!("The password must be at least {MINIMUM_PASSWORD_LENGTH} characters."))
        }
        Some(_) => None,
    }
}

/// `AccountRules.Change`.
///
/// `remaining_active_admins` counts active administrators **other than this account**.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Change {
    pub is_self: bool,
    pub was_admin: bool,
    pub will_be_admin: bool,
    pub will_be_active: bool,
    pub remaining_active_admins: u64,
}

/// `None` if the change is allowed, otherwise why it is refused.
pub fn refuse_self_lockout(change: Change) -> Option<String> {
    if change.is_self && !change.will_be_active {
        return Some("You cannot deactivate your own account.".to_owned());
    }
    if change.is_self && change.was_admin && !change.will_be_admin {
        return Some("You cannot remove your own administrator role.".to_owned());
    }
    let loses_admin = change.was_admin && (!change.will_be_admin || !change.will_be_active);
    if loses_admin && change.remaining_active_admins == 0 {
        return Some(
            "This is the last active administrator: removing them would leave Vectispire with nobody able to \
             administer it."
                .to_owned(),
        );
    }
    None
}

/// Only a platform governor may grant, remove or administer the platform governor role: the separation of duties
/// rests on it (`AccountRules.refuseGovernorAdministration`).
///
/// `acting` is the acting account's role, `None` when the caller is not an account; `current` the target's role
/// before the change, `None` for an account being created; `next` its role after, `None` when untouched.
pub fn refuse_governor_administration(
    acting: Option<Role>,
    current: Option<Role>,
    next: Option<Role>,
) -> Option<String> {
    let touches_governor = current.is_some_and(Role::governs_platform) || next.is_some_and(Role::governs_platform);
    if touches_governor && !acting.is_some_and(Role::governs_platform) {
        return Some(
            "Only a platform governor can grant, remove or administer the platform governor role: it is the role \
             that lifts the rules the others act under."
                .to_owned(),
        );
    }
    None
}

/// Nobody changes their own role, up or down.
pub fn refuse_own_role_change(is_self: bool, current_role: Option<&str>, next_role: Option<&str>) -> Option<String> {
    match next_role {
        Some(next) if is_self && !java_equals_ignore_case(next, current_role) => {
            Some("You cannot change your own role: another administrator has to.".to_owned())
        }
        _ => None,
    }
}

/// Likewise for deletion, whose consequences are the same but worse.
pub fn refuse_deletion(is_self: bool, is_admin: bool, remaining_active_admins: u64) -> Option<String> {
    if is_self {
        return Some("You cannot delete your own account.".to_owned());
    }
    if is_admin && remaining_active_admins == 0 {
        return Some(
            "This is the last active administrator: deleting them would leave Vectispire with nobody able to \
             administer it."
                .to_owned(),
        );
    }
    None
}

/// `String.length()`: UTF-16 code units.
pub fn java_length(text: &str) -> usize {
    text.encode_utf16().count()
}

/// `String.trim()`: every leading and trailing character up to U+0020, and nothing else — not the Unicode
/// spaces Rust's `trim` also removes. A name typed with a non-breaking space keeps it, and is refused by the
/// grammar, as in Java.
pub fn java_trim(text: &str) -> &str {
    text.trim_matches(|character: char| character <= ' ')
}

/// `String.toUpperCase(Locale.ROOT)`.
pub fn java_upper(text: &str) -> String {
    text.to_uppercase()
}

/// `String.equalsIgnoreCase`: same length in UTF-16 units, and each unit equal, or equal once upper-cased, or
/// once lower-cased.
fn java_equals_ignore_case(next: &str, current: Option<&str>) -> bool {
    let Some(current) = current else {
        return false;
    };
    let (left, right): (Vec<u16>, Vec<u16>) = (next.encode_utf16().collect(), current.encode_utf16().collect());
    left.len() == right.len()
        && left.iter().zip(&right).all(|(&a, &b)| {
            a == b || {
                let (upper_a, upper_b) = (unit_upper(a), unit_upper(b));
                upper_a == upper_b || unit_lower(upper_a) == unit_lower(upper_b)
            }
        })
}

/// `Character.toUpperCase(char)` on one UTF-16 unit: a surrogate, or a character whose upper case is not one
/// unit, stays as it is.
fn unit_upper(unit: u16) -> u16 {
    single_unit(char::from_u32(u32::from(unit)).map(|character| character.to_uppercase().collect()), unit)
}

fn unit_lower(unit: u16) -> u16 {
    single_unit(char::from_u32(u32::from(unit)).map(|character| character.to_lowercase().collect()), unit)
}

fn single_unit(mapped: Option<String>, unit: u16) -> u16 {
    let Some(mapped) = mapped else {
        return unit;
    };
    let units: Vec<u16> = mapped.encode_utf16().collect();
    match units.as_slice() {
        [single] => *single,
        _ => unit,
    }
}
