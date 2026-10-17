//! Every account rule, message and text transformation against what the Java side answers
//! (`vectispire-rust/reference/accounts/rules.json`, written by `AccountsReferenceSetTest`).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use serde_json::Value;
use vectispire_cp_access::account_rules::{
    self, Change, Role, RoleFlags, is_well_formed_username, java_length, java_trim, java_upper, refuse_deletion,
    refuse_governor_administration, refuse_own_role_change, refuse_self_lockout, validate_password, validate_username,
};

fn rules() -> Value {
    let file = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../reference/accounts/rules.json");
    serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap()
}

fn text(value: &Value) -> Option<&str> {
    value.as_str()
}

fn role(value: &Value) -> Option<Role> {
    value.as_str().map(|name| Role::of(Some(name)).unwrap_or_else(|| panic!("unknown role {name}")))
}

#[test]
fn usernames() {
    let rules = rules();
    let entries = rules["usernames"].as_array().unwrap();
    assert!(entries.len() >= 20);
    for entry in entries {
        let name = text(&entry["name"]);
        assert_eq!(is_well_formed_username(name), entry["wellFormed"].as_bool().unwrap(), "{name:?}");
        assert_eq!(validate_username(name).as_deref(), text(&entry["refusal"]), "{name:?}");
    }
}

#[test]
fn passwords() {
    let rules = rules();
    for entry in rules["passwords"].as_array().unwrap() {
        let candidate = text(&entry["candidate"]);
        assert_eq!(validate_password(candidate).as_deref(), text(&entry["refusal"]), "{candidate:?}");
    }
}

#[test]
fn trimming_upper_casing_lengths_and_bounding() {
    let rules = rules();
    for entry in rules["texts"].as_array().unwrap() {
        let original = entry["text"].as_str().unwrap();
        let trimmed = java_trim(original);
        assert_eq!(trimmed, entry["trim"].as_str().unwrap(), "trim of {original:?}");
        let upper = java_upper(trimmed);
        assert_eq!(upper, entry["upper"].as_str().unwrap(), "upper of {original:?}");
        assert_eq!(java_length(original) as u64, entry["length"].as_u64().unwrap(), "length of {original:?}");
        assert_eq!(Role::of(Some(&upper)).map(Role::name), text(&entry["role"]), "role of {original:?}");
        let bounded = if trimmed.is_empty() {
            None
        } else if java_length(trimmed) > 5 {
            Some("refused: The label is longer than 5 characters.".to_owned())
        } else {
            Some(trimmed.to_owned())
        };
        assert_eq!(bounded.as_deref(), text(&entry["boundedTo5"]), "bounded {original:?}");
    }
}

#[test]
fn roles_and_their_flags() {
    let rules = rules();
    let entries = rules["roles"].as_array().unwrap();
    assert_eq!(entries.len(), Role::ALL.len());
    for (entry, role) in entries.iter().zip(Role::ALL) {
        assert_eq!(entry["name"].as_str().unwrap(), role.name());
        assert_eq!(entry["administrative"].as_bool().unwrap(), role.is_administrative(), "{role}");
        assert_eq!(entry["globalSecurityScope"].as_bool().unwrap(), role.has_global_security_scope(), "{role}");
        assert_eq!(entry["canApproveTriage"].as_bool().unwrap(), role.can_approve_triage(), "{role}");
        assert_eq!(entry["canWriteGovernance"].as_bool().unwrap(), role.can_write_governance(), "{role}");
        assert_eq!(entry["canCauseEffects"].as_bool().unwrap(), role.can_cause_effects(), "{role}");
        assert_eq!(entry["governsPlatform"].as_bool().unwrap(), role.governs_platform(), "{role}");
    }
    for entry in rules["roleOf"].as_array().unwrap() {
        let name = entry["text"].as_str().unwrap();
        assert_eq!(Role::of(Some(name)).map(Role::name), text(&entry["role"]), "{name:?}");
    }
    assert_eq!(Role::administrative(), vec![Role::Superuser, Role::Admin]);
}

#[test]
fn self_lockout() {
    let rules = rules();
    let entries = rules["selfLockout"].as_array().unwrap();
    assert_eq!(entries.len(), 32);
    for entry in entries {
        let change = Change {
            is_self: entry["isSelf"].as_bool().unwrap(),
            was_admin: entry["wasAdmin"].as_bool().unwrap(),
            will_be_admin: entry["willBeAdmin"].as_bool().unwrap(),
            will_be_active: entry["willBeActive"].as_bool().unwrap(),
            remaining_active_admins: entry["remaining"].as_u64().unwrap(),
        };
        assert_eq!(refuse_self_lockout(change).as_deref(), text(&entry["refusal"]), "{change:?}");
    }
}

#[test]
fn governor_administration() {
    let rules = rules();
    let entries = rules["governor"].as_array().unwrap();
    assert_eq!(entries.len(), 7 * 7 * 7);
    for entry in entries {
        let (acting, current, next) = (role(&entry["acting"]), role(&entry["current"]), role(&entry["next"]));
        assert_eq!(
            refuse_governor_administration(acting, current, next).as_deref(),
            text(&entry["refusal"]),
            "{acting:?} {current:?} {next:?}"
        );
    }
}

#[test]
fn own_role_change() {
    let rules = rules();
    let entries = rules["ownRoleChange"].as_array().unwrap();
    assert!(entries.len() > 200);
    for entry in entries {
        let is_self = entry["isSelf"].as_bool().unwrap();
        let (current, next) = (text(&entry["current"]), text(&entry["next"]));
        // Java's `nextRole.equalsIgnoreCase(null)` is false, not a throw: no entry says "throws".
        assert_eq!(
            refuse_own_role_change(is_self, current, next).as_deref(),
            text(&entry["refusal"]),
            "{is_self} {current:?} {next:?}"
        );
    }
}

#[test]
fn deletion() {
    let rules = rules();
    for entry in rules["deletion"].as_array().unwrap() {
        let (is_self, is_admin) = (entry["isSelf"].as_bool().unwrap(), entry["isAdmin"].as_bool().unwrap());
        let remaining = entry["remaining"].as_u64().unwrap();
        assert_eq!(refuse_deletion(is_self, is_admin, remaining).as_deref(), text(&entry["refusal"]));
    }
}

#[test]
fn the_minimum_is_twelve() {
    assert_eq!(account_rules::MINIMUM_PASSWORD_LENGTH, 12);
}
