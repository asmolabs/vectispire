#!/usr/bin/env python3
"""Mutation check of Phase 1 task 1.5: the authorization of cp-access (visibility, rows, roles, four eyes, approvers,
the resolution of a principal). The SQL text of the checked statements is not mutated: a changed statement has no
entry in the offline cache and does not compile, which is that guard. See README.md.
"""
import sys

import _runner

SRC = "crates/cp-access/src/"
REF, ENG, UNIT = "authz_reference_set", "authz_on_both_engines", "--lib"

M = [
    # visibility.rs
    ("visibility.rs", "visibility: account.visibility.and(restriction),", "visibility: account.visibility.clone(),",
     "the credential's restriction is not intersected", [REF, ENG]),
    ("visibility.rs", "Ok(assemble(&grants, filed))", "Ok(if grants.is_empty() { Allowance::everything() } else { assemble(&grants, filed) })",
     "no grant read as everything", [ENG]),
    ("visibility.rs", "let narrowed = !matches!(restriction, Visibility::Everything);",
     "let narrowed = !matches!(restriction, Visibility::Everything) && !matches!(account.visibility, Visibility::Everything);",
     "a global account's key is not marked narrowed", [REF]),
    ("visibility.rs", "granted_projects: if narrowed { BTreeSet::new() } else { account.granted_projects },",
     "granted_projects: account.granted_projects,", "a narrowed key keeps the account's projects", [REF]),
    ("visibility.rs", "VisibilityMode::by_wire_name(value).unwrap_or(VisibilityMode::Assigned)",
     "VisibilityMode::by_wire_name(value).unwrap_or(VisibilityMode::Everyone)", "an unreadable mode opens", [REF]),
    ("visibility.rs", "value.trim_matches(|c: char| c <= '\\u{20}')", "value.trim()", "Rust's trim instead of Java's", [REF]),
    ("visibility.rs", "mode == VisibilityMode::Everyone || role_of(Some(role)).is_some_and(RoleFlags::has_global_security_scope)",
     "mode == VisibilityMode::Everyone", "a global role is assigned like any other", [REF, ENG]),
    ("visibility.rs", "        _ => Visibility::only([]),\n    }\n}", "        _ => Visibility::everything(),\n    }\n}",
     "a key of an unknown kind sees everything", [REF]),
    ("visibility.rs", "        // A kind nobody wrote grants nothing.\n        _ => {}",
     "        // A kind nobody wrote grants nothing.\n        _ => {\n            visible.insert(ScanTarget::Repository(grant.id));\n        }",
     "an unknown grant kind reads as a repository", [REF]),
    ("visibility.rs", "let filed = if projects.is_empty() { Vec::new() } else { self.targets.targets_in(&projects).await? };",
     "let filed = Vec::new();", "a granted project's targets are not added", [ENG]),
    # rows.rs
    ("rows.rs", "    if allowance.narrowed_by_credential {\n        return false;\n    }", "",
     "a narrowed key sees a project whole", [REF]),
    ("rows.rs", "(!repository_ids.is_empty()\n                    && ", "(true\n                    && ",
     "every one of none is whole", [REF]),
    ("rows.rs", "                || allowance.granted_projects.contains(&project_id)\n                || !visible.is_empty() =>",
     "                || !visible.is_empty() =>", "a project granted as such is not seen", [REF]),
    ("rows.rs", "(Visibility::Only(_), None) => false,", "(Visibility::Only(_), None) => true,",
     "an unclassifiable row is seen by a restricted reader", [REF]),
    ("rows.rs", "Err(refused(SCAN_NOT_FOUND))", "Err(refused(TARGET_NOT_FOUND))", "a scan refused in another sentence", [REF]),
    # roles.rs
    ("roles.rs", "Role::SecurityChampion => flags(false, false, true, false, true, false),",
     "Role::SecurityChampion => flags(false, false, false, false, true, false),", "a flag of the table flipped", [REF]),
    ("roles.rs", "Role::Superuser => flags(true, true, false, true, false, true),",
     "Role::Superuser => flags(true, true, false, false, false, true),", "the governor writes no governance", [REF, ENG]),
    # four_eyes.rs: settling
    ("four_eyes.rs", "            None | Some(None) => true,", "            None | Some(None) => false,",
     "by hand, no readable role queues", [REF]),
    ("four_eyes.rs", "            None | Some(None) => false,", "            None | Some(None) => true,",
     "an import with no readable role settles", [REF]),
    # four_eyes.rs: the setting and its switch
    ("four_eyes.rs", 'pub const DEFAULT: &str = "true";', 'pub const DEFAULT: &str = "false";',
     "an absent row reads as off", [REF]),
    ("four_eyes.rs", 'row.unwrap_or(DEFAULT) == "true"', 'row.unwrap_or(DEFAULT).eq_ignore_ascii_case("true")',
     "a stored TRUE reads as on", [REF]),
    ("four_eyes.rs", 'row.unwrap_or(DEFAULT) == "true"', 'row.unwrap_or(DEFAULT).trim() == "true"',
     "a stored value is trimmed", [REF]),
    ("four_eyes.rs", 'value.eq_ignore_ascii_case("true") || value == "1"', 'value.eq_ignore_ascii_case("true")',
     "1 does not switch on", [REF]),
    ("four_eyes.rs", 'value.eq_ignore_ascii_case("true") || value == "1"', 'value == "true" || value == "1"',
     "TRUE does not switch on", [REF]),
    ("four_eyes.rs", "    let value = java_trim(value);\n", "",
     "the switch's value is not trimmed", [REF]),
    ("four_eyes.rs", "    } else if !approvers.any_active {\n        Some(SwitchOnRefusal::NoApprover)\n    } else if !approvers.two_can_publish_templates {\n        Some(SwitchOnRefusal::OnePublisher)",
     "    } else if !approvers.two_can_publish_templates {\n        Some(SwitchOnRefusal::OnePublisher)\n    } else if !approvers.any_active {\n        Some(SwitchOnRefusal::NoApprover)",
     "the guards in another order", [REF]),
    ("four_eyes.rs", "    } else if !approvers.two_can_sign_off_checklists {\n        Some(SwitchOnRefusal::OneSignatory)\n", "",
     "the signatories' guard removed", [REF]),
    ("four_eyes.rs", "Create an administrator, a CISO or a security lead first.", "Create an administrator or a CISO first.",
     "a refusal in other words", [REF]),
    # approvers.rs
    ("approvers.rs", "two_can_sign_off_checklists: self.two_can_sign_off_checklists().await?,",
     "two_can_sign_off_checklists: self.two_can_publish_templates().await?,", "the switch asks the wrong count", [ENG]),
    ("approvers.rs", "Ok(self.active_holding(&approver_roles()).await? >= 2)", "Ok(self.active_holding(&approver_roles()).await? > 2)",
     "two signatories are not enough", [ENG]),
    ("approvers.rs", "Ok(self.active_holding(&publisher_roles()).await? >= 2)", "Ok(self.active_holding(&approver_roles()).await? >= 2)",
     "publishers counted as approvers", [ENG]),
    # persistence
    ("persistence/accounts.rs", "        total = total.saturating_add(holding);", "        total = holding;",
     "only the last role counted", [ENG]),
    ("persistence/accounts.rs", "    for role in roles {", "    for role in roles.iter().skip(1) {",
     "the first role not counted", [ENG]),
    ("persistence/grants.rs", "        grants.extend(\n            sqlx::query_as!(\n                Grant,\n                \"/* mysql */",
     "        drop(\n            sqlx::query_as!(\n                Grant,\n                \"/* mysql */",
     "MySQL: the teams' grants dropped", [ENG]),
    ("persistence/grants.rs", "        grants.extend(\n            sqlx::query_as!(\n                Grant,\n                \"/* postgres */",
     "        drop(\n            sqlx::query_as!(\n                Grant,\n                \"/* postgres */",
     "PostgreSQL: the teams' grants dropped", [ENG]),
    # security/mod.rs
    ("security/mod.rs", "            self.resolve(principal).await.map_err(|failure| {",
     "            Ok(self.resolve(principal).await.unwrap_or_else(|failure| {", "a failed lookup read as nothing", [ENG]),
    ("security/mod.rs", "        if matches!(principal.credential, Credential::Agent { .. }) {",
     "        if !matches!(principal.credential, Credential::Agent { .. }) {", "the agent branch inverted", [ENG]),
]

FOLLOW = {"a failed lookup read as nothing": [("                Unavailable\n            })\n", "                Allowance::nothing()\n            }))\n")]}


def _cargo(target):
    return ["-q", "-p", "vectispire-cp-access", "--lib"] if target == UNIT else ["-q", "-p", "vectispire-cp-access", "--test", target]


# The failed-lookup mutant needs its closing changed too (FOLLOW).
MUTANTS = [(what, SRC + path, old, new, [_cargo(t) for t in targets], FOLLOW.get(what, []))
           for path, old, new, what, targets in M]


if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=900, env={"SQLX_OFFLINE": "true"}))
