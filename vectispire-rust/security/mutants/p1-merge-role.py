#!/usr/bin/env python3
"""Mutation check of the code the Phase 1 merge changed: the one `Role` (cp-http) and what reads it in cp-access.
Taken from the 1.1, 1.5 and 1.2 lists where a mutant touches that code, plus mutants of the behaviour moved onto
cp-http's Role. Each must turn a test red. See README.md.
"""
import sys

import _runner

A = "crates/cp-access/src/"
H = "crates/cp-http/src/principal.rs"
UNIT = ["-p", "vectispire-cp-access", "--lib", "--test", "rules", "--test", "service", "--test", "passwords",
        "--test", "authz_reference_set", "--test", "reference_set"]
ENG = ["-p", "vectispire-cp-access", "--test", "authz_on_both_engines", "--test", "engines", "--test", "credentials_on_both_engines"]
MUTANTS = [
    # p1acc-mutate.py, the two that read the role
    ("anyone administers a governor", A + "account_rules.rs", "!acting.is_some_and(Role::governs_platform)", "false", UNIT),
    ("case-sensitive role compare", A + "account_rules.rs", "!java_equals_ignore_case(next, current_role)", "Some(next) != current_role", UNIT),
    # mutate-authz.py, roles.rs
    ("a flag of the table flipped", A + "roles.rs", "Role::SecurityChampion => flags(false, false, true, false, true, false),",
     "Role::SecurityChampion => flags(false, false, false, false, true, false),", UNIT),
    ("the governor writes no governance", A + "roles.rs", "Role::Superuser => flags(true, true, false, true, false, true),",
     "Role::Superuser => flags(true, true, false, false, false, true),", UNIT),
    # p1c-mutate.py, the role a session's account carries
    ("role read without case", A + "internal/credentials/mod.rs", "role: Role::parse(&row.role),",
     "role: Role::parse(&row.role.to_ascii_uppercase()),", UNIT + ["--test", "credentials_on_both_engines"]),
    # The behaviour moved from the accounts' enum onto cp-http's Role
    ("a role's name misspelt", H, 'Role::SecurityChampion => "SECURITY_CHAMPION",', 'Role::SecurityChampion => "SECURITY-CHAMPION",', UNIT),
    ("Role.of without case", H, "value.and_then(Role::parse)", "value.and_then(|value| Role::parse(&value.to_ascii_uppercase()))", UNIT),
    ("administrative() from another flag", H, ".filter(|role| role.is_administrative())", ".filter(|role| role.can_cause_effects())", UNIT),
    ("ALL out of declaration order", H, "[Role::Superuser, Role::Admin, Role::Ciso, Role::SecurityChampion, Role::Auditor, Role::User];",
     "[Role::Superuser, Role::Admin, Role::SecurityChampion, Role::Ciso, Role::Auditor, Role::User];", UNIT),
    ("roles::name_of not the type's", A + "roles.rs", "    role.name()\n", '    if role == Role::User { "USER " } else { role.name() }\n', UNIT),
    ("roles::role_of not the type's", A + "roles.rs", "    Role::of(value)\n", "    Role::of(value.map(str::trim))\n", UNIT),
    ("Display is the variant", H, "formatter.write_str(self.name())", 'write!(formatter, "{self:?}")', UNIT),
]


if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=1800))
