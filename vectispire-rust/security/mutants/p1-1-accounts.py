#!/usr/bin/env python3
"""Mutation check of Phase 1 task 1.1: accounts in cp-access (passwords, account rules, the service, the user store).
Each mutant must turn a test red. See README.md.
"""
import sys

import _runner

S = "crates/cp-access/src/"
UNIT = ["--test", "passwords", "--test", "rules", "--test", "service", "--lib"]
ENG = ["--test", "engines"]
M = [
    ("algorithm not checked", S + "passwords.rs", 'if *algorithm != "argon2id" {', "if false {", UNIT),
    ("trailing empties kept", S + "passwords.rs", "while parts.last().is_some_and(|part| part.is_empty()) {", "while false {", UNIT),
    ("rehash ignores t", S + "passwords.rs", "memory < i64::from(MEMORY_KIB) || iterations < i64::from(ITERATIONS)", "memory < i64::from(MEMORY_KIB)", UNIT),
    ("prefix compare", S + "passwords.rs", "actual.as_slice().ct_eq(expected.as_slice()).into()", "expected.len() >= 16 && actual.as_slice()[..16] == expected.as_slice()[..16]", UNIT),
    ("no memory ceiling", S + "passwords.rs", "if memory_kib > MAX_MEMORY_KIB {", "if false {", ["--test", "passwords"]),
    ("password length in bytes", S + "account_rules.rs", "Some(text) if java_length(text) < MINIMUM_PASSWORD_LENGTH", "Some(text) if text.len() < MINIMUM_PASSWORD_LENGTH", UNIT),
    ("Rust trim", S + "account_rules.rs", "text.trim_matches(|character: char| character <= ' ')", "text.trim()", UNIT),
    ("lockout ignores deactivation", S + "account_rules.rs", "(!change.will_be_admin || !change.will_be_active)", "!change.will_be_admin", UNIT),
    ("anyone administers a governor", S + "account_rules.rs", "!acting.is_some_and(Role::governs_platform)", "false", UNIT),
    ("one-character names", S + "account_rules.rs", "(2..=64).contains(&name.len())", "(1..=64).contains(&name.len())", UNIT),
    ("case-sensitive role compare", S + "account_rules.rs", "!java_equals_ignore_case(next, current_role)", "Some(next) != current_role", UNIT),
    ("role change keeps sessions", S + "accounts.rs", "let revoke = !is_active || password.is_some() || role != previous_role;", "let revoke = !is_active || password.is_some();", UNIT),
    ("reset keeps the keys", S + "accounts.rs", "let revoked = self.store.save_revoking_everything(&user).await?;", "let revoked = { self.store.save(&user, true).await?; Vec::new() };", UNIT),
    ("lift keeps the password", S + "accounts.rs", "user.password = Some(PasswordHash::new(passwords::hash_of_nothing_anybody_knows()));", "user.password = user.password.clone();", UNIT),
    ("lift keeps the sessions", S + "accounts.rs", "self.store.save(&user, true).await?;", "self.store.save(&user, false).await?;", UNIT),
    ("right proof not cleared", S + "accounts.rs", "attempts.clear(user.id).await?;", "", UNIT),
    ("same password accepted", S + "accounts.rs", "if Some(new_password) == current_password {", "if false {", UNIT),
    ("ill-formed names looked up", S + "accounts.rs", "Some(name) if account_rules::is_well_formed_username(Some(name)) => {", "Some(name) => {", UNIT),
    ("no rehash", S + "accounts.rs", "if passwords::needs_rehash(user.password.as_ref().map(PasswordHash::encoded)) {", "if false {", UNIT),
    ("created without the flag", S + "accounts.rs", "            must_change_password: true,\n            created_at,", "            must_change_password: false,\n            created_at,", UNIT),
    ("save ignores the revocation", S + "persistence/users.rs", "        if revoke_sessions {", "        if false {", ENG),
    ("no session named closes all", S + "persistence/users.rs", "if let Some(keep) = &keep_session {\n            self.credentials.delete_sessions_except(&mut tx, user_id, keep).await?;\n        }",
     "if let Some(keep) = &keep_session {\n            self.credentials.delete_sessions_except(&mut tx, user_id, keep).await?;\n        } else {\n            self.credentials.delete_sessions(&mut tx, user_id).await?;\n        }", ENG),
]

MUTANTS = [(n, p, o, nw, ["-p", "vectispire-cp-access", "--release", *t]) for n, p, o, nw, t in M]


if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=900))
