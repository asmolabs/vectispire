#!/usr/bin/env python3
"""Mutation check of Phase 1 task 1.2: the credentials of cp-access (sessions, keys, the agent and integration scopes).
Each mutant must turn a test red; one that does not compile is reported apart. See README.md.
"""
import sys

import _runner

SRC = "crates/cp-access/src/internal/credentials/"
TESTS = ["-p", "vectispire-cp-access", "--lib", "--test", "reference_set", "--test", "credentials_on_both_engines"]

M = [
    ("hash of the token", "sessions.rs", "hex(&Sha256::digest(presented.as_bytes()))", "hex(&Sha256::digest(presented.trim().as_bytes()))"),
    ("scheme case ignored", "sessions.rs", 'java_trim(header?).strip_prefix("Bearer ")?', 'java_trim(header?).strip_prefix("Bearer ").or_else(|| java_trim(header?).strip_prefix("bearer "))?'),
    ("whitespace in a session token", "sessions.rs", "!token.is_empty() && !token.chars().any(is_java_regex_space)", "!token.is_empty()"),
    ("absolute lifetime off by its edge", "sessions.rs", "if now >= plus(created_at, policy.absolute_lifetime) {", "if now > plus(created_at, policy.absolute_lifetime) {"),
    ("idle window ignored", "sessions.rs", "if now >= plus(last_seen_at, policy.idle_lifetime) {", "if false && now >= plus(last_seen_at, policy.idle_lifetime) {"),
    ("activity grain", "sessions.rs", "checked_div(60)", "checked_div(30)"),
    ("expired session kept", "mod.rs", "        if !sessions::is_active(row.created_at, row.last_seen_at, now, &self.policy) {\n            session_store::delete(&self.db, &row.token_hash).await?;\n", "        if !sessions::is_active(row.created_at, row.last_seen_at, now, &self.policy) {\n"),
    ("inactive account's session kept", "mod.rs", "                self.revoke(&session).await?;\n", ""),
    ("inactive account honoured", "mod.rs", ".filter(|row| row.is_active).map(AccountView::of)", ".map(AccountView::of)"),
    ("expired key accepted", "mod.rs", "            if candidate.expires_at.is_some_and(|expires| expires <= as_of) {\n                return Ok(None);\n            }\n", ""),
    ("expired key's use recorded", "mod.rs", "            // Refused, and its row kept: the audit trail needs to know it existed.\n            if candidate.expires_at", "            key_store::mark_used(&self.db, candidate.id, as_of).await?;\n            if candidate.expires_at"),
    ("agent key as integration", "mod.rs", "        if key.has_scope(ApiKeyScope::Agent) {\n            return Ok(None);\n        }\n        let Some(owner)", "        let Some(owner)"),
    # Removed at the Phase 1 merge: "agent key without agent falls through" is an equivalent mutant. An agent key
    # with no agent that falls through reaches `integration_for`, whose first line refuses any key with the agent
    # scope (`Ok(None)`, before any statement) — the same answer the original returns, so no test can tell them apart.
    # Its guard is pinned by "agent key as integration" below.
    ("unknown target kind sees everything", "api_keys.rs", "(Some(_), Some(_)) => Visibility::only([]),", "(Some(_), Some(_)) => Visibility::everything(),"),
    ("SCIM switched off still matches", "mod.rs", "self.scim.enabled && self.scim.token", "self.scim.token"),
    ("SCIM compared by prefix", "mod.rs", "is_some_and(|expected| secret_equals(token, expected.expose()))", "is_some_and(|expected| expected.expose().starts_with(token))"),
    ("PHC algorithm not checked", "phc.rs", 'if *algorithm != "argon2id" {', 'if algorithm.is_empty() {'),
    ("PHC digest compared by prefix", "phc.rs", "actual.as_slice().ct_eq(expected.as_slice()).into()", "actual.starts_with(&expected)"),
    ("prefix alone is a key", "api_keys.rs", "if utf16_len(trimmed) <= PREFIX_LENGTH {", "if utf16_len(trimmed) < PREFIX_LENGTH {"),
    ("agent scope issued", "mod.rs", "        if scopes.contains(&ApiKeyScope::Agent) {", "        if false && scopes.contains(&ApiKeyScope::Agent) {"),
    ("restriction not checked", "mod.rs", "            && !targets.issuer_sees(owner, target).await?", "            && false"),
    ("session lives for the idle window", "mod.rs", "expires_at: plus(now, self.policy.absolute_lifetime),", "expires_at: plus(now, self.policy.idle_lifetime),"),
    ("hand-off exchanged twice", "mod.rs", "if session_store::delete(&self.db, &handoff.token_hash).await? != 1 {", "if session_store::delete(&self.db, &handoff.token_hash).await? > 1 {"),
    ("hand-off edge", "mod.rs", "if plus(row.created_at, HANDOFF_LIFETIME) < self.clock.now() {", "if plus(row.created_at, HANDOFF_LIFETIME) <= self.clock.now() {"),
    ("other sessions: the kept one too", "mod.rs", "session_store::delete_by_user_except(&self.db, user_id, keep_token_hash).await", "session_store::delete_by_user(&self.db, user_id).await"),
    ("role read without case", "mod.rs", "role: Role::parse(&row.role),", "role: Role::parse(&row.role.to_ascii_uppercase()),"),
    ("pending password change dropped", "mod.rs", "must_change_password: row.must_change_password,", "must_change_password: false,"),
    ("stored hash authenticates", "mod.rs", "        let Some(row) = session_store::find(&self.db, &sessions::hash_of(token)).await? else {\n            return Ok(None);\n        };", "        let Some(row) = (match session_store::find(&self.db, &sessions::hash_of(token)).await? { Some(row) => Some(row), None => session_store::find(&self.db, token).await? }) else {\n            return Ok(None);\n        };"),
]

MUTANTS = [(n, SRC + f, o, nw, TESTS) for n, f, o, nw in M]


if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=900))
