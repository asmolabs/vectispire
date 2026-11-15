#!/usr/bin/env python3
"""Mutation check of Phase 2 task 2.9: the agents module — the administration's trimming, refusals and audit sentences
(held to Java by `reference/agents/administration.json`), the key a removal revokes, the claim's `wait` bound as Spring
binds it, a database failure at authentication kept apart from a refusal, the signs of life, the long poll, the
heartbeat's owner, and the crypto crate's key padding. See README.md.

Killed by `cp-agents`' `administration_reference` and `protocol_lifecycle` (MySQL, Docker required), its `read` unit
test, and `crypto`'s `key_padding`.
"""
import sys

import _runner

ADMIN = "crates/cp-agents/src/internal/admin_service.rs"
SERVICE = "crates/cp-agents/src/internal/protocol_service.rs"
POLLER = "crates/cp-agents/src/internal/poller.rs"
WEB = "crates/cp-agents/src/web/protocol.rs"
READ = "crates/cp-agents/src/web/read.rs"
CRYPTO = "crates/crypto/src/lib.rs"

REFERENCE = ["-p", "vectispire-cp-agents", "--test", "administration_reference"]
LIFECYCLE = ["-p", "vectispire-cp-agents", "--test", "protocol_lifecycle"]
UNIT = ["-p", "vectispire-cp-agents", "--lib", "read"]
KEYS = ["-p", "vectispire-crypto", "--test", "key_padding"]

MUTANTS = [
    # ── the administration, against Java's answers ──
    ("a name trimmed of every space", ADMIN,
     "let name = java::trim(&declaration.name);", "let name = declaration.name.trim();", REFERENCE),
    ("a mode looked up trimmed of every space", ADMIN,
     "CredentialsMode::by_wire_name(Some(java::trim(raw)))", "CredentialsMode::by_wire_name(Some(raw.trim()))",
     REFERENCE),
    ("an unknown mode quoted trimmed", ADMIN,
     'AgentError::invalid(format!("Unknown credentials mode: \\"{raw}\\"."))',
     'AgentError::invalid(format!("Unknown credentials mode: \\"{}\\".", java::trim(raw)))', REFERENCE),
    ("a pinned key trimmed of every space", ADMIN,
     'let supplied = java::trim(public_key.unwrap_or(""));', 'let supplied = public_key.unwrap_or("").trim();',
     REFERENCE),
    ("a relabelling is not audited", ADMIN, "        if labels != agent.labels {", "        if false {", REFERENCE),
    ("a limit compared as applied, not as stored", ADMIN,
     "        if max_concurrent != agent.max_concurrent {",
     "        if concurrency::effective(max_concurrent.map(i64::from))\n"
     "            != concurrency::effective(agent.max_concurrent.map(i64::from))\n        {",
     REFERENCE),
    ("one running scan does not hold a removal", ADMIN, "        if running > 0 {", "        if running > 1 {",
     REFERENCE),
    ("a removal leaves the key", ADMIN,
     "            self.credentials.revoke_key(key_id).await.map_err(|failure| AgentError::Unexpected(Box::new(failure)))?;",
     "            let _ = key_id;", REFERENCE),

    # ── the claim's wait ──
    ("an unbindable wait is no wait", WEB,
     "                    Ok(wait) => wait,\n                    Err(problem) => return problem.into_response(),",
     "                    Ok(wait) => wait,\n                    Err(_) => 0,", LIFECYCLE),
    ("an empty wait is refused", READ, "        Some(raw) if raw.is_empty() => Ok(0),\n", "", UNIT),
    ("a wait past an int wraps", READ,
     "value = value.checked_mul(radix)?.checked_sub(i32::try_from(digit).ok()?)?;",
     "value = value.wrapping_mul(radix).wrapping_sub(i32::try_from(digit).ok()?);", UNIT),
    ("the long poll does not wait", POLLER,
     "let wait = if wait_seconds < 0 { Duration::ZERO } else { Duration::seconds(wait_seconds as i64).min(MAX_WAIT) };",
     "let wait = Duration::ZERO;", LIFECYCLE),

    # ── authentication ──
    ("an unreadable database is the agent's fault", SERVICE,
     ".map_err(|failure| NotAuthenticated::Failed(Box::new(failure)))?",
     ".map_err(|_| NotAuthenticated::Refused(refusals::not_an_agent()))?", LIFECYCLE),

    # ── signs of life, and the lease's owner ──
    ("an idle poll is no sign of life", POLLER, "        self.protocol.heard_from(agent).await;\n", "", LIFECYCLE),
    ("a renewal is no sign of life", SERVICE,
     "        self.heard_from(agent).await;\n        let claiming = to_claiming_agent(agent);\n        self.dispatcher.renew_agent_lease",
     "        let claiming = to_claiming_agent(agent);\n        self.dispatcher.renew_agent_lease", LIFECYCLE),
    ("every poll rewrites the sign", SERVICE,
     "let stale_before = now.checked_sub(SEEN_GRANULARITY).unwrap_or(now);", "let stale_before = now;", LIFECYCLE),
    ("a lost lease is renewed anyway", WEB,
     "                        Ok(true) => no_content(),\n                        Ok(false) => Problem::handler(",
     "                        Ok(_) => no_content(),\n                        #[allow(unreachable_patterns)]\n"
     "                        Ok(false) => Problem::handler(", LIFECYCLE),

    # ── the keys' padding ──
    ("a signing key trimmed of every space", CRYPTO,
     "BASE64.decode(value.trim_matches(|c: char| c <= ' ')).ok()?", "BASE64.decode(value.trim()).ok()?", KEYS),
    ("a sealing key read trimmed", CRYPTO,
     "    let raw = BASE64.decode(value).ok()?;\n    (raw.len() == SPKI_LENGTH)",
     "    let raw = BASE64.decode(value.trim()).ok()?;\n    (raw.len() == SPKI_LENGTH)", KEYS),
]

# Not listed:
# - a mode blank as `str` says rather than as `String.isBlank`: they differ only on a no-break space alone, which no
#   case of the reference set sends — its padded no-break space is refused either way, by the lookup.
# - a failed revocation ignored rather than refused: no test makes `access`' delete fail; the order (key first) is held
#   by `a_removed_agent_takes_its_key_with_it` only as far as the key going at all.
# - the statements' own conditions (`record_seen`'s staleness, `accept_sealing_key`'s generations): a changed
#   statement is not in the checked cache and does not compile offline, so it proves nothing about the tests; the
#   engine tests hold them (`engines.rs`, `protocol_lifecycle.rs`).

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=900, env={"VECTISPIRE_TEST_ENGINES": "mysql"}))
