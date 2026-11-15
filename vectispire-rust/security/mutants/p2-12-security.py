#!/usr/bin/env python3
"""Mutation check of Phase 2 task 2.12: the guards the Phase 2 security review added — an agent's key authenticating
its own row, keys of small order refused, the scanners' configuration files taken out of the clone, a repository URL
refused when it names one of Vectispire's own endpoints, one-time secrets kept out of `Debug`. See README.md and
`security/reviews/2026-11-phase-2.md`.

Killed by `cp-agents`' `protocol_lifecycle` and `cp-access`' `credentials_on_both_engines` (MySQL, Docker required),
`crypto`'s `small_order`, `runner`'s unit tests, the domain's `git_host_allowlist` tests, `cp-app`'s
`clone_hosts_composition` and `cp-agents`' `admin_service` unit test.
"""
import sys

import _runner

WEB = "crates/cp-agents/src/web/protocol.rs"
SERVICE = "crates/cp-agents/src/internal/protocol_service.rs"
ADMIN = "crates/cp-agents/src/internal/admin_service.rs"
RESOLVED = "crates/cp-access/src/internal/credentials/mod.rs"
CRYPTO = "crates/crypto/src/lib.rs"
FILES = "crates/runner/src/configuration_files.rs"
RUNNER = "crates/runner/src/lib.rs"
ALLOWLIST = "crates/domain/src/git_host_allowlist.rs"
URL = "crates/domain/src/repository_url.rs"
GUARD = "crates/cp-outbound/src/guard.rs"
HOSTS = "crates/cp-app/src/clone_hosts.rs"

LIFECYCLE = ["-p", "vectispire-cp-agents", "--test", "protocol_lifecycle"]
CREDENTIALS = ["-p", "vectispire-cp-access", "--test", "credentials_on_both_engines"]
SMALL_ORDER = ["-p", "vectispire-crypto", "--test", "small_order"]
RUNNER_UNIT = ["-p", "vectispire-runner", "--lib"]
DOMAIN = ["-p", "vectispire-domain", "--lib", "git_host_allowlist"]
COMPOSITION = ["-p", "vectispire-cp-app", "--test", "clone_hosts_composition"]
SECRETS = ["-p", "vectispire-cp-agents", "--lib", "the_one_time_secrets"]

MUTANTS = [
    # ── H1: an agent's key is its own row's ──
    ("the protocol reads the name, not the row's id", WEB,
     "Credential::Agent { agent_id, .. } => agent_id,", "Credential::Agent { agent, .. } => agent,", LIFECYCLE),
    ("the principal carries the name, not the row's id", RESOLVED,
     'Principal::agent(&format!("agent:{}", agent.name), &agent.id.as_hyphenated().to_string())',
     'Principal::agent(&format!("agent:{}", agent.name), &agent.name)', CREDENTIALS),
    ("a disabled agent is authenticated", SERVICE,
     "        if !row.enabled {\n            return Err(NotAuthenticated::Refused(refusals::disabled(&row.name)));",
     "        if false {\n            return Err(NotAuthenticated::Refused(refusals::disabled(&row.name)));", LIFECYCLE),

    # ── M2, M3: keys of small order ──
    ("a weak signing key verifies", CRYPTO,
     "    if key.is_weak() {\n        return false;\n    }", "", SMALL_ORDER),
    ("sealed to a recipient of small order", CRYPTO,
     "    if !shared.was_contributory() {\n        return Err(CryptoError::Recipient);\n    }", "", SMALL_ORDER),
    ("opened from an ephemeral key of small order", CRYPTO,
     "        if !shared.was_contributory() {\n            return None;\n        }", "", SMALL_ORDER),

    # ── H2: the scanners' configuration files ──
    ("the tree is not cleared before the scanners", RUNNER,
     "    let removed = configuration_files::remove_from(source).map_err(",
     "    let removed: Result<Vec<String>, std::io::Error> = Ok(Vec::new());\n"
     "    let _ = configuration_files::remove_from;\n    let removed = removed.map_err(", RUNNER_UNIT),
    ("a .checkov.yaml stays", FILES, '".checkov.yaml", ".checkov.yml"', '".checkov.yaml.kept", ".checkov.yml"',
     RUNNER_UNIT),
    ("a .checkov.yml stays", FILES, '".checkov.yaml", ".checkov.yml"', '".checkov.yaml", ".checkov.yml.kept"',
     RUNNER_UNIT),
    ("a .gitleaksignore stays", FILES, '".gitleaksignore", ".semgrepignore"]', '".gitleaksignore.kept", ".semgrepignore"]',
     RUNNER_UNIT),
    ("a .semgrepignore stays", FILES, '".gitleaksignore", ".semgrepignore"]', '".gitleaksignore", ".semgrepignore.kept"]',
     RUNNER_UNIT),
    ("only the top of the clone is cleared", FILES, "                    pending.push(path);\n", "", RUNNER_UNIT),
    ("a directory that cannot be read is skipped", FILES,
     "for entry in std::fs::read_dir(&directory)? {", "for entry in std::fs::read_dir(&directory).into_iter().flatten() {",
     RUNNER_UNIT),
    ("a directory bearing a name is entered, not removed", FILES,
     "                if named {\n                    // `remove_dir_all`",
     "                if false {\n                    // `remove_dir_all`", RUNNER_UNIT),

    # ── M1: Vectispire's own endpoints ──
    ("the allow-list does not ask the reserved endpoints", ALLOWLIST,
     "        if self.reserved_reason(url).is_some() {\n            return false;\n        }\n", "", [DOMAIN, COMPOSITION]),
    ("the refusal does not name the endpoint", ALLOWLIST,
     "        if let Some(endpoint) = self.reserved_reason(url) {\n            return endpoint;\n        }\n", "",
     [DOMAIN, COMPOSITION]),
    ("the composition does not refuse them", HOSTS,
     "    Ok(GitHostAllowlist::parse(Some(configured))?\n"
     "        .refusing(Arc::new(move |host: &str, port: i32| guard.reserved_reason(host, port, LABEL))))",
     "    let _ = (guard, LABEL, Arc::new(()));\n    GitHostAllowlist::parse(Some(configured))", COMPOSITION),
    ("the guard answers nothing reserved", GUARD,
     "        self.refuse_reserved(&hostname, port, &addresses, label).err().map(|refused| refused.0)",
     "        let _ = (addresses, port, label);\n        None", COMPOSITION),
    ("git:// asks about no port", URL, '        "git" => Some(9418),\n', "", DOMAIN),
    ("a written port is ignored", URL,
     "    if let Some(port) = parsed.port.filter(|port| *port > 0) {\n        return Some(port);\n    }\n", "",
     [DOMAIN, COMPOSITION]),

    # ── L6: one-time secrets ──
    ("the agent's key is Debug-printed", ADMIN,
     'f.debug_struct("DeclaredAgent").field("id", &self.id).field("name", &self.name).finish_non_exhaustive()',
     'f.debug_struct("DeclaredAgent").field("id", &self.id).field("name", &self.name).field("s", &self.secret).finish()',
     SECRETS),
    ("the seed is Debug-printed", ADMIN,
     '.field("private_key", &self.private_key.as_ref().map(|_| "***"))', '.field("private_key", &self.private_key)',
     SECRETS),
]

# Equivalent or not mutated, with the reason:
# - `kind.is_dir() && !kind.is_symlink()` → `kind.is_dir()`: on Unix `DirEntry::file_type` never reports a link as a
#   directory, so no test can tell them apart; the clause stays for a platform where it would.
# - the lookup by name restored in place of the lookup by id: `find_by_name` is gone with its cached statements, so the
#   mutant does not compile offline. It was proved by hand (commit 5e732e8fb): `protocol_lifecycle` went red on
#   MySQL with the disabled namesake's key answered 200.
# - Java's trim in the protocol service and `normalize_host` (L5): no guard depends on it — the decoders trim as Java
#   does — so no test can tell `str::trim` from it there, short of the no-break-space cases the reference sets carry
#   for the administration.

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=900, env={"VECTISPIRE_TEST_ENGINES": "mysql"}))
