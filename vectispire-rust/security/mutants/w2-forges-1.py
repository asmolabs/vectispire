#!/usr/bin/env python3
"""Mutation check of wave 2, forges: the token's scopes judged against the allow-lists and which refusals are signalled,
the address held to https, a path segment refusing dots, the pager refusing an encoded dot, the owner and token forms,
the import's forge ids and mapping rules, GitLab's branch wildcard, and the discovery queue's conditional updates — a
take matches once, a lapsed run goes back or fails on its attempts, gone is marked only on what the run did not list.
See README.md.

Killed by `vectispire-domain`'s and `cp-outbound`'s unit tests, `cp-forges`' unit tests, and its persistence suite
(`persistence::tests::on_mysql`, MySQL, Docker required).
"""
import sys

import _runner

CREDENTIAL = "crates/domain/src/forges/credential.rs"
ADDRESS = "crates/domain/src/forges/address.rs"
MAPPING = "crates/domain/src/forges/mapping.rs"
SELECTION = "crates/domain/src/forges/selection.rs"
PATH = "crates/cp-forges/src/internal/path.rs"
PAGER = "crates/cp-outbound/src/pager.rs"
CONNECTIONS = "crates/cp-forges/src/connections.rs"
PLANNER = "crates/cp-forges/src/internal/planner.rs"
STORE = "crates/cp-forges/src/persistence/mod.rs"

DOMAIN = ["-p", "vectispire-domain", "--lib", "forges"]
PAGER_TESTS = ["-p", "vectispire-cp-outbound", "--lib", "pager"]
FORGES = ["-p", "vectispire-cp-forges", "--lib", "internal", "connections"]
STORE_TESTS = ["-p", "vectispire-cp-forges", "--lib", "persistence::tests::on_mysql"]

MUTANTS = [
    ("a GitLab write scope accepted", CREDENTIAL,
     "held.iter().map(String::as_str).filter(|scope| !GITLAB_ALLOWED.contains(scope)).collect();",
     "held.iter().map(String::as_str).filter(|_| false).collect();", DOMAIN),
    ("every refusal signalled", CREDENTIAL,
     "matches!(self, RefusalReason::DestinationBlocked | RefusalReason::ScopeRefused)", "true", DOMAIN),
    ("a classic GitHub token accepted on a cloud", CREDENTIAL,
     "        if edition.cloud() {\n            return Err(ForgeConnectionRefusal::new(",
     "        if false {\n            return Err(ForgeConnectionRefusal::new(", DOMAIN),
    ("a token over http accepted", ADDRESS, 'if scheme != "https" {', "if false {", DOMAIN),
    ("an API path typed kept", ADDRESS,
     '|| lower_path.contains("/api/v4/")\n        {', '|| false\n        {', DOMAIN),
    ("a no-project rule naming a project accepted", MAPPING,
     "if no_project && (solution.is_some() || project.is_some()) {", "if false {", DOMAIN),
    ("a segment of dots carried", PATH, "if value.is_empty() || value.chars().all(|c| c == '.') {",
     "if value.is_empty() {", ["-p", "vectispire-cp-forges", "--lib", "internal::path"]),
    ("an encoded dot followed", PAGER, 'if path.to_ascii_lowercase().contains("%2e")\n',
     "if false\n", PAGER_TESTS),
    ("a GitHub owner starting with a dash", CONNECTIONS, "            first.is_ascii_alphanumeric()\n",
     "            true\n", FORGES),
    ("a token with a space kept", CONNECTIONS, "if token.chars().any(java::is_whitespace) {", "if false {", FORGES),
    ("an empty forge id skipped", PLANNER,
     'return Err(ForgeError::InvalidInput("A forge id is empty.".into()));', "continue;", FORGES),
    ("a glob's star read literally", SELECTION, "        } else if at == Some(star) {", "        } else if false {",
     DOMAIN),
    ("a run taken twice", STORE,
     "            .filter(discovery::Column::Id.eq(id))\n            .filter(discovery::Column::State.eq(pending)),\n    );",
     "            .filter(discovery::Column::Id.eq(id)),\n    );", STORE_TESTS),
    ("a lapsed run requeued past its attempts", STORE,
     ".filter(discovery::Column::Attempts.lt(max_attempts)),", ",", STORE_TESTS),
    ("what the run listed marked gone", STORE,
     ".filter(repository::Column::LastSeenBy.ne(discovery_id))", "", STORE_TESTS),
]

# Not listed:
# - the probe's audit of a signalled refusal, the import's provenance link and its purge, the selection's operations,
#   the readings' claim and the suspended connection's port: held by the golden replay (ForgeConnectionsRoutesTest,
#   ForgeImportsRoutesTest, ChangeReviewRoutesTest), which runs too long for a mutation run.
# - the URI's user info refused in ForgeAddress: `carries_credential` refuses every user part over https first, so a
#   mutant there is equivalent.

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=900, env={"VECTISPIRE_TEST_ENGINES": "mysql"}))
