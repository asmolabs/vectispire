#!/usr/bin/env python3
"""Mutation check of wave 1, access SCIM stage: `/scim` taking the SCIM token alone, a SCIM refusal written as plain JSON,
and the user attributes read as Java's controller reads them — the display name falling back on the formatted name,
the first email and role. See README.md.

Killed by `cp-access`' `web::scim` unit tests. The routes' answers themselves are held by the golden replay, and the
directory's audit entries by `scim_on_both_engines`.
"""
import sys

import _runner

SCIM = "crates/cp-access/src/web/scim.rs"
UNIT = ["-p", "vectispire-cp-access", "--lib", "web::scim"]

MUTANTS = [
    ("any credential reaches scim", SCIM,
     "(!matches!(caller.0.credential, Credential::Scim))", "(false)", UNIT),
    ("a refusal written as scim+json", SCIM,
     '    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));\n', "", UNIT),
    ("no fallback on the formatted name", SCIM, ".or(formatted.filter", ".or(None::<String>.filter", UNIT),
    ("the last email and role", SCIM,
     "let Some(first) = items.and_then(|items| items.first())", "let Some(first) = items.and_then(|items| items.last())",
     UNIT),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=900))
