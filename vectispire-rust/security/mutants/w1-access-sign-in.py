#!/usr/bin/env python3
"""Mutation check of wave 1, access sign-in stage: what the stage changed outside cp-access — a request with no content
type and no body answered as a missing body (cp-http), and the replay's one-time codes and its TOTP step (cp-contract).
See README.md.

Killed by `cp-http`'s `extract` unit tests and `cp-contract`'s `placeholders` unit tests. The sign-in routes themselves
are held by the golden replay, which runs too long for a mutation run.
"""
import sys

import _runner

EXTRACT = "crates/cp-http/src/extract.rs"
PLACEHOLDERS = "crates/cp-contract/src/recorded/placeholders.rs"

HTTP = ["-p", "vectispire-cp-http", "--lib", "extract"]
CONTRACT = ["-p", "vectispire-cp-contract", "--lib", "placeholders"]

MUTANTS = [
    ("a missing body is a 415", EXTRACT,
     "if parts.headers.get(CONTENT_TYPE).is_none() && read(body).await?.is_empty() {",
     "if false {", HTTP),
    ("a typed empty body is a missing body", EXTRACT,
     "if parts.headers.get(CONTENT_TYPE).is_none() && read(body).await?.is_empty() {",
     "if read(body).await?.is_empty() {", HTTP),
    ("a step set from null is no change", PLACEHOLDERS,
     '&& text != "null" {', "{", CONTRACT),
    ("the code's dynamic truncation drops the sign bit's mask", PLACEHOLDERS,
     "let value = u32::from_be_bytes(window.try_into().ok()?) & 0x7fff_ffff;",
     "let value = u32::from_be_bytes(window.try_into().ok()?);", CONTRACT),
    ("the code's offset ignored", PLACEHOLDERS,
     "let offset = usize::from(hash.last()? & 0x0f);", "let offset = usize::from(0u8);", CONTRACT),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=900))
