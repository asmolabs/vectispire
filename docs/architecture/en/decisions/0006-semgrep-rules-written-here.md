# 0006 — The Semgrep rules are written here, not redistributed

**Date:** 2026-08-07 · **Status:** accepted

## Context

Upstream Semgrep rule licensing constraints prevent redistributing third-party rule sets.

## Decision

Vectispire ships bundled native rules, supports custom rule directories via `VECTISPIRE_SEMGREP_RULES_DIR`, and ensures fully reproducible offline scans.
