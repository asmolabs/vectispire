# 0005 — Quality and AI review enter no verdict

**Date:** 2026-08-07 · **Status:** accepted

## Context

Code quality findings (Semgrep non-security rules) and AI reviews generate large backlogs that should inform developers without breaking CI builds.

## Decision

Quality findings and AI reviews are tracked in the backlog but **never block the Policy Gate**.
