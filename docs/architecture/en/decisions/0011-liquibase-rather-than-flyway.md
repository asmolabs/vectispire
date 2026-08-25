# 0011 — Liquibase stays, and structural DDL is written by hand

**Date:** 2026-08-22 · **Status:** **superseded** by [0013](0013-flyway-multi-dialect-migrations.md)

## Context & Decision

The port arrived with Liquibase and a database-agnostic changelog: the schema described once and
translated per engine by the tool. Structural DDL the changelog could not express was to be
written by hand alongside it.

## Why it was wrong

**The hand-written exceptions were not the edge case; they were the load-bearing part.** Two of
them decided it, both recorded in [0013](0013-flyway-multi-dialect-migrations.md):

* a bare `DATETIME` on MySQL truncates to the second, and the audit chain hashes a timestamp
  canonicalised to the millisecond — so the abstraction getting that type wrong makes a security
  control fail *its own* integrity verification, reporting tampering that never happened;
* foreign keys and cascade behaviour differ enough between engines that the generated DDL had to
  be read per engine anyway.

Once the generated statements must be reviewed per engine, the abstraction stands between the
author and a statement they are already reading. 0013 removed it.
