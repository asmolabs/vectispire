# 0013 — Flyway with dialect-specific native migrations

**Date:** 2026-08-22 · **Status:** accepted · **Supersedes:** [0011](0011-liquibase-rather-than-flyway.md)

## Context & Decision

Adopt Flyway with native SQL migrations per dialect (`src/main/resources/db/migration/{vendor}/`) across PostgreSQL, MySQL, MariaDB, and SQLite to ensure full DDL control and schema parity.
