# 0002 — The database carries the queue, not a broker

**Date:** 2026-08-06 · **Status:** accepted

## Context

The scan queue was a module-level `ThreadPoolExecutor`. A second instance could not take the work, and a restart lost in-flight tasks.

## Decision

Scans are database rows in `t_scan`. Claiming is transactional (`SELECT … FOR UPDATE SKIP LOCKED` / dialect conditional updates). Triggering a scan inserts a `pending` row and returns immediately.
