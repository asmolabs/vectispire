# 0003 — Agents speak HTTP long-polling, never to the database

**Date:** 2026-08-06 · **Status:** accepted

## Context

Executing scans on remote agent nodes required a safe transport without exposing database credentials or decryption keys.

## Decision

Agents use `GET /api/v1/agents/jobs?wait=30` via HTTP long-polling. The agent never connects to the database or holds `ENCRYPTION_KEY`.
