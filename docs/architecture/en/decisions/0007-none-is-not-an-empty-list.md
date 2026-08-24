# 0007 — An analyzer that fails returns `None`, never `[]`

**Date:** 2026-08-07 · **Status:** accepted

## Context

An analyzer crashing or timing out produces no findings. Treating an unexecuted step as an empty list `[]` would incorrectly resolve existing issues in the backlog.

## Decision

`[]` means "analyzed, found nothing". `None` (`Optional.empty()`) means "did not run". Unexecuted scanner steps leave the backlog untouched.
