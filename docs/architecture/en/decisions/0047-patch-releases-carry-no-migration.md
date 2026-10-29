# 0047 — A patch release carries no migration

**Date:** 2026-10-29 · **Status:** accepted · **Builds on:** [0043](0043-what-1-0-promises.md) §5, [0027](0027-common-migrations-with-type-placeholders.md) · **Decider:** Laurent Boucher

## Context

[0043](0043-what-1-0-promises.md) §5 promises security fixes on the previous minor for three months after
its successor, and says a patch release never needs a migration a later minor would not also carry; the
numbering rule was left to be written.

Migrations are numbered by one integer (`V91__…`), applied by Flyway with `outOfOrder` off, and
`MigrationLayoutTest` accepts only `V<integer>__<description>.sql`. Until now every patch release was cut
from `develop` itself: 0.11.1 added `V91` and 0.11.2 added none, while `develop` had nothing newer. Once a
minor's successor is out, that stops being true, and a migration on the old line meets one of two failures:

- **It takes the next free number** on the old line, which `develop` has already used for something else:
  two different migrations under one version, and Flyway refuses the second on its checksum.
- **It takes a number in a gap** below what `develop` already ships. An installation already on the newer
  minor then meets a migration older than its schema, and Flyway refuses it unless `outOfOrder` is on. With
  it on, nothing says a forgotten merge apart from a deliberate patch.

## Decision

- **A patch release carries no migration.** A fix that needs a schema change goes into the next minor. A
  security fix on the previous line is written to work on that line's schema; if it cannot be, it ships only
  in the next minor, and the security notice says so.
- **Checked by the release workflow.** `release.yml` refuses a `vX.Y.Z` tag with `Z > 0` whose migration
  directories differ from `vX.Y.0`'s. A rule kept by memory is the one forgotten on the day of an urgent fix.
- **If an exception is ever needed**, it is a decision of its own, made then, with the line's state in
  front of it. The reserved-gap scheme below is where it would start, and it is not adopted now.

## Consequences

- A security fix that cannot avoid a schema change reaches the previous line late or not at all; the
  supported-versions table in `SECURITY.md` says that patch releases do not change the schema.
- `MigrationLayoutTest` and Flyway's `outOfOrder: false` stay as they are.
- The release workflow gains one step, run before anything is built.

## Rejected

- **Reserved gaps** — each minor's first migration starts at the next multiple of ten, leaving the gap for
  that minor's patches. It solves the number, and not the installation already on the newer minor, which
  needs `outOfOrder` to apply it, with `develop` carrying the same file at the same version. Two lines,
  out-of-order migrations, and a weaker check for one case nobody has met.
- **Decimal versions** (`V91.1`). Flyway orders them, but the same `outOfOrder` problem applies, and
  `MigrationLayoutTest` would have to accept a second shape of name.
- **Idempotent duplicates** — the same change under a new number on each line, written to do nothing the
  second time. Each line then holds a migration the other does not, and Flyway's validation fails on an
  upgrade from the old line unless missing migrations are ignored, which hides real ones too.
