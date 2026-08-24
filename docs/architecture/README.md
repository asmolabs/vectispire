# Vectispire architecture

This folder is written for **someone picking up the code** — not for a reviewer, not for
a committee. It answers three questions, in this order: how it is built, why it is built
that way, and what breaks if you change it without knowing.

> These documents describe the system as it is: a Spring Boot control plane in
> `vectispire-java/` and an Angular interface in `vectispire-angular/`. The deliberate omissions
> (OSV and sidecar scan backends, remote agent without a client binary) are named in the
> [README](../../README.md).

| Document | The question it answers |
|---|---|
| [01 — Overview](01-overview.md) | What does Vectispire do, what is it made of, and what path does a scan take? |
| [02 — Data model](02-data-model.md) | What is stored, and why is a *finding* not an *issue*? |
| [03 — Security](03-security.md) | What are the trust boundaries, what guards them, and what is still open? |
| [04 — Runtime and deployment](04-runtime-and-deployment.md) | One instance, several, remote agents: what is allowed and what is refused? |
| [Decision register](decisions/) | One page per structural decision, with the alternative that was rejected. |

## What this folder replaces

Two files named `ADR-001` and `ADR-002` that had reached 957 and 825 lines. They were no
longer decisions but logbooks: sections `9bis`, `9ter`, `9quater`, … up to `9undecies`,
each added after a wave of work, none superseding the previous one. Nobody could have
found the system's current state in them without reading all 1,800 lines and deciding
for themselves what was still true and what had been overtaken.

The distinction this folder keeps, and that the two files had lost:

- **Description is in the present tense.** Documents 01 to 04 describe the system as it
  is. They are rewritten when it changes, not appended to.
- **Decisions are dated and immutable.** A decision that no longer holds is *superseded*
  by another that cites it, never edited. That is the whole point of an ADR, and exactly
  what the old files failed to do.

The content of both files was carried over before they were deleted: the decisions into
the register, the hard-won lessons — the six portability defects, the measured
concurrency traps, the dead ends tried — into these documents and into the code
comments. `git log docs/architecture/` finds the originals.

## How to keep it honest

This folder is worth nothing unless it is true, and a false architecture document is
worse than none: it gets believed. Three rules are followed here.

**Whatever a test enforces says so and cites it.** A folder that claims "the agent never
touches the database" without saying what enforces it is stating a wish. Here it is not even a
test: `vectispire-agent` does not depend on `vectispire-core`, so the violation fails to compile.

**Known limits are written in the same place as the guarantees.** A "still open" section
at the end of each document, not in a separate file nobody opens. A reader who discovers
a limit elsewhere stops believing the rest.

**Implementation detail stays in the code.** This folder explains *why* and *how the
pieces fit*; the "how exactly" lives in the doc comments, which sit next to what they
describe and therefore age more slowly. When this folder and a module contradict each
other, **the module is right** and this folder has a bug.

## Elsewhere in the documentation

- [`docs/fr/GETTING_STARTED.fr.md`](../fr/GETTING_STARTED.fr.md) / [`docs/en/GETTING_STARTED.md`](../en/GETTING_STARTED.md) — install and run.
- [`docs/fr/TECHNICAL_DOCUMENTATION.fr.md`](../fr/TECHNICAL_DOCUMENTATION.fr.md) / [`docs/en/TECHNICAL_DOCUMENTATION.md`](../en/TECHNICAL_DOCUMENTATION.md) — reference for the
  modules, the settings and the environment variables.
- [`docs/fr/ROTATION_AND_PURGE.fr.md`](../fr/ROTATION_AND_PURGE.fr.md) / [`docs/en/ROTATION_AND_PURGE.md`](../en/ROTATION_AND_PURGE.md) — encryption key rotation and
  purging of raw data.
