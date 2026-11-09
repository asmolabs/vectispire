# 0007 — None is not an empty list

**Date:** 2026-08-12 · **Status:** accepted · **Decider:** Laurent Boucher

## Context

A scan step produces a list of findings. When the step does not happen — the container times out,
the image cannot be pulled, the report is unreadable, the tool exits non-zero — the natural thing
for a caller to hold is an empty list, because that is what "no findings" looks like in memory.

It is also the most expensive mistake this system can make, and it makes it silently.

`IssueSyncService` reconciles a scan's findings against the open backlog: an issue of a type the
scan covered, which the scan did not report, is **resolved**. That is correct and necessary —
without it a fixed vulnerability would stay open forever. It is also why an empty list is not a
neutral value. `[]` from the secrets step is the assertion *"I looked, there are no secrets in this
repository"*, and it closes every open secret finding for that target: triage, VEX justification,
history and all.

So the two states have to be told apart at the type level, because nothing else will tell them
apart at all. A failure here raises no exception, logs no error, and produces a scan marked
`completed` with a smaller backlog than before — which reads as progress.

## Decision

**`[]` means "the step ran and found nothing".** It resolves that type's open issues.

**Absent means "the step did not run".** It leaves the backlog untouched.

Every scanner returns `Optional<List<…>>`, every field of
[`ScanArtifacts`](../../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/scanning/ScanArtifacts.java)
is an `Optional`, and `ScanRunner.ran(…)` converts an absent result into a recorded step failure
rather than letting the call site decide. One place decides what a failed step does.

## Consequences

**The rule is enforced by types, not by discipline.** `ran(…)` does not compile against a bare
`List`, and
[`ScannerContractTest`](../../../../vectispire-java/vectispire-common/src/test/java/com/asmolabs/vectispire/common/scanning/scanners/ScannerContractTest.java)
asserts by reflection that every container-running scanner returns `Optional` — identified by
holding a `ContainerRunner` rather than by name, so a scanner added later is in scope the moment it
exists.

**That enforcement exists because the rule was broken where it mattered most.** The secrets step
ran two scanners and merged them inside a `catch (Exception ignored)`, with both returning bare
`List`s. A failure of the second engine therefore produced the first's results alone — non-null,
hence "complete" — and any leaked credential only the second detected was resolved in silence. The
finding type was leaked credentials, where a false resolution is the most expensive answer the
product can give. It was found by an audit, not by a test, and nothing in the type system had
objected.

**An absent result is a failure, not a silence.** Earlier the call sites consumed an absent
artifact with `ifPresent`: the backlog was correctly protected, but `failures` stayed empty, the
scan was recorded `completed` with no error to show, and an operator reading an empty SAST list saw
a clean repository instead of a step that never ran. Raising it through `ran(…)` means the reason
travels to the scan record.

**Exit codes are not enough, and that is why this is a rule about values.** A Semgrep run where
most files timed out exits 0 with a short list. `errors[]` and `paths.scanned` are inspected, and
past a 25% error ratio the result is absent — a step can fail while reporting success, so the
decision cannot be delegated to the process.

**Steps that never apply stay absent too.** Secrets, IaC and SAST do not run against a container
image: they look in source code, and declaring them scanned would resolve that target's whole
history for those types.
