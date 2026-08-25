# 0006 — The analyser's rules come from here, never from the target

**Date:** 2026-08-11 · **Status:** accepted

## Context

Two of the scanners read their configuration from the tree they are analysing when nothing tells
them otherwise, and that tree is written by whoever is being audited:

* **gitleaks** falls back to `.gitleaks.toml` in the scanned repository, and uses it *instead of*
  its built-in rules. An empty config with a universal allowlist switches detection off entirely:
  exit 0, empty report, empty list.
* **Semgrep** honours the analysed tree's `.gitignore`. A committed `*` excludes everything, and
  the run reports success over nothing.

Neither produces an error. Both produce the shape [0007](0007-none-is-not-an-empty-list.md) calls
the most expensive one — an empty list, meaning "analysed, found nothing", which **resolves** that
type's open issues. A repository that wanted its findings gone could close them itself, and the
audit trail would record a clean scan.

The rule sets themselves are a second, unrelated constraint: upstream Semgrep registry rules cannot
be redistributed under the licence this project ships with, and a scan that pulls them at runtime
is neither offline-capable nor reproducible.

## Decision

**The configuration is always passed explicitly**, so the target's own is never consulted:
`--config` for both gitleaks and Semgrep, `--no-git-ignore` for Semgrep.

**Vectispire ships its own rules**, copied into the scan's workspace by
[`RulePlacement`](../../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/scanning/RulePlacement.java),
and merges an operator-supplied directory from `VECTISPIRE_SEMGREP_RULES_DIR`.

## Consequences

**Rules are copied into the workspace rather than mounted from the image.** Counter-intuitive, and
mandatory: volume paths are resolved by the Docker *daemon*, not by the process calling it, so a
directory inside Vectispire's own image is invisible to the sibling scanner container. The
workspace is the only path both sides see — locally and on a remote agent alike.

**The rules are placed before the scanners run, not inside the SAST step.** The secrets scanner
needs them too. Copying them only for the source analyser left gitleaks reading the target's own
configuration, which is the exact defect this decision exists to prevent — and it was present after
the first version of it.

**This is the mitigation the threat model names.** The STRIDE Tampering entry for the scan workspace
points here: server-side enforced configuration is what stops a scanned repository from deciding
what is looked for in it.

**What an operator can still do.** `VECTISPIRE_SEMGREP_RULES_DIR` merges their rules with the
bundled set — an addition made by the deployment, not by the audited tree. The distinction is the
whole decision: rules come from someone who is not the subject of the scan.

**A rule set that cannot be obtained fails SAST alone**, and leaves its result absent rather than
letting the analyser run with the bundled rules and report a clean, shorter list. Same principle as
above, applied one level down.
