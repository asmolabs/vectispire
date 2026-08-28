# Vectispire

Vectispire tracks the security posture of the software you ship. It scans Git repositories
and container images, generates an SBOM, matches known vulnerabilities against it, finds
hardcoded secrets, problematic licenses and infrastructure-as-code misconfigurations, and
centralises everything in one dashboard.

Every scanner runs in an ephemeral local container with **the network disabled** and a
read-only mount. Nothing about the code you scan leaves your machine.

## Where to start

<div class="grid cards" markdown>

- **Install it** — prerequisites, database, first account, first launch.
  [Installation](getting-started/installation.md)

- **Scan something** — register a repository, run a scan, watch it finish.
  [Your first scan](getting-started/first-scan.md)

- **Understand what came back** — findings, issues, severity, and what actually needs doing.
  [Reading the results](getting-started/reading-results.md)

- **Fail a build on it** — the policy gate, from a shell script or a CI template.
  [CI policy gate](integrations/ci-gate.md)

</div>

## What it looks at

| Area | Scanner | Notes |
|---|---|---|
| Dependencies (SCA) | Syft → Grype | SBOM generation, then known-vulnerability matching |
| Secrets | gitleaks | API keys, tokens and credentials committed to the repository |
| Infrastructure as code | checkov | Terraform and Kubernetes misconfigurations |
| Source code | Semgrep | Off by default; see [Semgrep rule sets](administration/rule-sets.md) |
| End of life | endoflife.date | Runtimes and distributions past their security support |
| Licenses | from the SBOM | Evaluated against a configurable blocklist |

Every scanner image is pinned by digest, not by tag.

## Two ideas worth reading first

Two distinctions run through the whole product, and most confusion about it comes from
collapsing them.

**A finding is not an issue.** A *finding* is one observation, valid for one scan. An
*issue* is the same problem tracked across scans — first seen, times seen, whether a fix
exists, what was decided about it. The issue's fingerprint deliberately ignores the package
version, so a dependency that stays vulnerable through three patch releases keeps one
history and one decision instead of three.

**State is not triage.** `state` (open / resolved) is written only by the pipeline, from
what the scanners observe. `triage_status` (the VEX vocabulary: affected, not affected,
fixed, under review) is written only by a person. They are kept strictly apart, because a
suppressed finding and a genuinely fixed one must not look alike.

[More on this →](guide/issues.md)

## Getting help

- Something broken during install: [FAQ](reference/faq.md).
- A security problem in Vectispire itself: see
  [SECURITY.md](https://github.com/asmolabs/vectispire/blob/main/SECURITY.md) for the
  disclosure policy — please do not open a public issue.
