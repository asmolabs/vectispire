# Scans

A scan is one execution of the pipeline against one target, by one agent.

## The pipeline

The pipeline is split along one line: **the runner executes the scanners and never touches
the database; the ingestor reads its results and never runs a container.** That is what
lets identical code run inside the control plane or on a remote agent that holds no
database credentials.

1. **Clone or pull** the target into a temporary working directory.
2. **Catalogue** it with Syft, producing the SBOM.
3. **Match** known vulnerabilities with Grype.
4. **Secrets** with gitleaks, dual-engine with automatic deduplication.
5. **IaC** with checkov, for Terraform and Kubernetes.
6. **Source code** with Semgrep, if enabled — see [Semgrep rule sets](../administration/rule-sets.md).
7. **Normalise** everything into `Finding` rows, enrich with EPSS and KEV, evaluate the
   license blocklist, check end-of-life, and reconcile against existing issues.

Steps 2 to 6 run in ephemeral containers with **the network disabled**, a read-only mount,
`cap_drop: ALL` and `no-new-privileges`. Every image is pinned by digest.

The only outbound calls a scan makes are the EPSS and KEV lookups, carrying CVE
identifiers and nothing else, and the end-of-life catalogue, carrying product names and
versions. The code being scanned does not leave the machine.

## Reading a scan

The scan detail shows what was found and, more usefully, what **changed**: issues that are
new, issues that are now resolved. On a repository scanned nightly the standing total
barely moves, and the delta is the entire news.

The raw outputs are kept alongside the normalised findings — the SBOM as the cataloguer
produced it, and the raw matcher output — for audit purposes. They are what you hand to
somebody who wants to re-derive your conclusions rather than take them.

## A failed scan is not a clean scan

A scan that failed produces no findings, and a target with no findings passes every
policy. The [Security overview](dashboard.md) names that state explicitly for this reason.
Check it before reading a green dashboard as good news.

Common causes are in the [FAQ](../reference/faq.md).

## Where it ran

Every scan records its agent. With a single-machine install that is always the built-in
agent — the web process itself, created automatically at startup, which is why an install
works with no agent configuration at all.

A result produced on a remote agent is indistinguishable from a local one: same rows, same
enrichment, same policy, same reconciliation. See [Agents](../administration/agents.md).
