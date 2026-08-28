# Your first scan

## 1. Sign in

Open the control plane — `http://localhost:3180` for a default install — and sign in with
the bootstrap account created at first start. Change its password straight away.

## 2. Register a repository

Go to **Repositories → add**, and fill in:

| Field | Notes |
|---|---|
| **Repository URL** | The clone URL. HTTPS for a public repository; SSH if it needs a deploy key. |
| **Display name** | What the dashboard calls it. |
| **Branch** | The branch to scan. |
| **Sub-path** | For a monorepo. A monorepo is registered **once per project**, not once. |
| **Business criticality tier** | Tier 1 · Mission Critical, Tier 2 · Operational, or Tier 3 · Internal. This is what lets the dashboard rank a critical CVE in a mission-critical service above the same CVE in an internal tool. |
| **Required agent** | Leave empty unless the repository is only reachable from a particular machine. See [Agents](../administration/agents.md). |

### Private repositories

A private repository needs a deploy key. Add it under [SSH keys](../administration/ssh-keys.md)
first, then select it when registering the repository. The private half is encrypted with
your `ENCRYPTION_KEY`, which is why the application refuses to store one before that key
is set.

Give the key **read-only** access at your Git provider. Vectispire never pushes.

## 3. Run the scan

Use **Scan now** on the repository. The first run is slow: the Docker backend pulls
`anchore/syft`, `anchore/grype`, `zricethezav/gitleaks` and `bridgecrew/checkov` on demand
the first time each is used. Later scans reuse the cached images.

What happens, in order:

1. The repository is cloned to a temporary working directory.
2. Syft catalogues it and produces an SBOM.
3. Grype matches known vulnerabilities against that SBOM.
4. gitleaks looks for committed secrets; checkov looks at Terraform and Kubernetes.
5. Results are normalised into `Finding` rows, enriched with EPSS scores and CISA KEV
   status, evaluated against the license blocklist, and reconciled against existing issues.

Steps 2–4 run with **the network disabled**. The only outbound calls the pipeline makes are
the EPSS and KEV lookups, which carry CVE identifiers and nothing else, and the
end-of-life catalogue, which carries product names and versions.

## 4. Schedule it

A one-off scan tells you about today. New vulnerabilities appear in code that has not
changed, so set a recurrence on the repository: either a **scan interval** or a **cron
expression**.

Prefer the cron expression. An interval drifts a few minutes every run, so a scan
configured for the quiet hours eventually runs in the middle of the day. Where both are
set, the expression wins.

## 5. Add a container image

Container images are registered on **Containers** and work the same way — the image is
catalogued and matched exactly as a repository is, and the distribution the image is built
on is checked against the end-of-life catalogue. That last check catches a class of risk
with no CVE attached: nothing will be fixed for the *next* vulnerability, whatever it turns
out to be.

## Next

[What the results mean →](reading-results.md)
