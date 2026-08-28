# Repositories

A repository is a scan target: a clone URL, a branch, optionally a sub-path, and a
recurrence.

## Registering one

**Repositories → add.**

| Field | Notes |
|---|---|
| **Repository URL** | HTTPS for a public repository, SSH where a deploy key is needed. |
| **Display name** | What every other screen calls it. |
| **Branch** | The branch scanned on every run. |
| **Sub-path** | For a monorepo. Register a monorepo **once per project**, not once for the whole tree — otherwise one SBOM conflates several applications' dependencies and no verdict means anything. |
| **Business criticality tier** | Tier 1 · Mission Critical, Tier 2 · Operational, Tier 3 · Internal. |
| **Required agent** | Pins the scan to one agent. Leave empty unless the repository is only routable from a particular network segment. |

## Credentials

Private repositories authenticate with a deploy key registered under
[SSH keys](../administration/ssh-keys.md). Give it **read-only** access at your provider —
Vectispire only ever clones.

The private half is encrypted at rest with your `ENCRYPTION_KEY`. Storing a key is refused
outright until that variable is set.

## Recurrence

Set either a **scan interval** or a **cron expression**. The expression wins when both are
present.

Prefer cron. An interval drifts a few minutes on every run, so a scan configured for 03:00
migrates into the working day over a few weeks — and a scan that competes with the working
day is the scan somebody eventually turns off.

Recurrence is the point of the product rather than a convenience: new vulnerabilities are
published against code that has not changed, so a repository scanned once is a repository
whose posture is known as of a date in the past.

## Business criticality tiers

Three tiers, and they exist so that ranking can account for what a target *is* rather than
only for what was found in it:

- **Tier 1 · Mission Critical**
- **Tier 2 · Operational**
- **Tier 3 · Internal**

The same critical CVE is a different problem in a payment path than in an internal
scratch tool. Without a tier, the backlog says they are the same.

## The README badge

Each repository can expose a dynamic badge for its own README, showing the security
posture grade. It puts the number in front of the people who commit, which is where it
changes behaviour.

## Deleting a repository

Removing a repository removes its scans and its issue history with it. Where you need the
record kept, export the
[detection and triage history](history.md) first — that document is written to be read
after the fact by somebody who was not there.
