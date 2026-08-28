# FAQ and troubleshooting

## Installation

**Permission denied on the Docker socket.** The user running Vectispire needs access to
`/var/run/docker.sock`. On Linux, add it to the `docker` group. Every scan fails at the
first container without it.

**The first scan is very slow.** Expected. The images — `anchore/syft`, `anchore/grype`,
`zricethezav/gitleaks`, `bridgecrew/checkov`, `semgrep/semgrep` — are pulled on demand the
first time each is used. Later scans reuse the cache.

**Can I use SQLite?** No. PostgreSQL and MySQL 8 are the supported engines. SQLite exists
in the build as a test fixture only.

**The application will not start: the encryption key path does not resolve.** Deliberate.
Starting with no key would mean refusing every secret write hours later, somewhere
unrelated to the actual mistake.

## Signing in

**"Incorrect credentials or inactive account".** Either the credentials are wrong, or the
account's `is_active` flag is `false`. Check under **Users** with an existing
administrator.

**I have lost the bootstrap account.** The bootstrap variables are only honoured when the
user table is empty. Another SUPERUSER can reset the password; otherwise the reset is a
database operation.

**Single sign-on works but the user has no access.** Expected: no account is created on
sign-on. An administrator creates it first, and the role stays Vectispire's to decide. See
[Single sign-on](../administration/sso.md).

## Scanning

**A scan failed and the dashboard still looks green.** An empty backlog passes every
policy. The Security overview names both "never scanned" and "last scan failed" for exactly
this reason — see
[Reading the results](../getting-started/reading-results.md#two-states-with-an-empty-backlog).

**Nothing is picked up and the queue grows.** Either the built-in agent is disabled with no
remote agent connected, or the targets are pinned to an agent that has never announced
itself. Check [Agents](../administration/agents.md).

**A private repository will not clone.** The deploy key must be registered under
[SSH keys](../administration/ssh-keys.md), selected on the repository, and granted
read-only access at your provider.

**An SSH key shows as unreadable.** No configured key decrypts it — most likely it predates
any `ENCRYPTION_KEY`. That old default has been removed and its private half is public:
replace the key pair at your provider.

**Semgrep finds almost nothing.** Vectispire bundles a single rule, because the public rule
sets are not redistributable. Install your own — see
[Semgrep rule sets](../administration/rule-sets.md).

## Results

**Why did the same CVE not create a new issue after a version bump?** By design. The
fingerprint ignores the package version, so a dependency vulnerable across three patch
releases keeps one history and one decision.

**I suppressed an issue and it is still open.** Also by design. `state` is written only by
the pipeline; triage is written only by a person. Conflating them would make "resolved"
meaningless.

**A suppressed issue came back.** Its review date arrived and it returned to *under
review*, with the justification and comment intact. See
[Issues and triage](../guide/issues.md#review-dates).

**MTTR is blank rather than zero.** Nothing was resolved in that period. Zero would read as
"fixed the day it appeared".

## CI

**My `policy` in the request was ignored.** A request can only **tighten** the stored
policy, never loosen it. Change the stored policy under
[Gate policies](../administration/gate-policies.md).

**The verdict does not match what I see in the interface.** Read which policy the verdict
names — a per-target override may apply, or the built-in default where nothing is stored.

**Quality findings never fail my build.** Correct, and not configurable. See
[Code quality](../guide/quality.md).

## Notifications

**Teams receives nothing.** Teams is reached through a Power Automate **workflow**; the
Office 365 connector it replaced was retired. Recreate the destination as a workflow.

**A notification arrived twice.** Each destination has its own outbox row precisely so that
one failing does not duplicate another. A genuine duplicate to a single destination is
worth reporting.

**Nothing fires on a quiet week.** By design — notifications fire when something appears.
Enable the [weekly posture report](../integrations/notifications.md#the-weekly-posture-report),
which also names what was never scanned.

## AI review

**The model dropdown shows only two suggestions.** Ollama is unreachable at the configured
URL. Check it is running and refresh the list.

**Review is slow.** Expected with Ollama in Docker on Apple Silicon — no GPU or Metal
passthrough, so inference is CPU-only. Install natively, or use the lighter model.

## Reporting a security problem

Do not open a public issue. See
[SECURITY.md](https://github.com/asmolabs/vectispire/blob/main/SECURITY.md).
