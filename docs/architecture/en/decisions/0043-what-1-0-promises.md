# 0043 — What 1.0 promises: an additive API, agents one version behind, one engine, one instance, a supported line

**Date:** 2026-10-12 · **Amended:** 2026-10-29 (§3: MySQL only; §5: one maintainer) · **Status:** accepted (2026-10-29) · **Builds on:** [0003](0003-long-polling-for-agents.md), [0034](0034-mysql-replaces-the-sqlite-fixture.md), [0035](0035-report-plugins.md), [0038](0038-deploying-on-kubernetes.md) · **Decider:** Laurent Boucher

## Context

Vectispire is pre-1.0 (`README.md`) and says so: "There is no long-term support line yet"
(`SECURITY.md`). Nothing written says what a 1.0 would guarantee, so nothing says what has to be true
before one is cut. Every minor so far has changed what an integration sees — 40 such bullets in 0.10, 49
in 0.11 — which is right for a project finding its shape and wrong for one that asks pipelines,
auditors and agents on other machines to depend on it.

Five facts make the question concrete:

- **The API is frozen by a test, not by a promise.** `ClientContractSpecTest` fails when `openapi.json`
  drifts; regenerating the file makes it pass again. It detects a change, it does not refuse a breaking
  one. No operation has ever been marked deprecated.
- **The agent protocol broke without saying so.** `AgentContract.VERSION` is `"1"`, compared by strict
  equality, and 0.11.0 hands no work to an agent older than 0.11.0 (the sealed `v2` envelope) — with the
  version still `"1"`. The refusal the strict comparison was meant to make loud did not happen.
- **The engines the documentation names are not the ones tested.** The installation guide says
  MySQL 8; the integration campaign runs `mysql:9.4` and `postgres:17.6`; the restore drill runs
  `mysql:8` and has no PostgreSQL case.
- **Two control planes have never run together.** [0038](0038-deploying-on-kubernetes.md) records that
  no test runs two replicas; the maintenance tasks assume one.
- **One person can cut a release and answer a security report** (still true at 1.0; §5 says how it is handled). The code of conduct promises that a
  maintainer who is the subject of a report stays out of its handling, which one maintainer cannot keep.

## Decision

1.0 is cut when the five promises below are written, executed by a check where they can be, and have
held through one minor release with no unplanned break.

### 1. The REST API is additive within `/api/v1`

- Within `/api/v1`, a release may **add** routes, optional request fields, response fields and enum
  values. It does not remove or rename a route or a field, narrow what a request accepts, or change
  what a field means.
- A removal is **announced, then made two minor releases later**: the operation or field is marked
  `deprecated` in `openapi.json`, the release notes name it and its replacement, and it keeps working
  meanwhile. A change that cannot be made that way is `/api/v2`.
- **The interface's own calls are covered by the same rule.** They use the same API; a second, unstable
  surface beside the stable one would be a second contract to keep apart, and the first integration to
  copy a call from the browser would depend on it anyway.
- **Checked by CI**: a compatibility diff of `openapi.json` against the last release tag fails the build
  on a breaking change that is not a removal announced two minors earlier.
- Clients must ignore response fields they do not know. Enum values are open: a client meeting a value it
  does not know shows it as sent (the interface already does, [0019](0019-screen-text-is-translated-on-the-client.md)).

### 2. An agent one minor version behind the control plane is served

- The control plane serves an agent of its own minor and of the **previous** one (N-1). Upgrading the
  control plane first, then the agents, is supported; the reverse is not.
- `AgentContract` carries a **range**, not a single value, and a change the previous minor's agent would
  not understand — a new envelope, a new mandatory field — is made in two steps: the control plane
  accepts both forms for one minor, the next drops the old one.
- This accepts the cost `AgentContract`'s javadoc names: for every field added, someone decides whether
  an agent that ignores it is still correct. A **compatibility test** decides it — the previous release's
  agent, from its published image, against the current control plane, claiming and finishing a scan —
  rather than the reviewer's memory.
- Strict lockstep was the alternative. It is simpler and wrong for the deployments it would meet: on
  Kubernetes the control plane and the agents roll at different moments, and a strict refusal during that
  window stops every scan.

### 3. One engine, MySQL, at named versions

- **MySQL 8.4 LTS and 9.x.** The integration campaign runs the oldest and the newest supported version;
  the installation guide names exactly these.
- The restore drill and the upgrade job (§6) run on MySQL.
- An engine version leaves the list in a minor release, announced in the release notes of the one before.
- **PostgreSQL is not part of 1.0** (amended 2026-10-29; this section first promised it beside MySQL). Its
  code stays — the per-engine migrations under `db/migration/postgresql/`, the driver, the dialect's
  placeholders, `Engine.POSTGRES` — but no CI job runs it, and nothing promises it works. A migration
  whose structure diverges is still written twice (`MigrationLayoutTest` holds that without a server), so
  the code does not rot on the schema; it may on a query, and nothing would say so.
- **Why one engine.** Each engine doubles the integration campaign, the upgrade and the restore drills,
  and the cases a reviewer has to reason about, for an installation base that runs MySQL — the engine the
  composition ships and the one production runs. Four servers to keep green (two versions of each) was
  the price of the first wording; two is the price of this one.
- **Bringing PostgreSQL back** is a minor release of its own: its campaign and drills run green again on
  named versions, and the installation guide lists it. The code kept is what makes that a matter of
  checks rather than of writing.

### 4. One control-plane instance is what is promised

- 1.0 supports **one** control-plane replica. The chart's default stays one; the documentation says that
  a second replica is not supported, and why (maintenance tasks, the audit chain's lock, the outbox).
- High availability is a 1.x goal with its own decision, made when two replicas run in a test.
- Promising HA now would promise something no check executes ("a guarantee that is not executed is not a
  guarantee", `AGENTS.md`).

### 5. A supported line, and the people behind it

- **The latest minor** receives fixes. **The previous minor** receives security fixes for **three months**
  after its successor is released. `SECURITY.md` names the supported lines and the date each ends.
- A patch release never needs a migration a later minor would not also carry: a fix that needs one goes
  into the next minor, or its migration takes a version reserved for the line (the numbering rule is
  written before the first 0.11.x patch). [0047](0047-patch-releases-carry-no-migration.md) settles it: a patch release
  carries no migration.
- **One maintainer, said plainly** (amended 2026-10-29; this line first required a second maintainer before
  1.0). The project looks for its second maintainer through the outreach 1.0 itself opens, so requiring one
  before 1.0 was a condition that could only wait on itself. What a second person was meant to cover is
  covered differently, and written down:
  - **A report about the maintainer** goes outside the project: the code of conduct names GitHub's own
    reporting as the recourse, and stops promising that "the person concerned stays out", which one
    maintainer cannot keep.
  - **Security reports** go through the private channel `SECURITY.md` names, which says the project has one
    maintainer and keeps response times one person can meet.
  - **Cutting a release** is written in `CONTRIBUTING.md`, step by step, so the procedure does not live in
    one head; the tag, build, signature and verification are already a workflow.
  - **A second maintainer remains a goal of 1.x**, and the condition for applying to OWASP's Incubator.
- **The repository's final home is settled before 1.0.** The release signatures name the repository,
  its owner and the workflow file; moving it afterwards invalidates every signature a consumer has
  learned to verify.

### 6. What has to be true before the tag

Besides the five promises, the contracts 1.0 freezes are put right first, because freezing them as they
are would freeze their defects:

- the gate's refusal reasons carry a **machine-readable code** beside the sentence (pipelines parse
  English text today);
- the attestation predicate moves to **v2** with one unit for its counts (`findings.total` counts issues,
  the severities count occurrences);
- the compliance codes are settled (the CRA codes' 2022 numbering, OWASP Top 10:2025 labels) —
  [0046](0046-compliance-codes-for-1-0.md): the CRA's renamed to the adopted text, OWASP kept on 2021 for 1.0;
- the scan plugin manifest carries a **schema version**, as the report plugins' export already does;
- the deprecated `reachability` fields are removed — before the promise, not two minors after it;
- an **N-1 → N upgrade job** runs nightly on both engines over a database holding data, and a restore is
  performed on each.

## Consequences

- A breaking API change after 1.0 costs two minor releases or a `/api/v2`; the CI diff makes the cost
  visible at the pull request, not in a consumer's pipeline.
- Every agent-facing change is designed in two steps, and the compatibility test runs the previous
  release's agent image on every build of `develop` — slower CI, and the only way the promise holds.
- The supported engine list keeps the integration campaign at two servers, both MySQL. An installation on
  PostgreSQL moves to MySQL before 1.0 or stays on 0.x.
- Security fixes are backported to the previous minor for three months: a cost in one maintainer's time,
  held down by [0047](0047-patch-releases-carry-no-migration.md) (a patch never carries a migration).
- Until these hold, the project stays 0.x and says so; nothing here changes what 0.11 promises.

## Rejected

- **Strict agent/control-plane lockstep** — simpler, and stops every scan during each rolling upgrade (§2).
- **A separate internal API for the interface** — a second contract to keep apart, depended on anyway (§1).
- **HA in 1.0** — nothing executes it today (§4).
- **Two engines, PostgreSQL 16 and later beside MySQL** — the first wording of §3. Rejected on
  2026-10-29: the checks existed, but keeping them green on two versions of each engine costs more than an
  installation base that runs MySQL returns. The code is kept so that the choice can be reversed (§3).
