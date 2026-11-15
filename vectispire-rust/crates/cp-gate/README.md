# vectispire-cp-gate

The control plane's quality gate in Rust — `core.gate` and `common.domain.gate` (plan, Phase 3 task 3.4). Not shipped:
the Java control plane is the product. Its seven routes are served, composed in the binary and in the golden replay,
and every one of their recordings replays green — `golden/deferred/gate.txt` is gone.

## What it does

| Rust | Java | |
|---|---|---|
| `PolicyGate` (`gate.rs`) | `PolicyGate` | what a verdict considers (open, a type that takes part, triage, fixable-only), its rules in their order — the observation first, then one violation per issue (KEV before severity), then coverage — and `harden`, by which a request only tightens |
| `PolicyResolution`, `RequestedPolicy`, `SeverityRequest` | the same | whose policy applies (the target's replaces the global one whole; the built-in carries no version) and how its source is described |
| `GatePolicyFields` | `GatePolicyFields` | the one reading of a route's body: as one verdict's request (absent is not mentioned) or as a stored policy replacing the last (every field required but the two newest flags) |
| `Observation` | `Observation` | what a target's newest finished scan says about how far its backlog can be trusted (decision 0007: never scanned is a refusal, not a clean backlog) |
| `SecurityOverview` | `SecurityOverview` | the security screen: each target's verdict over its newest finished scan, its posture over its newest scan, the KEV banner over what the verdicts held |
| `GateService` | `GateService` | `evaluate_and_record` — the only way a route reaches a verdict, so each answer joins the register; the verdict and its `SECURITY_GATE_FAILED` in one transaction, or apart if that cannot commit, and never at the expense of the answer |
| `GatePolicyAdministrationService`, `ActiveGatePolicies` | the same | a stored policy is a new version superseding the active one, audited; a stored threshold reads empty as off and unreadable as the built-in one |
| `GateRegisterService`, `RegisterCursor` | the same | the register paged by `(decided_at, id)`, visibility applied after the read, the cursor taken from the rows read |
| `VerdictRetentionTask`, `GatePolicyPurge` | the same | the register purged past the evidence window (maintenance slot `GATE_VERDICTS`); a target's policies deleted with it |
| `persistence` | `GatePolicyEntity`, `GateVerdictEntity` and repositories | SeaORM entities and statement builders run on the port's `Tx` (decided 2026-10-26) — no `sqlx::query!`, so no `.sqlx/` cache: the statements follow the input's shape, and each entity is held to the schema by `orm::entity_table` |
| `routes` (`web`) | `GateController`, `GatePoliciesController` | `POST /api/v1/gate` (write account, or a key of scope `scan`), `GET /api/v1/gate/verdicts` (account, or a `read` key), `GET /api/v1/security/overview`, and the four policy routes (governance read; security lead to change) |

## Authorization

`POST /api/v1/gate` names a target: the route resolves the caller's `Visibility` (the account's grant intersected with
the credential's) and refuses a target outside it with **404**, never 403, before the policy fields are read — a body
refusal first would tell the caller the target exists. The register and the overview narrow to what the caller sees;
the policy routes name a target but answer only to governance roles that see the whole estate, as in Java.
`cp-app/tests/route_authorization.rs` holds every route's marker and scoping to the registry.

## Differences from Java

None deliberate. Parity slips found while closing the task (2026-11-15) and fixed rather than kept: the policy fields,
the stored threshold, the note and a published fix were read with Rust's whitespace where Java asks `isBlank` and
`String.trim` (a no-break space is not blank to Java; a control character is padding to `trim`); the register's cursor
was trimmed where Java reads it as sent, and its number read in ASCII where `Long.parseLong` takes every script's
digits; `limit=%20` took the default where Spring refuses it, and a query value was decoded byte by byte as Latin-1.

## What holds it

| | |
|---|---|
| the recorded traffic | the golden replay (`crates/cp-agents/tests/golden.rs`) — every recording of the seven routes, on MySQL |
| the decisions | `tests/domain.rs`: Java's `PolicyGateTest`, `PolicyResolutionTest`, `SecurityOverviewTest`, `GatePolicyFieldsTest` and `RegisterCursorTest`, case by case, and the parity cases above |
| the tables | `src/persistence/tests.rs`, on MySQL 9.4 (and PostgreSQL 17 where `VECTISPIRE_TEST_ENGINES` asks): policies read back, versioned and deleted by scope; the register's order, ties, paging for a restricted reader, window and purge; a refusal raised with its verdict or apart; the entities against the schema |
| the contract | `tests/contract.rs`: the seven routes as `openapi.json` documents them, and the router probed |
| mutation | `security/mutants/p3-4-gate.py` |
