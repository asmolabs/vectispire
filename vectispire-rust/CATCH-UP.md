# What the Rust port owes Java 1.0 — the catch-up list

The port was paused on 2026-10-29 against the 0.11.1 line and re-landed on 2026-11-12 on 1.0.0-rc.2 (`c99a3ccb5`),
Phase 0 of the recovery plan. Everything below is a difference Phase 0 **found**, not one it fixed: the reference
sets were regenerated from Java 1.0, the contract copy refreshed, the Flyway record rewritten, and each test that now
fails is a module whose Rust half still answers as Java did on 2026-10-29. Phase 1 works through this list; an entry
leaves it in the commit that makes its tests green. **No test was ignored or loosened to empty this list.**

State at the end of Phase 0, `VECTISPIRE_TEST_ENGINES=mysql cargo test --workspace`: 1,307 passed, 19 failed, in the
13 targets named below.

## Access (`cp-access`, `cp-runtime`)

- [ ] **Sign-in throttling was redesigned** (V101 `sign_in_known_clients`). `vectispire.security.login-attempts-per-window`
      and `login-attempt-window` are gone; Java counts `vectispire.sign-in.failures-per-account` (50),
      `failures-per-client` (20), `failures-per-account-from-client` (5), keeps known clients
      `known-client-retention` (P30D), and bounds password derivations (`derivations.concurrent`, `queue-wait`).
      Buckets: IPv6 grouped by /64, and IPv4 in brackets and `host:port` spelled differently.
      Red: `cp-access --test sign_in_reference_set`, `cp-runtime --test java_parity`.
- [ ] **Account requests**: `GET /account-requests`, `POST …/{id}/approve`, `POST …/{id}/reject`; audit operations
      `ACCOUNT_REQUEST_FILED / _APPROVED / _REJECTED` (SIEM maps them to `ACCOUNT_CHANGED`). Not-yet-ported list.
- [ ] **`DELETE /users/{id}/second-factor`**, and `UserView.scimManaged` (V102). Not-yet-ported list.
- [ ] **OIDC**: settings bound by `OidcProperties` (no longer `@Value`), new `vectispire.oidc.link-by-claim` (true);
      SCIM's link-privileged switch reads `OidcProperties.linkPrivilegedAccounts`. Red: `java_parity`.
- [ ] **Mail** settings bound by a record (no longer `@Value`). Red: `java_parity`.
- [ ] **Access reference set** — settings save: one transaction holding the notification channels; 409
      `integration-disabled` when the tracker or the AI provider moves to a disabled integration, or AI review is turned
      on over one; a secret administrator-only setting refused from a non-administrator even unchanged;
      `checkAiEndpoint` hides the URL from a non-administrator. Red: `cp-access --test reference_set`.

## Agents and the protocol (`cp-agents`, `protocol`, `agent`)

- [ ] **Executors** (ADR 0045): `HelloRequest.executors` (optional, `null` when absent); `AgentView.executors`,
      `executorsReportedAt`; `PUT /agent/executors` (`{executors:[…]}`, 400 when the list is missing; an older control
      plane answers 404, read by the agent as "not supported"); the claim limited to the target kinds the agent's
      available executors run, none claimed with none available. Red: `protocol --test server_wire_reference_set`.
- [ ] **Contract refusal and acceptance**: the 409 now reads "… and Vectispire serves contract <served>. <remedy>"
      (remedy for a newer agent: "Upgrade the control plane first, then its agents."); an accepted hello answers the
      contract spoken to that agent, not `CURRENT`. Red: `server_wire_reference_set`.
- [ ] **`GET /admin/agents/built-in-worker`**: Rust's `GET /admin/agents/{id}` answers that path today — "built-in-worker"
      read as an agent id — so the route check calls it served. Register the literal route before the parameter one.
      Red: `cp-agents --test contract`.
- [ ] The built-in worker checks its Docker daemon before claiming.
- [ ] Maintenance: new tasks `SCAN_METRICS` (order 50) and `AGENT_METRICS` (60). Red: `cp-maintenance --test reference`.

## Platform, crypto and integrations (`cp-platform`, `cp-crypto`, `cp-settings`)

- [ ] **Signing keys rotate** (`docs/en/KEY_ROTATION.md`): the record of known keys is sealed
      (`internal.document_signing_keys.sealed`) before the first signature; `vectispire.signing.revoked-keys`,
      `adopt-unsealed-keys`; verification tried against every published key, `Verification.keyStatus`; messages
      "…any of Vectispire's signing keys…" and "…nor one it signed with before…"; `GET /crypto/public-keys` and
      `/crypto/public-keys/{keyId}.pub`. Red: `cp-crypto --test reference_set`.
- [ ] **`ENCRYPTION_KEY` refused at start** when a template placeholder or a passphrase under 20 code points (exact
      32-byte keys and previous keys exempt).
- [ ] **Integrations** (ADR 0040): `GET /integrations`, `PUT /integrations/{key}/enabled`, audit
      `INTEGRATION_ENABLED_CHANGED`. Not-yet-ported list.
- [ ] **Settings**: new `four_eyes_independence_days` (INTEGER, 30, TRIAGE), one setting became administrator-only,
      forge API roots with a query or fragment refused; `validation.json` moved. Red: `cp-settings --test reference_set`.
- [ ] **Metrics**: `vectispire.metrics.scrape-token` / `-file` accepted as a bearer on `/actuator/prometheus` (declared
      in the property table; not honoured yet).
- [ ] Audit operations list. Red: `cp-audit --test reference_set`.

## SIEM (`cp-siem`, `domain`)

- [ ] Each transport is an integration: a disabled one holds delivery (`HeldDeliveryException`, attempts not counted);
      an enabled save or a test over one answers 409 `integration-disabled`; the save runs in a transaction; no stop
      notice over a disabled transport, and the audit text says so; `census()` reports how the stored authorization
      header is sealed. Red: `domain --test siem_reference_set`.

## Targets, scanning, checklists, compliance

- [ ] `GET /git-tokens`, `/repositories/duplicates`, `/ssh-keys` take `limit` and `offset`. Red: `cp-targets --test contract`.
- [ ] `ScanningProperties` binds `bundledRules`, `hostSsh`, `pluginRegistry`, `pluginSignatureRequired`,
      `vulnerabilityDbDir`, `images` (the property table already says `bundled-rules` is a record).
- [ ] Checklists: NO_DATA reason `forge_integration_disabled`. Red: `cp-checklists --test reference_set`.
- [ ] `GET /owasp/coverage/export.csv`. Not-yet-ported list.

## The golden replay of Java 1.0's traffic

Recorded at 1.0.0-rc.2 (`record-goldens.sh`: 2,616 tests, the two expected failures, 7,949 files) and replayed on
MySQL (`replay-goldens.sh`): 3,053 recordings of served routes are owed a replay, and they differ by a handful of
causes rather than one by one. Counts are recordings.

- [ ] **Every answer lacks four security headers** Java 1.0 sends: `permissions-policy`,
      `cross-origin-opener-policy` (same-origin), `cross-origin-embedder-policy` (require-corp),
      `cross-origin-resource-policy` (same-origin) — 4,505. One layer in `cp-http`.
- [ ] **Problem details carry a `code`** (`authentication-required`, …) — 432; and a few refusals' `type`, `title`,
      `status`, `instance`, `detail` where Rust answered differently.
- [ ] **Inventory components carry `reachability` and `reachableSymbols`** — 58.
- [ ] **Agents**: `executors`, `executorsReportedAt` on the agent views — 33; `t_scan.examined_types` written by a
      result — 33; the outbox rows a result writes — 34; status differences on `GET /agent/jobs`,
      `POST /agent/sealing-key`, `PUT /admin/agents/{id}/signing-key`, `POST /agent/jobs/{id}/failure`,
      `POST /agent/hello` (the contract range) — about 60.
- [ ] **SIEM configuration**: `PUT /siem/config` and `POST /siem/test` answer differently (the integration switch, a
      CA that is not current refused) — 14; `tlsCa*` fields null where the contract says string.
- [ ] **Recordings that cannot be replayed yet** — 64: a request of the test the replay cannot rebuild, mostly
      `«pem:…»` request bodies of SSH-key and CA tests the recorder hides.
- [ ] **`ListPagingEstateRoutesTest/refusesWhatItCannotServe`** — 36: the seed of `POST /plugins` (not served,
      played in Java's place) writes a `t_audit_log.description` longer than 255 once the recorder's placeholders
      are made concrete. A replay defect, not the port's.

Fixed in Phase 0, not owed: the seeder wrote `t_scan.has_sbom`, a generated column since V98, which MySQL refuses
(986 recordings could not be replayed at all); a seed, a restore and an update now leave generated columns out.

## Not done in Phase 0, still owed by it

- [x] The recorder's golden recordings regenerated from Java 1.0 and replayed, `fix/golden-signatures` applied first:
      the section above.
- [x] PostgreSQL left the port's jobs (2026-11-12, decision 0043 §3): `rust-engines` deleted, the nightly replay and
      `check.sh` on MySQL; the code for both engines kept.
