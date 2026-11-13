# What the Rust port owes Java 1.0 — the catch-up list

The port was paused on 2026-10-29 against the 0.11.1 line and re-landed on 2026-11-12 on 1.0.0-rc.2 (`c99a3ccb5`),
Phase 0 of the recovery plan. Everything below is a difference Phase 0 **found**, not one it fixed: the reference
sets were regenerated from Java 1.0, the contract copy refreshed, the Flyway record rewritten, and each test that now
fails is a module whose Rust half still answers as Java did on 2026-10-29. Phase 1 works through this list; an entry
leaves it in the commit that makes its tests green. **No test was ignored or loosened to empty this list.**

State at the end of Phase 0, `VECTISPIRE_TEST_ENGINES=mysql cargo test --workspace`: 1,307 passed, 19 failed, in the
13 targets named below.

**`[→]` marks an item moved to the wave that ports its module** (2026-11-13): a route of a module whose routes Rust does
not serve at all yet is ported with that module, not stood up alone during the catch-up.

## Access (`cp-access`, `cp-runtime`)

- [x] **Sign-in throttling was redesigned** (V101 `sign_in_known_clients`). `vectispire.security.login-attempts-per-window`
      and `login-attempt-window` are gone; Java counts `vectispire.sign-in.failures-per-account` (50),
      `failures-per-client` (20), `failures-per-account-from-client` (5), keeps known clients
      `known-client-retention` (P30D), and bounds password derivations (`derivations.concurrent`, `queue-wait`).
      Buckets: IPv6 grouped by /64, and IPv4 in brackets and `host:port` spelled differently.
      Red: `cp-access --test sign_in_reference_set`, `cp-runtime --test java_parity`.
      - [x] The settings, read with Java's defaults (`cp-runtime` `java_parity`, `settings`); the three counters, the
            soft budget across clients, `t_sign_in_client` (remembered at every session, asked for unknown names too,
            purged by `SESSION_CLEANUP`), the code sent with the password and the one-second deadline
            (`sign_in_flow`, `sign_in_on_both_engines`).
      - [ ] **The buckets** — `ClientBuckets.of` now reads through `AddressLiterals` (port dropped, brackets for IPv6
            only); `client_bucket` is `cp-http`'s (`address.rs`), left to its owner. `sign_in_reference_set` stays red
            on 6 addresses. `TrustedProxies` reads hops through `AddressLiterals` too (every `X-Forwarded-For` line, a
            hop that is no address answering the nearest trusted proxy) — not on this list before.
      - [x] **The derivation gate** (`DerivationGate`, 503 `DerivationsSaturated` with `Retry-After`): `cp-access`
            `derivations` — fair permits, the queue wait, the shipped bound (processors, at least two, a quarter of the
            container's memory where Java reads its heap), one bound for the process installed at start; every
            password derived through it (`passwords::verify_bounded` / `hash_bounded`: the sign-in, the stand-in's
            included, the password change, the MFA enrolment, an account created or reset, the rehash) and the API
            keys' verification. A saturated sign-in, password change or enrolment takes its attempt back
            (`verifyReserved`); `DerivationsSaturated::problem` is `ApiExceptionHandler`'s 503 (`derivations`,
            `p1-access-catch-up.py`). Still owed, not on this list before: **the bearer chain's 503** for an API key
            refused for want of a permit — `cp-http`'s `Credentials::api_key` has no way to say "busy", so the key
            path answers it as no credential (Java's `BearerAuthenticationFilter` writes 503 with `Retry-After`); and
            **an API key's issuance** (`AgentKeys`, `ApiKeyAdministrationService` hash under the bound in Java) still
            derives outside it.
      - [x] `cp-app` composes `vectispire.sign-in.*` (`access::compose`): the derivation bound for the process, the
            known clients' retention on `SESSION_CLEANUP` (`session_cleanup_task_with_limits`), and the ceilings the
            sign-in flows are built with (`Access::limits`, for `SignInFlow::with_limits` — the binary builds no flow
            while no access route is served). `cp-app --test access_composition`, on a real database.
      *Closed 2026-11-13: the address buckets (the last sub-item) were done in cp-http on 2026-11-12;
      `sign_in_reference_set` is green.*
- [→] **Account requests** *(moved 2026-11-13 to access, wave 1 (task 1.7: Rust serves no access route yet): a route of a module Rust does not serve yet is ported with its module)*: `GET /account-requests`, `POST …/{id}/approve`, `POST …/{id}/reject`; audit operations
      `ACCOUNT_REQUEST_FILED / _APPROVED / _REJECTED` (SIEM maps them to `ACCOUNT_CHANGED`). Not-yet-ported list.
- [→] **`DELETE /users/{id}/second-factor`** *(moved 2026-11-13 to access, wave 1 (task 1.7): a route of a module Rust does not serve yet is ported with its module)*, and `UserView.scimManaged` (V102). Not-yet-ported list.
      - [x] `scim_managed` read on `User`, `UserView` and SCIM's rows, set by every provisioning write
            (`scim_on_both_engines`).
      - [x] The refusal it exists for — an e-mail change on such an account, 409 `managed-by-directory` — at the
            service: `AccountChange.email` (`emailChange`: the address it holds is no change, read as an address,
            refused when another account holds it, audited without the address; a creation's address read the same
            way), `AccountError::ManagedByDirectory`. SCIM's `scimLoweredFrom` (V93): recorded when the directory lowers
            a privileged unbound account, refusing its binding until an administrator sets its role, which clears it;
            `bindOnce`'s refusals in Java 1.0's words (`service`, `engines`, `scim_on_both_engines`). The route's 409
            is task 1.7's, with the route.
- [x] **OIDC**: settings bound by `OidcProperties` (no longer `@Value`), new `vectispire.oidc.link-by-claim` (true);
      SCIM's link-privileged switch reads `OidcProperties.linkPrivilegedAccounts`. Red: `java_parity`. (The loader reads
      `link-by-claim`; its consumer is the single sign-on, task 1.4, not ported.)
- [x] **Mail** settings bound by a record (no longer `@Value`). Red: `java_parity`.
- [x] **Access reference set** — red on `Sessions.bearerToken` only: Java 1.0 reads `^bearer\s+(\S+)$` in any case.
      What this entry listed (settings saved in one transaction with the notification channels, 409
      `integration-disabled`, a secret administrator-only setting refused unchanged, `checkAiEndpoint` hiding the URL)
      is in no Rust test or reference set: it is the settings service's (`cp-settings` / `cp-platform`), still owed.
- [x] **Settings save and AI endpoint check** (moved from the line above): settings saved in one
      transaction with the notification channels; 409 `integration-disabled` when the tracker or the AI provider moves
      to a disabled integration, or AI review is turned on over one; a secret administrator-only setting refused from a
      non-administrator even unchanged; `checkAiEndpoint` hides the URL from a non-administrator.
      *Done 2026-11-13 in `cp-platform`'s `SettingsAdministration` (`cp-platform --test engines`): the channels a save
      configures (`NotificationDestinations.configuredBy`, read in cp-platform until the notifications module lands in
      wave 2) held in the write's transaction, the risk acknowledgement written in it too; `check_ai_endpoint` over
      an `AiEndpoint` seam the AI module will fill. Found on the way: the Ollama address's 403 had the channels'
      sentence instead of its own. The settings routes stay unserved.*

- [x] **Found while catching up access** (2026-11-12): the derivation gate (`DerivationGate`, 503 when every password
      derivation permit is taken — the `sign-in.derivations.*` settings are read, nothing uses them yet); cp-app does
      not pass `settings.sign_in` to the sign-in flow and the session cleanup (`with_limits`); an e-mail change on a
      directory-managed account → 409 `managed-by-directory` (V102; `AccountChange` has no e-mail yet) and SCIM's
      `scimLoweredFrom`; `POST /auth/mfa/enable` asks the current password again (`MfaEnableRequest.password`);
      ~~`TrustedProxies` reads every `X-Forwarded-For` line through `AddressLiterals`, and a hop that is no address
      answers the nearest trusted proxy (cp-http)~~ — done 2026-11-12, as are the address buckets.
      *The rest done 2026-11-13 (the sub-items above): the gate, the composition, the e-mail refusal and
      `scimLoweredFrom`, and the password asked again at enrolment — `SecondFactor::enable(account, password, …)`,
      `reservePassword` spent, 401 `CurrentPasswordWrong`, 429 `PasswordLocked`, each audited (`sign_in_flow`). Every
      one at the service: no access route is served yet.*

- [x] **A busy derivation on an API key answers "no credential"** (found 2026-11-13): when no derivation permit comes
      free, Java answers 503 (`DerivationsSaturated`); cp-http's `Credentials::api_key` can only say a key is absent.
      *Done 2026-11-13: `Credentials::api_key_lookup` → `KeyLookup::Busy`, which the chain answers 503 with
      `Retry-After` and `retryAfterSeconds` (`tests/busy_key.rs`); cp-access returns it on `DerivationsSaturated`.*
- [x] **Issuing an API key derives outside the gate** (`issue_agent_key`, `issue_integration_key`): their error types
      have no "busy" case yet. *Done 2026-11-13: both hash under the bound; saturated, nothing is stored and the
      failure is the gate's (`credentials::saturation`), which `AgentError::Busy` answers 503
      (`tests/derivations.rs`).*

## Agents and the protocol (`cp-agents`, `protocol`, `agent`)

- [x] **Executors** (ADR 0045): `HelloRequest.executors` (optional, `null` when absent); `AgentView.executors`,
      `executorsReportedAt`; `PUT /agent/executors` (`{executors:[…]}`, 400 when the list is missing; an older control
      plane answers 404, read by the agent as "not supported"); the claim limited to the target kinds the agent's
      available executors run, none claimed with none available. Red: `protocol --test server_wire_reference_set`.
- [x] **Contract refusal and acceptance**: the 409 now reads "… and Vectispire serves contract <served>. <remedy>"
      (remedy for a newer agent: "Upgrade the control plane first, then its agents."); an accepted hello answers the
      contract spoken to that agent, not `CURRENT`. Red: `server_wire_reference_set`.
- [x] **`GET /admin/agents/built-in-worker`**: Rust's `GET /admin/agents/{id}` answers that path today — "built-in-worker"
      read as an agent id — so the route check calls it served. Register the literal route before the parameter one.
      Red: `cp-agents --test contract`.
- [x] The built-in worker checks its Docker daemon before claiming.
- [x] Maintenance: new tasks `SCAN_METRICS` (order 50) and `AGENT_METRICS` (60), composed with the gauges they refresh
      (`cp-app/src/gauges.rs`: Java's `PlatformMetrics` and `AgentMetrics` gauges, read from a snapshot each tick takes;
      `tests/gauges_composition.rs` on a real database). Java's counters beside them (scans started, completed, failed,
      lapsed; agents' polls and claims) are not ported yet, and whether a NaN gauge is written `null` (cp-runtime's
      JSON) or `"NaN"` (Jackson) is unverified against the Java image.
- [x] **Signing keys rotate** (`docs/en/KEY_ROTATION.md`): the record of known keys is sealed
      (`internal.document_signing_keys.sealed`) before the first signature; `vectispire.signing.revoked-keys`,
      `adopt-unsealed-keys`; verification tried against every published key, `Verification.keyStatus`; messages
      "…any of Vectispire's signing keys…" and "…nor one it signed with before…"; `GET /crypto/public-keys` and
      `/crypto/public-keys/{keyId}.pub`. Red: `cp-crypto --test reference_set`.
      *Phase 1 (`rust/p1-platform`): the service is done and green (`reference_set`, `rotation` on MySQL), the binary
      starts it as Java's constructor does. Owed: the two routes, written and tested in `cp-platform` but not routed —
      `cp-http`'s chain opens only `public-key.pub` to an anonymous caller, and its route builder cannot route
      `{keyId}.pub` (matchit 0.8.4); `cp-runtime` binds neither `revoked-keys` nor `adopt-unsealed-keys`; the replay's
      router (`cp-agents/tests/golden.rs`) builds a key per test, so its first signature records the key where Java's
      context had recorded it before the suite (the 5 crypto recordings now differ by that insert).*
      *Done 2026-11-12: both routes served (cp-http opens them and routes `{keyId}.pub`), the two settings bound.*
- [x] **`ENCRYPTION_KEY` refused at start** when a template placeholder or a passphrase under 20 code points (exact
      32-byte keys and previous keys exempt).
- [x] **Integrations** (ADR 0040): `GET /integrations`, `PUT /integrations/{key}/enabled`, audit
      `INTEGRATION_ENABLED_CHANGED`. Not-yet-ported list. *The registry in `cp-settings`, the routes in `cp-platform`;
      their `golden/deferred/platform.txt` lines stay until the replay's router composes them, and the notification
      channels' in-use answer joins with the notifications module.*
- [x] **Settings**: new `four_eyes_independence_days` (INTEGER, 30, TRIAGE), one setting became administrator-only,
      forge API roots with a query or fragment refused; `validation.json` moved. Red: `cp-settings --test reference_set`.
- [x] **Metrics**: `vectispire.metrics.scrape-token` / `-file` accepted as a bearer on `/actuator/prometheus` (declared
      in the property table; not honoured yet). The loader now reads it as `ScrapeTokenProperties` does — the file's
      when named, read at each call, refused at start under 32 characters (`Settings::metrics`). Still owed: the Rust
      actuator serves no `/actuator/prometheus`, and recognising the token is `cp-http`'s chain.
      *Done 2026-11-13 (`rust/p1-actuator`): `cp-runtime` writes the meters in the text format 0.0.4 as Micrometer does
      (`metrics::tests`; the gauges `cp-app` registers held line for line to the page Java 1.0 recorded,
      `cp-app --test actuator_composition`); `cp-http` recognises the token on that exact path only, compared in
      constant time, a file that cannot be read failing the scrape (`cp-http --test actuator`); the binary mounts the
      actuator behind the chain (`cp-app --test binary`). **Found on the way**: the binary mounted no actuator at all —
      `/actuator/health` and its probes answered 404 — it does now. The actuator's index (`/actuator`) still lists
      0.11's links: its reference (`reference/actuator/rc3-answers.json`) is rc3's, and no 1.0 recording says where
      Java puts `prometheus` and `encryption` among them. Java's counters beside the gauges (above) are still not
      ported, so the page has no `_total` series yet.*
- [x] Audit operations list. Red: `cp-audit --test reference_set`.

## SIEM (`cp-siem`, `domain`)

- [x] Each transport is an integration: a disabled one holds delivery (`HeldDeliveryException`, attempts not counted);
      an enabled save or a test over one answers 409 `integration-disabled`; the save runs in a transaction; no stop
      notice over a disabled transport, and the audit text says so; `census()` reports how the stored authorization
      header is sealed. Red: `domain --test siem_reference_set`.
      *Phase 1: all but the census, green (`siem_reference_set`, `cp-siem --test engines`, the outbox's `Held`); the
      port has no `/actuator/encryption` and so no census to report into yet.*
      *Census done 2026-11-13 (`rust/p1-actuator`): `/actuator/encryption` served from `cp-crypto`'s `EncryptionCensus`
      with the contributors the port has — the signing key and its record (cp-crypto), the clone tokens and deploy keys
      (cp-targets), the SIEM header (cp-siem, `cp-siem --test engines`) — and the start's warning while a store needs a
      previous key. Java's other seven stores have no Rust module yet and are not in the census: TOTP secrets and backup
      codes (access), forge connection tokens (forges), the tracker's token and inbound webhook secret (tickets), the
      notification signing secret (notifications), the OpenAI key (ai) — each port adds its line to
      `cp-app/src/actuator.rs` (`cp-app --test actuator_composition` lists them). Until then the census's two 200
      recordings are listed in `golden/deferred/_composition.txt`.*

## Targets, scanning, checklists, compliance

- [x] `GET /git-tokens`, `/repositories/duplicates`, `/ssh-keys` take `limit` and `offset`. Red: `cp-targets --test contract`.
- [x] `ScanningProperties` binds `bundledRules`, `hostSsh`, `pluginRegistry`, `pluginSignatureRequired`,
      `vulnerabilityDbDir`, `images` (the property table already says `bundled-rules` is a record).
      *Checked 2026-11-13: nothing to change — `cp-runtime`'s table reads each from `application.yaml` with Java's
      default (`java_parity` green), `bundled-rules` as a record, and a blank `image-platform` reads as absent, as the
      record's constructor makes it.*
- [x] Checklists: NO_DATA reason `forge_integration_disabled`, and the suspended reading checked first. Nothing feeds
      `ReviewFacts::Suspended` yet: the facts reader learns it with the integrations registry (decision 0040). Red: `cp-checklists --test reference_set`.
- [→] `GET /owasp/coverage/export.csv` *(moved 2026-11-13 to compliance, wave 1: a route of a module Rust does not serve yet is ported with its module)*. Not-yet-ported list.

## The golden replay of Java 1.0's traffic

Recorded at 1.0.0-rc.2 (`record-goldens.sh`: 2,616 tests, the two expected failures, 7,949 files) and replayed on
MySQL (`replay-goldens.sh`): 3,053 recordings of served routes are owed a replay, and they differ by a handful of
causes rather than one by one. Counts are recordings.

- [x] **Every answer lacks four security headers** Java 1.0 sends: `permissions-policy`,
      `cross-origin-opener-policy` (same-origin), `cross-origin-embedder-policy` (require-corp),
      `cross-origin-resource-policy` (same-origin) — 4,505. One layer in `cp-http`.
- [x] **Problem details carry a `code`** (`authentication-required`, …) — 432; and a few refusals' `type`, `title`,
      `status`, `instance`, `detail` where Rust answered differently.
- [x] **`IssueView` no longer carries `reachability` and `reachableSymbols`** (Java 1.0 dropped the two, always UNKNOWN and
      null) — 58, on `POST /issues/triage` mostly; the columns stay.
- [x] **Agents**: `executors`, `executorsReportedAt` on the agent views — 33; `t_scan.examined_types` written by a
      result — 33; the outbox rows a result writes — 34; status differences on `GET /agent/jobs`,
      `POST /agent/sealing-key`, `PUT /admin/agents/{id}/signing-key`, `POST /agent/jobs/{id}/failure`,
      `POST /agent/hello` (the contract range) — about 60.
      Phase 1, replayed on MySQL: the 349 recordings of `/agent/…` and `/admin/agents…` differ by the four headers
      and the problem details' `code` alone (the two entries above); the last own difference, an image scan's
      `branch` read as null in the activity, is fixed.
- [x] **SIEM configuration**: `PUT /siem/config` and `POST /siem/test` answer differently (the integration switch, a
      CA that is not current refused) — 14; `tlsCa*` fields null where the contract says string.
- [ ] **Recordings that cannot be replayed yet** — 4 (was 64): a request of the test the replay cannot rebuild.
      Left: two 2 MiB bodies in a gzip sidecar (a decompressor is a new crate to vet), a TLS collector nothing runs
      during the replay, and MockMvc's charset (an accepted difference, pinned by cp-http's own capture).

      *Result attestations done 2026-11-13: a signature on `/agent/jobs/{id}/result` or `/failure` that verifies under
      a seed the test was shown is written `«result-signature:result|failure:secret:S»`, and the replay signs the
      scan its path names and the bytes it sends with `ResultSigner`, as the Rust agent does. Recognised for its own
      record only: the same value sent to another scan (`noReplayAcrossScans`) stays `«secret:N»` (6 → 4).*
      The `«pem:…»` request bodies of SSH-key and CA tests are done; the rest are other kinds of hidden input.

      *`pem:` part done 2026-11-13: no test generated those keys — each was an invented literal (`DUMMY PRIVATE KEY` around a
      word, a PKCS#8 header with no scalar), hidden because the recorder hid every private-key PEM. Gathered in
      `core/golden/FixturePrivateKeys.java`, they are recorded as they are, by fingerprint only; the recordings' scan
      allows their exact text. A whole recording holds no `«pem:…»` any more: 22 of the 23 lines replay green, with
      the two `withheldPollsCostNoAttempt` lines their requests unblocked; `theCredentialIsSealedForTheVerifiedKeyOnly--006`
      stays, its audit entry chaining onto a sealing-key announcement the recorder hides (`_recording.txt`, 87 → 63).*

      *Also 2026-11-13: the 412 of a withheld credential answers code `credential-withheld` and a missing key
      `encryption-key-missing`, as `ApiExceptionHandler.preconditionFailed` (both were `precondition-failed`); an older
      agent's `v1` announcement is refused by name (`signed_by_a_previous_agent`). Nine lines replay green (15 → 6).*

      *Sealing part done 2026-11-13: the sealing keys `AgentSealingKeyRoutesTest` announces are fixtures
      (`FixtureSealingKeys`), and a signature the pinned seed made over one is recorded as
      `«sealing-signature:v2:secret:S:uuid:U:<generation>:<key>»` — Ed25519 is deterministic, but it signs the agent's id
      and the seed the server drew, so the replay signs again for its own agent. Folded in the same recording: a
      one-character padding under a credential's name stays literal (`gitTokenFieldsAreBounded--003`), an
      `identity_guard` its row's identity accounts for stays literal (`twinsFiledBeforeTheRule`), and the 8 rewind lines
      replay green with `«datetime:past»`. 43 lines removed, 58 → 15. Left from these: 8 claims answered 412 with
      `code` `precondition-failed` where Java says `credential-withheld` (cp-agents), and the `v1` announcement no
      Rust code signs or names (cp-agents).*
- [x] **`ListPagingEstateRoutesTest/refusesWhatItCannotServe`** — 36: the seed of `POST /plugins` (not served,
      played in Java's place) writes a `t_audit_log.description` longer than 255 once the recorder's placeholders
      are made concrete. A replay defect, not the port's.

      *Fixed 2026-11-13: the seed of a row Java had cut at its column's width came out wider once the recorder's
      placeholders were made concrete (a hidden id is not kept at its width). A seeded text is now cut to its column, as
      Java's database held it; the test's 24 recordings replay green and its 18 lines left `_recording.txt`.*
- [x] **An issue's decisions read oldest first, with `requestedStatus`** — 5, `HistoryTest`: Rust read them newest
      first, an older defect the 1.0 history recordings exposed; the decision view lacked V88's `requestedStatus`.
- [→] **A notification channel in use cannot be switched off** *(moved 2026-11-13 to notifications, wave 2: a route of a module Rust does not serve yet is ported with its module)* — 21, `NotificationChannelSwitchRoutesTest`: Java's
      `NotificationDestinations` answers the integrations registry `integration-in-use`; Rust has no notifications
      module yet (wave 2), so its switch-off is accepted.
- [→] **The published keys' list in the read-cost sweep** *(moved 2026-11-13 to compliance's exports, wave 1: a route of a module Rust does not serve yet is ported with its module)* — 2: an export Rust does not serve wrote the key record in
      Java's run, and the replay cannot rebuild its `«sealed»` value; ends with the compliance exports.

- [x] **`AgentExecutorsRoutesTest/anUnavailableExecutorClaimsNothing`'s wait reads 1 where Java's read 0** — fixed
      2026-11-13: the agents' administration takes a clock, as Java's does, and the replay hands it one that runs only
      while the router answers; the wall clock counted the replay's own seeding and comparing. 37 of 37 green, twice.

- [x] **Six scanning mutants survive on MySQL** (`security/mutants/p2-7-scanning.py`, re-pointed from PostgreSQL to
      MySQL on 2026-11-13: 96 of 102 killed). Survivors: "a deleted agent still claims", "another worker's report is
      applied", "the reason is stored whole", "the purge keeps the findings", "the latest scan forgets its status",
      "a clean scan is failed" — each a guard no test on MySQL holds; a test per guard is owed. Done 2026-11-13: 101 of
      101 killed. Four engine cases added or extended ("a deleted agent claims nothing", the latest scan's status, the
      findings phase alone inside its transaction — the FK's cascade had hidden it —, a result with every step absent
      and nothing broken); "the reason is stored whole" is killed by "a long reason is kept within its column" and
      did not survive again in three runs; "another worker's report is applied" is equivalent — the release's
      statement repeats the owner — and is named as such in the script.

Fixed in Phase 0, not owed: the seeder wrote `t_scan.has_sbom`, a generated column since V98, which MySQL refuses
(986 recordings could not be replayed at all); a seed, a restore and an update now leave generated columns out.

## Not done in Phase 0, still owed by it

- [x] The recorder's golden recordings regenerated from Java 1.0 and replayed, `fix/golden-signatures` applied first:
      the section above.
- [x] PostgreSQL left the port's jobs (2026-11-12, decision 0043 §3): `rust-engines` deleted, the nightly replay and
      `check.sh` on MySQL; the code for both engines kept.
