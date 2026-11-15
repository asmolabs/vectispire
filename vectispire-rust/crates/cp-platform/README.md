# vectispire-cp-platform

The control plane's platform module in Rust — `core.platform` (plan, Phase 1 task 1.6), as far as the modules it
composes are ported. In progress, not shipped: the Java control plane is the product.

## What is here

`SettingsAdministration` is `SettingsAdministrationService`'s catalog and save:

| Rule | As Java has it |
|---|---|
| A sensitive value leaves for an administrator only; a credential's for nobody; whether one is set is always said | `catalog` |
| An empty save, an unknown key, the AI acceptance record set from the wire — refused | `InvalidInputException`, its words |
| The rule-deciding settings (access, triage, checklists, evidence window) — the platform governor's only | `AccessDeniedException`, its words |
| A credential's destination and the reach of the SIEM and notification channels — an administrator's, **on a change only** | the three sentences, by setting |
| Four-eyes switched on — only with an approver, two template publishers and two checklist signers | the three sentences, in that order |
| A credential through this door; a value its type refuses; a tracker CA that would not be pinned; an expiry that is not a date (`LocalDate.parse`, held to a JDK's answers); a GitHub project that is not `owner/repository`, on the state the save produces | the sentences |
| The AI destination judged on the state the save produces, and **never** when the save withdraws the acknowledgement | `requireLocalUnlessAcknowledged` |
| Every change validated before any is written; then written together; the acknowledgement stamped or erased on the switch's transition only | |
| One audit entry per save — the keys as its resource, each change described without a secret's value — signalled `SECURITY_SETTING_CHANGED` when a security-governing setting is among them | |

The routes served so far are `AuditLogController`'s, `CryptoController`'s, `IntegrationsController`'s and the first two
of `SettingsController`'s (`src/web/`):

| Route | Marker | Service |
|---|---|---|
| `GET /api/v1/audit-log` | governance read | `cp-audit`'s `AuditLogQuery::page` — `limit`/`offset` clamped by the service, `search` bounded |
| `GET /api/v1/audit-log/operation-types` | governance read | `AuditLogQuery::operation_types` |
| `GET /api/v1/audit-log/verify` | governance read | `AuditLogQuery::verify` — a break told to the SIEM's listener |
| `GET /api/v1/crypto/public-key.pub` | anonymous | `cp-crypto`'s `SigningKeys::public_key_pem`, as a named download |
| `POST /api/v1/crypto/verify` | account | `SigningKeys::verify_with` — a request without a payload or a signature answered `valid: false`, not checked |
| `GET /api/v1/crypto/cosign-cli-helper` | account | `SigningKeys::key_id`, and the commands, `--insecure-ignore-tlog=true` on each cosign one |
| `GET /api/v1/settings` | account | `SettingsAdministration::catalog` — every setting with its type, section label, help, default, the value this reader may see, and who may change it |
| `PUT /api/v1/settings` | security lead | `SettingsAdministration::update` — answered `{"updated": n}`; a service's access denial is the chain's audited 403 |

The save's body is read as Jackson reads `Map<String, String>` into Spring's `LinkedHashMap`: in the order sent, a key
sent twice keeping its first place and its last value; `null` as absent; `true`, `false` and a number as **the text
sent** (`1.50` stays `1.50`, which `serde_json`'s `f64` would not give back — hence `raw_value`); an object or an array
as a value, or a body that is not an object, refused as the unreadable body.

The query parameters are read as Spring binds `@RequestParam` (`src/web/read.rs`): an `int`'s default for an absent or
empty value only, its first value when sent twice, a `String`'s values joined by commas.

**Replayed** (`crates/cp-agents/tests/golden.rs`) with the signing key configured, as `vectispire.signing.key` sets it:
the Java suite's context made its key before the recorded tests ran, so a key generated into `t_setting` here would be
an insertion no recording holds. Three recordings stay listed — two in `golden/deferred/_recording.txt` (a signature
and a forger's key the test made at run time, hidden by the recorder) and one in `compliance.txt` (a verification over
entries the compliance exports write, played in Java's place with invented hashes).

**Seams for the modules not ported yet.** `platform` may use any module in Java (decision 0029); it stays open in `cp-arch-tests`'
`edges.toml`, and the crate uses `audit`, `settings` and the outbound door; the rest is asked through traits the binary
fills (`cp-app/src/settings_screen.rs`, exercised by `cp-app/tests/settings_composition.rs`):

| Seam | Filled by | What of Java it is |
|---|---|---|
| `Approvers` | `cp-app`'s `AccessApprovers` over `access`' `TriageApprovers` | the three counts four-eyes needs, from the accounts table |
| `Tracker` | `TrackerCaPinning` (`src/seams.rs`) | `TicketService.caToPin`: `PinnedCa.parsePasted(pem, now, CA)`, the tracker's subject |
| `AiDestination` | `GuardedAiDestination` (`src/seams.rs`), over the guard `main` built | `AiReviewService.openAiUrl`/`ollamaUrl`, `requireLocalUnlessAcknowledged`, `record`/`clearRiskAcknowledgement` |
| `AiEndpoint` | `cp-app`'s `EndpointNotPorted`, which fails if asked | `checkAiEndpoint`'s questions of `ai` — its route is not served |

**Why `Tracker` and `AiDestination` are narrow.** A save asks `tickets` one question — would this pasted CA be pinned —
and `ai` two: is the destination this save leaves internal unless sending off-site was acknowledged, and record whose
acknowledgement it was. Each answer is a pure function of what this crate already reads: the CA rule is
`vectispire_domain::pinned_ca`'s (the forge connections' and the SIEM collector's), the guard is `cp-outbound`'s, the
acknowledgement two settings written in the save's transaction. Nothing of the tracker client, the token's health, the
review calls or the OpenAI key is needed, so none is brought forward: those are the wave-2 modules', and when `tickets`
and `ai` land they implement the two traits themselves and `src/seams.rs` goes. Both seams are held, with the save, to
`reference/platform/settings-save.json` (86 cases), which `SettingsSaveReferenceSetTest` writes with the real
`SettingsAdministrationService`, a real `AiReviewService` over a real `OutboundUrlGuard` (a fixed resolver table, in the
file) and `PinnedCa` itself; `tests/save_reference.rs` replays it on a database with the binary's seams.

The notification channels a save configures are read here (`NotificationDestinations.configuredBy`) until
`notifications` lands, and held through `settings`' integrations registry. The writer's two role properties come as a
`Caller`, read from the account's role by the route.

## Differences from Java, on purpose

- None left in the settings save: Java 1.0 writes a save's changes in one transaction as this crate did before it
  (decision 0040, lot I6, which holds the notification channels a save configures in that transaction), and stamps or
  erases the AI acknowledgement inside it — as `SettingsAdministration::update` now does too.

## Not here yet

`SettingsController`'s ten other routes, each waiting for the wave-2 module that ends it (listed in
`cp-contract/reference/not-yet-ported/platform.txt` and `golden/deferred/platform.txt`):

- the four credential doors, which encrypt before storing — the tracker token (`tickets`, which also asks the tracker
  about it), the inbound webhook secret (`tickets`), the webhook signing secret (`notifications`), the OpenAI key
  (`ai`) — and their four state reads;
- `GET /api/v1/settings/ticket-ca`, the pinned CA's description (`tickets`' `pinnedCa`);
- `POST /api/v1/settings/ollama-test`, the endpoint check, which calls the model (`ai`). The service's
  `check_ai_endpoint` is ported and tested over a stand-in; the route waits for a real `AiEndpoint`.

```sh
cargo test -p vectispire-cp-platform     # the forms' and routes' unit tests, the contract, the service and the Java reference set on a database (Docker)
```
