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

**Seams for the modules not ported yet.** `platform` may use any module in Java (decision 0029); it stays open in `cp-arch-tests`'
`edges.toml`, and the crate uses `audit` and `settings`; the rest is asked through traits the binary fills: `Approvers`
(`access`' `TriageApprovers`), `Tracker` (`tickets`' CA pinning), `AiDestination` (`ai`'s guard and acceptance record).
The writer's two role properties come as a `Caller`, resolved by `access`.

## Differences from Java, on purpose

- **A save's changes are written in one transaction.** `SettingsAdministrationService.update` validates every change
  first and then writes each in a transaction of its own (`SettingsService.set`), so a write that fails half-way
  leaves the earlier ones committed — the configuration between two intended states, which the validation-first
  rule exists to prevent. `SettingsAdministration::update` writes them all in one read-write transaction: every
  change or none. This was decided when the streams of Phase 1 were merged, and is kept: nothing a reader sees
  differs when every write succeeds, and when one fails nothing of the save is left written here.
  The acknowledgement of a remote AI destination is still stamped or erased after that commit, as in Java.

## Not here yet

- The routes: `SettingsController`, `AuditLogController`, `CryptoController` — with the access routes' goldens.
- The four credential doors (tracker token, webhook signing secret, OpenAI key, inbound webhook secret), which encrypt
  before storing and ask the tracker about its token: `crypto`, `tickets`, `notifications`, `ai`.
- The AI endpoint check (`checkAiEndpoint`): `ai`.

```sh
cargo test -p vectispire-cp-platform     # the forms' unit tests, and the service on both engines (Docker)
```
