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

**One difference, on purpose:** Java writes each change in a transaction of its own; here they share one, which keeps
the rule "all or nothing" true when a write fails half-way, and changes nothing a reader can see otherwise.

## Not here yet

- The routes: `SettingsController`, `AuditLogController`, `CryptoController` — with the access routes' goldens.
- The four credential doors (tracker token, webhook signing secret, OpenAI key, inbound webhook secret), which encrypt
  before storing and ask the tracker about its token: `crypto`, `tickets`, `notifications`, `ai`.
- The AI endpoint check (`checkAiEndpoint`): `ai`.

```sh
cargo test -p vectispire-cp-platform     # the forms' unit tests, and the service on both engines (Docker)
```
