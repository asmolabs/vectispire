# 0040 — An integration is switched on, not installed: forges, SIEM transports, AI providers, notification channels and trackers the governor enables

**Date:** 2026-10-07 · **Status:** accepted · **Builds on:** [0025](0025-siem-events-leave-through-the-outbox.md), [0035](0035-report-plugins.md), [0037](0037-discovering-repositories-at-setup.md) · **Decider:** Laurent Boucher

*Accepted on 2026-10-07 by the product owner (option A below). Built after the end-of-October
go-live; nothing of it is in 0.11.0.*

## Context

An installation is asked to choose which outside systems it talks to: GitLab but not GitHub, a SIEM
over syslog TLS but never a webhook. Today every adapter is on for everyone:

- **Forges** (0037): `ForgeKind` is GitHub and GitLab, both offered on the connection form; Bitbucket
  Cloud and Data Center are planned (D8). Adding a repository by its URL — "plain git" — is not a
  forge connection and needs none; which hosts may be cloned is already restricted by
  `VECTISPIRE_GIT_ALLOWED_HOSTS`.
- **SIEM** (0025): one destination, four transports (`SiemProtocol`: webhook, syslog over UDP, TCP and
  TLS), CEF or JSON.
- **AI** (`AiProvider`): Ollama, on a host the operator runs, and OpenAI.
- **Notifications** (`Setting`, section notifications): a generic webhook, Microsoft Teams, Slack,
  Discord and mail.
- **Trackers** (`TicketProvider`): GitLab, GitHub, Jira and ServiceNow issues.

The request named it "plugins": choose in the administration what is loaded and what is not. Two
things can be meant.

## Decision

**Option A — integrations switched on and off, in the product.** The adapters stay part of
Vectispire. A registry lists each integration — the forge kinds, the SIEM transports, the AI providers,
the notification channels and the trackers (amended 2026-10-07) — and the platform governor enables or
disables each one in *Administration → Integrations*. An installation that wants Ollama and never
OpenAI, Teams and never Discord, says so once.

1. **A disabled integration is unreachable, not hidden only.** It leaves every form and list that
   would offer it; its routes refuse with 409 `integration-disabled`, naming it; and no code path
   calls it — the outbound guard is not the place this is decided, the adapter's entry is.
2. **What already uses it is suspended, never deleted.** A forge connection of a disabled kind keeps
   its row and its encrypted token, reads *suspended — integration disabled*, and runs no discovery
   and no change-review reading; a checklist line it fed reads no data with that reason. Re-enabling
   resumes it as it was.
3. **What is disabled while in use depends on what would be lost.**
   - **A SIEM transport or a notification channel in use cannot be disabled.** Its configuration is
     changed first: security events or alerts left queued in the outbox with nowhere to go would be
     lost in silence, the one failure 0025 and 0033 exist to prevent. The refusal says so.
   - **An AI provider in use can be**, and the features that read it say *AI unavailable — provider
     disabled* rather than answering from another provider: nothing recorded is lost, and a review never
     silently moves from a host the operator runs to a hosted service.
   - **A tracker in use is suspended like a forge connection**: the links between issues and tickets
     are kept, no ticket is opened or synchronised, and re-enabling resumes.
4. **Each switch is a governance gesture.** Audited, and sent to the SIEM as a security setting
   change. Enabling widens what the installation can reach and may be put under four-eyes by the
   same setting as plugin registration; disabling narrows it and needs no second person.
5. **Defaults change nothing.** An upgrade and a new installation start with every existing
   integration enabled; an installation narrows from there. A new adapter (Bitbucket, D8) arrives
   disabled, so an upgrade never widens an installation's reach without a gesture.

## Alternatives considered

- **Option B — separately loaded modules** (a jar per adapter, present or absent). Rejected. A module
  loaded into the control plane runs with its secrets — `ENCRYPTION_KEY`, the database — so each one
  would need what the scanner and report plugins have (a signed artifact, a verified signer, a
  registry under four-eyes) without the isolation that makes those safe: they run in a container
  that reaches nothing, a forge or a SIEM adapter must hold tokens and reach the internal network.
  The cost of a plugin system for a gain an enable switch gives.
- **A deployment-time list** (an environment variable of the enabled kinds). Rejected as the only
  means: invisible on screen, unaudited, changed by whoever edits the deployment. It may remain as an
  upper bound an operator sets — what the governor can enable — if an installation asks for one.

## Consequences

- The connection form, the SIEM settings and the discovery screens read the registry; the API
  reference names `integration-disabled`.
- Every adapter added later — Bitbucket first — registers itself and arrives disabled.
- A suspended connection is visible as such, in English and French, with what re-enabling does.

## Implementation, in lots (after the go-live)

| Lot | Content | Size |
|---|---|---|
| I1 | The registry in a table of its own (`t_integration`, not a setting: a setting records neither who switched it nor when), the governor's route and audit; 409 on the routes of a disabled integration | M |
| I2 | Forge connections: suspended state, discovery and change review skipped with their reason | M |
| I3 | SIEM: transports in the registry, the in-use refusal | S |
| I4 | *Administration → Integrations* screen, forms filtered; documentation in English and French | M |
| I5 | AI providers: the registry, *AI unavailable — provider disabled* in the features that read it | S |
| I6 | Notification channels (the in-use refusal) and trackers (suspended) | M |
