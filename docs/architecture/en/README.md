# Vectispire Architecture (English)

This folder is written for **someone picking up the code** — not for a reviewer, not for a
committee. It answers three questions, in this order: how it is built, why it is built that way, and
what breaks if you change it without knowing.

> These documents describe the system as it is: a Spring Boot control plane in `vectispire-java/`
  and an Angular interface in `vectispire-angular/`.

| Document | The question it answers |
|---|---|
| [01 — Overview](01-overview.md) | What does Vectispire do, what is it made of, and what path does a scan take? |
| [02 — Data model](02-data-model.md) | What is stored, and why is a *finding* not an *issue*? |
| [03 — Security](03-security.md) | What are the trust boundaries, what guards them, and what is still open? |
| [04 — Runtime and deployment](04-runtime-and-deployment.md) | One instance, several, remote agents: what is allowed and what is refused? |
| [Decision register](decisions/) | One page per structural decision, with the alternative that was rejected. |

Three further bodies of work live beside these chapters, and are reached from here rather than only
from the folder above — a reader who enters at this page should not have to guess that they exist.

| Where | What it is |
|---|---|
| [STRIDE threat model](../security/en/STRIDE_THREAT_MODEL.en.md) | The formal threat analysis behind [03](03-security.md): one pass per STRIDE category, with the control that answers it. |
| [C4 model](../c4/README.md) | The system in Structurizr DSL, with generated context, container and component diagrams. CI fails if the committed diagrams drift from [`workspace.dsl`](../c4/workspace.dsl). |
| [Architecture dossier](../bflorat/en/README.md) | The five views of the Bertrand Florat model — application, security, dimensioning, infrastructure, development. |

## Elsewhere in the documentation

- [`docs/en/GETTING_STARTED.md`](../../en/GETTING_STARTED.md) — install and run.
- [`docs/en/TECHNICAL_DOCUMENTATION.md`](../../en/TECHNICAL_DOCUMENTATION.md) — reference for
  modules and settings.
- [`docs/en/ROTATION_AND_PURGE.md`](../../en/ROTATION_AND_PURGE.md) — encryption key rotation and
  purging.
- [`docs/en/api/rest_api_reference.md`](../../en/api/rest_api_reference.md) — complete REST API
  endpoints reference.
- [`docs/en/CI_CD_INTEGRATION.md`](../../en/CI_CD_INTEGRATION.md) — CI/CD integration guide &
  vectispire-cli runner.
- [`docs/en/TICKETING_INTEGRATION.md`](../../en/TICKETING_INTEGRATION.md) — bidirectional ticketing
  sync (Jira, GitLab, GitHub, ServiceNow).
- [`docs/en/NOTIFICATIONS_INTEGRATION.md`](../../en/NOTIFICATIONS_INTEGRATION.md) — alerts &
  webhooks integration (Discord, Slack, Microsoft Teams).
- [`docs/en/ATTACK_PATH_VISUALIZER.md`](../../en/ATTACK_PATH_VISUALIZER.md) — interactive attack
  path visualizer (Ingress &rarr; API &rarr; RCE &rarr; Secret/DB).

