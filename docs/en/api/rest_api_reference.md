# Vectispire REST API Reference

This document provides the official, comprehensive reference for all REST endpoints exposed by the **Vectispire Control Plane** (v4.1.0).

---

## 🔒 Security & Authentication

Vectispire APIs support three distinct authentication mechanisms:

### 1. User Session Token (`Bearer JWT`)
* **Header**: `Authorization: Bearer <token>`
* **Usage**: Angular web console and interactive user sessions.
* **Acquisition**: Via `POST /api/v1/auth/login` (with MFA / TOTP step verification via `POST /api/v1/auth/mfa/verify`).

### 2. Scanner Agent Key (`X-Agent-Key`)
* **Header**: `X-Agent-Key: <agent_key>`
* **Usage**: Distributed remote scanning agent protocol (`/api/v1/agent/**`).

### 3. Programmatic API Key (`X-API-Key`)
* **Header**: `X-API-Key: <api_key>`
* **Usage**: Automation scripts, CI/CD pipelines (GitHub Actions, GitLab CI), and SIEM integration.

---

## 🧭 Endpoints Summary

| Domain | Method | Endpoint | Auth | Description |
|---|---|---|---|---|
| **Auth** | `POST` | `/api/v1/auth/login` | Public | User credentials authentication (username / password). |
| **Auth** | `GET` | `/api/v1/auth/methods` | Public | Discover active login methods (Password, SSO OIDC). |
| **Auth** | `POST` | `/api/v1/auth/session/exchange` | Public | Exchange SSO hand-off cookie for a valid JWT session. |
| **Auth** | `POST` | `/api/v1/auth/mfa/verify` | Public | Verify TOTP code for active MFA challenge. |
| **Auth** | `POST` | `/api/v1/auth/mfa/setup` | Account | Initialize two-factor authentication (generate TOTP secret). |
| **Auth** | `POST` | `/api/v1/auth/mfa/enable` | Account | Confirm and activate 2FA with an initial code. |
| **Auth** | `POST` | `/api/v1/auth/mfa/disable` | Account | Disable 2FA after providing verification code. |
| **Attack Surface** | `GET` | `/api/v1/attack-surface` | Account | Global attack surface summary and high-risk exposed routes. |
| **Attack Surface** | `DELETE` | `/api/v1/attack-surface` | Account | Atomically purge all discovered endpoints and contracts. |
| **Attack Surface** | `GET` | `/api/v1/repositories/{id}/apis` | Account | Discovered endpoints and declared OpenAPI contracts for a target. |
| **Attack Surface** | `DELETE` | `/api/v1/repositories/{id}/apis` | Account | Purge endpoints and contracts for a specific repository. |
| **Attack Surface** | `GET` | `/api/v1/repositories/{id}/apis/export/openapi` | Account | Export synthesized OpenAPI 3.0 specification from source code. |
| **Repositories** | `GET` | `/api/v1/repositories` | Account | List monitored repositories with latest scan status. |
| **Repositories** | `POST` | `/api/v1/repositories` | Admin | Register a new Git repository for continuous scanning. |
| **Repositories** | `PATCH` | `/api/v1/repositories/{id}` | Admin | Update repository configuration, schedule, branches, or SSH keys. |
| **Repositories** | `POST` | `/api/v1/repositories/{id}/scan` | Admin | Enqueue an immediate full security scan. |
| **Repositories** | `DELETE` | `/api/v1/repositories/{id}` | Admin | Delete repository and cascade removal of its scans and findings. |
| **Scans** | `GET` | `/api/v1/scans` | Account | Security scans execution history with target filters. |
| **Scans** | `GET` | `/api/v1/scans/{id}` | Account | Detailed scan result and observed security findings; `examinedTypes` names the built-in steps that produced (`null`: not recorded, never "examined nothing"). |
| **Scans** | `GET` | `/api/v1/scans/{id}/sbom` | Account | Download the raw Software Bill of Materials, as Syft produced it (native JSON). The generated CycloneDX-with-VEX document is `/api/v1/cyclonedx` — see [decision 0016](../../architecture/en/decisions/0016-no-spdx-document.md). |
| **Vulnerabilities** | `GET` | `/api/v1/issues` | Account | Query active and resolved vulnerability issues backlog. |
| **Vulnerabilities** | `GET` | `/api/v1/issues/{id}` | Account | Query vulnerability finding details and remediation history. |
| **Vulnerabilities** | `POST` | `/api/v1/issues/{id}/triage` | Lead/Admin | Submit triage decision (Risk acceptance, False positive, Mitigation). |
| **Compliance** | `GET` | `/api/v1/compliance/summary` | Account | Regulatory compliance posture summary (NIS2, ISO 27001, CRA, SOC2). |
| **Compliance** | `GET` | `/api/v1/compliance/frameworks/{fw}` | Account | Detailed evaluation for a specific compliance standard. |
| **Compliance** | `GET` | `/api/v1/compliance/export.pdf` | Account | Download executive regulatory compliance report in PDF format. |
| **Compliance** | `GET` | `/api/v1/compliance/evidence-bundle.zip` | Account | Export cryptographically sealed audit evidence bundle with SHA-256 proofs. |
| **Scorecards** | `GET` | `/api/v1/scorecards/repositories/{id}` | Account | Repository security posture scorecard and letter grade. |
| **Scorecards** | `GET` | `/api/v1/scorecards/containers/{id}` | Account | Container image security scorecard and grade. |
| **Scorecards** | `GET` | `/api/v1/scorecards/global` | Account | Organization-wide aggregate posture scorecard. |
| **Scorecards** | `GET` | `/api/v1/scorecards/repositories/{id}/badge` | Account | Whether a public badge is published for this repository, and its URL. |
| **Scorecards** | `POST` | `/api/v1/scorecards/repositories/{id}/badge` | Write | Publish the badge. Its grade then becomes readable by anyone holding the URL. |
| **Scorecards** | `DELETE` | `/api/v1/scorecards/repositories/{id}/badge` | Write | Revoke it. Every README carrying the old URL starts answering 404. |
| **Scorecards** | `GET` | `/api/v1/scorecards/badges/{token}.svg` | Public | Dynamic SVG vector badge for embedding into Git README files. |
| **Process evidence** | `GET` | `/api/v1/gate/verdicts` | Governance | The gate's answers, newest first, with a cursor. A refusal is the only proof a control runs: "every target passes" does not distinguish a clean estate from a gate that has never stopped anything. |
| **Process evidence** | `GET` | `/api/v1/exceptions` | Account | Risk acceptances and dismissals, with who decided, on what justification, until when, and when it was last revisited. |
| **Process evidence** | `POST` | `/api/v1/exceptions/{issueId}/reviews` | Lead/Admin | Record that somebody revisited an exception — confirmed, extended or revoked. A confirmation changes nothing, which is the point: it is the only thing that makes "somebody looked" a dated fact. |
| **Process evidence** | `GET` | `/api/v1/remediation/distribution` | Account | Time to fix by the tail rather than the average: share within the deadline, median, 90th percentile, overdue backlog and oldest open item. |
| **Process evidence** | `GET` | `/api/v1/rule-sets/coverage` | Governance | Which languages the installed code-analysis rules reach, and which ecosystems in the estate they do not. What makes a zero finding count readable. |
| **ISMS** | `GET` | `/api/v1/compliance/soa` | Governance | The declaration of applicability per framework, each control reconciled against its measured status (ISO 27001 clause 6.1.3 d). |
| **ISMS** | `GET` | `/api/v1/compliance/soa/{framework}` | Governance | One framework's declaration, line by line, with the divergence between claim and measurement. |
| **ISMS** | `GET` | `/api/v1/compliance/soa/reviews/overdue` | Governance | Declarations whose review date has passed, across every framework. |
| **ISMS** | `PUT` | `/api/v1/compliance/soa/{framework}/{controlId}` | Lead/Admin | Write or revise one line. An exclusion needs a justification; evidence held elsewhere must say where. |
| **ISMS** | `GET` | `/api/v1/compliance/scope` | Governance | The certified scope, how many assets it declares, and how many carry current evidence. |
| **ISMS** | `PUT` | `/api/v1/compliance/scope/repositories/{id}` | Lead/Admin | Mark one repository as inside or outside the certified scope. |
| **ISMS** | `PUT` | `/api/v1/compliance/scope/containers/{id}` | Lead/Admin | Mark one container image as inside or outside the certified scope. |
| **OWASP** | `GET` | `/api/v1/owasp/coverage` | Account | The Top 10 answered by rule, in four states. Seven categories are covered by no scanner here, and this route says so rather than showing them green. |
| **Plugins** | `GET` | `/api/v1/plugins` | Account | Registered plugins, each with the manifest it runs (image pinned by digest, languages, arguments, network exception). |
| **Plugins** | `POST` | `/api/v1/plugins` | Governor | Register a plugin from its manifest. The id is never reused. |
| **Plugins** | `PUT` | `/api/v1/plugins/{id}` | Governor | A new manifest under the same id — a new image version keeps every issue's triage. |
| **Plugins** | `PUT` | `/api/v1/plugins/{id}/enabled` | Governor | Enable or disable a plugin everywhere, keeping its activations. |
| **Plugins** | `GET` | `/api/v1/plugins/{id}/projects` | Governance | The projects a plugin is switched on for. |
| **Plugins** | `GET` | `/api/v1/projects/{id}/plugins` | Governance | The plugins switched on for a project. |
| **Plugins** | `PUT` / `DELETE` | `/api/v1/projects/{id}/plugins/{pluginId}` | Lead/Admin | Switch a plugin on or off for a project. |
| **SARIF import** | `GET` / `POST` | `/api/v1/sarif-sources` | Governance / Governor | The declared internal sources: one integration key, one project or repository, the kinds it may deliver (`sarif`, `coverage`, `test_report`; absent is `sarif`) and, for SARIF, the tools. |
| **SARIF import** | `PUT` / `DELETE` | `/api/v1/sarif-sources/{id}[/enabled]` | Governor | Suspend, resume or remove a declared source. |
| **SARIF import** | `POST` | `/api/v1/repositories/{id}/sarif-imports` | `sarif_import` key | Deposit a declared source's SARIF 2.1.0 report into a repository's backlog; see [Plugins and SARIF imports](../../../docs-site/administration/plugins.md). |
| **SARIF import** | `GET` | `/api/v1/repositories/{id}/sarif-imports` | Account | The repository's latest imports, with their document hashes and what each did. |
| **Report import** | `POST` | `/api/v1/repositories/{id}/coverage-imports` | `report_import` key | Record a declared source's coverage report for a repository, its format declared in `?format=` (`jacoco`, `cobertura`, `lcov`); see [Importing coverage and test reports](../../../docs-site/administration/plugins.md#importing-coverage-and-test-reports). |
| **Report import** | `POST` | `/api/v1/repositories/{id}/test-report-imports` | `report_import` key | Record a declared source's JUnit report — one XML document or a zip of them — for a repository. |
| **Report import** | `GET` | `/api/v1/repositories/{id}/coverage-imports`, `/test-report-imports` | Account | The repository's latest fifty imports of each kind, with their figures and document hashes. |
| **Checklist templates** | `GET` | `/api/v1/checklist-templates` | Governance | Every template of the organisation's checklists, with its versions and where each stands (`draft`, `published`, `retired`); [decision 0032](../../architecture/en/decisions/0032-security-checklists.md). |
| **Checklist templates** | `POST` | `/api/v1/checklist-templates/{slug}/versions` | Lead/Admin | Import the workbook — the `.xlsx` as the raw body, 10 MB — as the template's next version, a draft; a new slug creates the template (`?name=`). Never published in one step. |
| **Checklist templates** | `GET` | `/api/v1/checklist-templates/{slug}/versions/{ordinal}/preview` | Governance | The layout the reader proposes from the workbook's structure, the confirmed one, a sheet's cells, and each item's pairing with the previous version. |
| **Checklist templates** | `PUT` | `/api/v1/checklist-templates/{slug}/versions/{ordinal}/layout` | Lead/Admin | Confirm a draft's layout and map its answer words; the items are read by it. `?revision=` is the one the editor read; a draft changed since is refused (409). |
| **Checklist templates** | `PUT` | `/api/v1/checklist-templates/{slug}/versions/{ordinal}/pairs` | Lead/Admin | On `?revision=`, the one the editor read: pair a reworded item with the previous version's by hand, so that a project's answer follows it, to be confirmed. |
| **Checklist templates** | `POST` | `/api/v1/checklist-templates/{slug}/versions/{ordinal}/derive` | Lead/Admin | A new draft from a published version: same workbook, layout and items. |
| **Checklist templates** | `POST` | `/api/v1/checklist-templates/{slug}/versions/{ordinal}/publish` | Lead/Admin | Publish a draft at the `revision` reviewed. With four-eyes approval on, not by one of the accounts that wrote it (409). |
| **Checklist templates** | `POST` | `/api/v1/checklist-templates/{slug}/versions/{ordinal}/retire` | Lead/Admin | Stop offering a published version for new checklists — with four-eyes on, not by one of its authors — or set a draft aside. |
| **Project checklists** | `GET` | `/api/v1/projects/{id}/checklists` | Account | Every revision of the project's checklist, newest first. For a caller who sees the **whole** project — everything, the project granted as such, or every one of its repositories; anybody else, and a project that does not exist, is answered 404 in the same words ([decision 0032](../../architecture/en/decisions/0032-security-checklists.md) §8). |
| **Project checklists** | `GET` | `/api/v1/projects/{id}/checklists/offered` | Account | The published template versions the project's checklist may be opened on or moved to. |
| **Project checklists** | `POST` | `/api/v1/projects/{id}/checklists` | Write | Open the project's checklist on a published version — `template` (slug), `version` — or move it to another: a new revision, the answers carried, current where the line is unchanged and awaiting confirmation where it changed. `edition` is the newest revision's as read, absent when none was seen. |
| **Project checklists** | `GET` | `/api/v1/projects/{id}/checklists/{revision}` | Account | One revision: its lines with their current answer, proofs and what keeps each from a submission (`problems`), its authors, its `edition`. |
| **Project checklists** | `GET` | `/api/v1/projects/{id}/checklists/{revision}/items/{itemId}/history` | Account | Every answer given on the line, with its author and instant, never edited, and every proof. |
| **Project checklists** | `POST` | `/api/v1/projects/{id}/checklists/{revision}/items/{itemId}/answers` | Write | Answer a line of a draft (`yes`, `no`, `not_applicable`; a comment for the last two) at the `edition` read. A line changed since is refused (409 `checklist-line-changed`). |
| **Project checklists** | `POST` | `/api/v1/projects/{id}/checklists/{revision}/items/{itemId}/confirmation` | Write | Confirm an answer carried onto a line that changed, under the caller's name. |
| **Project checklists** | `POST` | `/api/v1/projects/{id}/checklists/{revision}/items/{itemId}/evidence/links` | Write | Attach a link as proof — `https:` or `http:`, 2,000 characters — with the day the work was done (`performedOn`). |
| **Project checklists** | `POST` | `/api/v1/projects/{id}/checklists/{revision}/items/{itemId}/evidence/files` | Write | Attach a file as proof: the raw body, 25 MB, its `Content-Type` stored and never trusted; `name`, `performedOn` and `edition` as parameters. |
| **Project checklists** | `GET` | `/api/v1/projects/{id}/checklists/{revision}/evidence/{evidenceId}/file` | Account | A proof's file, always as an attachment, `application/octet-stream` and `nosniff`, whatever its declared type. |
| **Project checklists** | `POST` | `/api/v1/projects/{id}/checklists/{revision}/evidence/{evidenceId}/withdrawal` | Write | Withdraw a proof from a draft; the row stays, dated and attributed. |
| **Project checklists** | `POST` | `/api/v1/projects/{id}/checklists/{revision}/submission` | Write | Submit a draft at the `edition` reviewed: every line answered, commented where negative, proven where a yes needs it, none awaiting confirmation (409 `checklist-incomplete` names the lines). |
| **Project checklists** | `POST` | `/api/v1/projects/{id}/checklists/{revision}/return` | Write | Return a submitted revision to its authors with a `reason`: a draft again. |
| **Project checklists** | `POST` | `/api/v1/projects/{id}/checklists/{revision}/sign-off` | Write | Sign a submitted revision off — an administrator, a CISO or a security champion, 403 otherwise. With four-eyes approval on, none of its authors: whoever opened it, answered, carried, confirmed, proved or submitted (409 `checklist-four-eyes`). |
| **Project checklists** | `POST` | `/api/v1/projects/{id}/checklists/{revision}/reopen` | Write | The next revision of a signed-off one, on the same version, every answer carried as current; the signed one is never modified. |
| **Agent** | `GET` | `/api/v1/agent/plugins/{id}/{digest}` | Agent key | The manifest a task named, by id and digest; the agent refuses one that does not hash to the digest. |
| **Crypto** | `GET` | `/api/v1/crypto/public-key.pub` | Public | Instance ECDSA public key for Sigstore / Cosign signature verification. |

---

## 🛠️ Example cURL Commands

### 1. User Login and Token Retrieval
```bash
curl -X POST "https://vectispire.example.com/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "YourStrongPassword"}'
```

### 2. Triggering a Repository Scan
```bash
curl -X POST "https://vectispire.example.com/api/v1/repositories/1/scan" \
  -H "Authorization: Bearer <YOUR_JWT_TOKEN>"
```

### 3. Querying the Attack Surface
```bash
curl -X GET "https://vectispire.example.com/api/v1/attack-surface" \
  -H "Authorization: Bearer <YOUR_JWT_TOKEN>"
```

### 4. Downloading Scan SBOM
```bash
curl -X GET "https://vectispire.example.com/api/v1/scans/42/sbom" \
  -H "Authorization: Bearer <YOUR_JWT_TOKEN>" \
  -o scan-42-sbom.json
```
