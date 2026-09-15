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
| **Scans** | `GET` | `/api/v1/scans/{id}` | Account | Detailed scan result and observed security findings. |
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
