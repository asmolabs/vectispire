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
| **Scans** | `GET` | `/api/v1/scans/{id}/sbom` | Account | Download raw Software Bill of Materials (CycloneDX / SPDX). |
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
| **Scorecards** | `GET` | `/api/v1/scorecards/repositories/{id}/badge.svg` | Public | Dynamic SVG vector badge for embedding into Git README files. |
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
