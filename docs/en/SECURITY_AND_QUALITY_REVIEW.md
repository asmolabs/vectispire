# Architecture, Quality & Security Audit Review

**Project**: Vectispire  
**Scope**: Backend (Spring Boot 4.1 / JDK 25), Frontend (Angular 21 / Optimus UI), Database Engines, Container Sandboxing, CI/CD Supply Chain, Compliance Engine & Certified Evidence Vault.  
**Author**: Security & Software Architect  
**Date**: August 2026  

---

## 1. Executive Summary & Security Posture

Vectispire demonstrates an **exceptional architectural and security maturity**. The system rigorously enforces **Security by Design**, **Defense-in-Depth**, and **Least Privilege** across all software layers.

Security guarantees do not rely on implicit conventions; they are verified and locked by:
1. **Compilation-level module boundaries** (physical JVM separation without JDBC leakage to remote agents).
2. **Automated architecture tests (ArchUnit)** verifying layer boundaries.
3. **Multi-engine integration test suites (PostgreSQL, MySQL, plus the SQLite fixture)** verifying schema parity and concurrency.
4. **Strict, uncompromising Content Security Policy (CSP)** prohibiting dynamic script execution (`'unsafe-eval'` excluded).
5. **Supply Chain Security** enforced via Sigstore keyless signing, Gradle dependency locking (`gradle.lockfile`), and SBOM audits.
6. **Integrated Regulatory Compliance Engine** (NIS 2, DORA, ISO 27001, PCI-DSS, EU CRA) backed by a certified, cryptographically-sealed evidence vault (`EvidenceVaultService`).
7. **Four-Eyes Triage Governance & Upstream VEX Ingestion** (`SECURITY_CHAMPION`, `VexIngestorService`, `CsafGeneratorService`) guaranteeing risk acceptance auditability and automated vulnerability suppressions.

```mermaid
flowchart TB
    subgraph Hostile["Untrusted Perimeter"]
        SRC["Target Source Code"]
        FEEDS["CVE / KEV Feeds & Supplier VEX Advisories"]
    end

    subgraph Runtime["Container Isolation (Vectispire Common)"]
        DOCKER["Scanners (Syft, Grype, Semgrep, Gitleaks)<br/>cap_drop: ALL | network: none | read-only | digest pin"]
    end

    subgraph Core["Control Plane (Spring Boot 4 / JDK 25)"]
        AUTH["Auth & Sessions (Argon2id, Bearer hash SHA-256)"]
        CIPHER["SecretCipher (AES-GCM + Row AAD Context)"]
        SSRF["OutboundUrlGuard + PinnedHttpSender (DNS Pinning)"]
        AUDIT["AuditChain (HMAC-SHA256 Hash Chain Integrity + Mirror)"]
        COMPLIANCE["ComplianceEngine (NIS 2, DORA, ISO 27001, PCI-DSS, EU CRA)"]
        VAULT["EvidenceVaultService (Signed ZIP / In-Toto / OpenVEX / CSAF 2.0)"]
        VEX["VexIngestorService (Cascade Suppression & 4-Eyes Triage)"]
        DB[(PostgreSQL / MySQL)]
    end

    subgraph Agent["Remote Agent (Isolated JVM)"]
        AGENT_RUN["vectispire-agent (No JDBC/Hibernate, Long Polling API)"]
    end

    subgraph Front["Frontend (Angular 21)"]
        UI["Optimus UI / Signals / In-Memory Session<br/>Strict CSP: script-src 'self' (No unsafe-eval)"]
    end

    SRC --> DOCKER
    DOCKER -->|Normalized Results (Data only)| Core
    FEEDS --> Core
    Core <---> DB
    AGENT_RUN -->|REST API only| Core
    Core -->|JSON + Strict CSP| Front
```

---

## 2. Backend Architecture & Security (Java 25 / Spring Boot 4.1)

### 2.1. Module Isolation at Build Time (Compile-Time Boundary)
- **Design**: `vectispire-agent` depends strictly on `vectispire-common` and has zero dependency on `vectispire-core`.
- **Security Property**: The remote agent daemon holds no JDBC driver, no Hibernate/JPA ORM, and no Spring Data on its classpath.
- **Guarantee**: Even if an agent node is fully compromised, an attacker cannot access `ENCRYPTION_KEY` or connect directly to the central database.
- **Validation**: Enforced by the Gradle build graph and verified by `AgentIsolationTest`.

### 2.2. Cryptography & Secrets Management (`SecretCipher`, `PasswordHasher`)
- **Authenticated AES-256-GCM Encryption**: All deployment private SSH keys and sensitive tokens are encrypted at rest with AES-GCM.
- **Row-Level AAD Binding**: Associated Authenticated Data incorporates the row identity (`ssh_key:<id>:private_key`), preventing ciphertext splicing attacks across database records.
- **Argon2id Password Hashing**: Implemented via BouncyCastle's lightweight API (19 MiB memory, 2 passes). Prevents 72-byte truncation inherent to bcrypt and avoids mutable global JCA providers.
- **Constant-Time Comparison**: `Arrays.constantTimeAreEqual` is used across all authentication and hash checks to eliminate side-channel timing attacks.

### 2.3. SSRF & DNS Rebinding Mitigation (`OutboundUrlGuard`, `PinnedHttpSender`)
- **Strict Outbound Policies**: `OutboundPolicy` distinguishes internal vs public destinations and unconditionally bans link-local and cloud metadata ranges (`169.254.169.254`).
- **DNS Pinning**: The resolver validates all resolved IP addresses upfront and supplies the validated socket address directly to the HTTP client, eliminating DNS rebinding and TOCTOU races.
- **No Automatic Redirects**: Prevents code exfiltration or internal network pivoting via `302 Found` responses.
- **ArchUnit Enforcement**: `ArchitectureTest` asserts that no component can instantiate arbitrary HTTP clients outside the security wrapper.

### 2.4. Scanner Sandboxing & Container Isolation
- **Least Privilege**: Analysis containers execute with `cap_drop: ALL`, `no-new-privileges`, strict memory and PID limits, read-only mounts, and disabled networking (`network: none`) for local scanners.
- **Digest Pinning**: All scanner images (Syft, Grype, Semgrep, Gitleaks) are pinned by exact **SHA-256 digest**.
- **Docker Socket Sanitization**: No scan container has access to `/var/run/docker.sock`. For container image scanning, Vectispire exports image tarballs locally and mounts them read-only.

### 2.5. Regulatory Compliance Engine & Evidence Vault (`ComplianceEngine`, `EvidenceVaultService`)
- **Deterministic Scoring**: Real-time evaluation across 5 frameworks (NIS 2, DORA, ISO 27001, PCI-DSS, Cyber Resilience Act EU CRA) and 7 assessment categories.
- **Strict Non-Dilution**: A single non-compliant critical control invalidates the overall compliance status of the framework.
- **Certified Evidence Bundles**: Generates cryptographically sealed ZIP archives with SHA-256 manifests, In-Toto attestations, OpenVEX statements, OASIS CSAF 2.0 advisories, CycloneDX/SPDX SBOMs, and signed HMAC audit trails.

### 2.6. Four-Eyes Triage Governance & Upstream VEX Ingestion (`IssueTriageService`, `VexIngestorService`)
- **Four-Eyes Principle**: Developer-initiated risk exemptions enter `PENDING_APPROVAL`, blocking CI/CD quality gates until explicitly approved by a `SECURITY_CHAMPION`, `CISO`, or `ADMIN`.
- **Upstream VEX Ingestion**: Automated cascade suppression of vendor-justified vulnerabilities (`POST /api/v1/vex/ingest`) with complete tamper-evident audit history.

---

## 3. Frontend Architecture & Security (Angular 21)

### 3.1. Session Management & In-Memory Token Handling (`SessionStore`)
- **In-Memory Signal Storage**: Authentication bearer tokens reside solely in Angular memory signals and are **never stored in `localStorage` or `sessionStorage`**.
- **XSS Mitigation**: In the event of an XSS flaw, access tokens cannot be extracted from persistent browser storage and vanish upon tab closure.
- **Functional HTTP Interceptor**: `authInterceptor` injects the `Authorization` header and handles automatic invalidation on HTTP 401 responses.

### 3.2. Strict Content Security Policy (CSP)
- **HTTP Security Headers**: Enforced globally across all endpoints and static assets:
  ```http
  default-src 'self';
  script-src 'self';
  style-src 'self' 'unsafe-inline';
  img-src 'self' data:;
  font-src 'self';
  connect-src 'self';
  object-src 'none';
  base-uri 'self';
  form-action 'self';
  frame-ancestors 'none'
  ```
- **No `'unsafe-eval'`**: Full Ahead-of-Time (AOT) compilation without dynamic code evaluation.
- **Zero External CDN Dependencies**: Validated by `scripts/check-assets.mjs` during frontend test suites.

---

## 4. Quality & Verification Matrix

| Area | Rating | Enforcement & Verification Mechanism |
|---|---|---|
| **Layered Hexagonal Architecture** | 🟢 Exemplary | ArchUnit (`ArchitectureTest.java`): Pure domain decoupled from framework dependencies |
| **Multi-Engine Database Parity** | 🟢 Exemplary | Multi-dialect Flyway migrations tested on PostgreSQL, MySQL (SQLite for tests) (`SchemaParityIntegrationTest`) |
| **Supply Chain & Dependency Locking** | 🟢 Exemplary | Gradle dependency locking (`gradle.lockfile`), Git pre-commit hook, Syft SBOM, Grype CVE scanner, Sigstore keyless signing |
| **Fingerprint Determinism** | 🟢 Exemplary | NUL byte (`\0`) delimiter preventing separator collisions (`IssueFingerprintTest`) |
| **Regulatory Compliance & Evidence** | 🟢 Exemplary | Automated NIS 2 / DORA / ISO 27001 / PCI-DSS evaluations + Certified Evidence Vault |
| **Real-Time Workload Supervision** | 🟢 Exemplary | Agent Control Center, live running scan tracking, and pending queue diagnostics |

---

## 5. Summary of Implemented Enhancements

1. **Automated Pre-Commit Dependency Locking**:
   - ✅ *Delivered*: Git `.githooks/pre-commit` hook automatically computes Gradle write-locks and npm lockfiles on every commit.
2. **Real-Time Agent & Scan Queue Center**:
   - ✅ *Delivered*: Live KPI cards, active running scan timers, and queue routability alerts on `/agents`.
3. **Certified Compliance Evidence Export**:
   - ✅ *Delivered*: Executive PDF generation and sealed ZIP evidence bundles for external auditors.
4. **Real-World Exploitability Prioritization (FIRST.org EPSS & CISA KEV)**:
   - ✅ *Delivered*: Risk matrix combining CVSS, EPSS (30-day exploit probability & percentile), code reachability, and CISA KEV status on `/epss`.

