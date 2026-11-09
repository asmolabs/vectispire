# Architecture, quality and security self-review (August 2026)

**Project**: Vectispire  
**Scope**: Backend (Spring Boot 4.1 / JDK 25), Frontend (Angular 22 / Optimus UI), Database Engines, Container Sandboxing, CI/CD Supply Chain, Compliance Engine & Evidence Bundle.  
**Written by**: the project's maintainers, about their own code  
**Date**: August 2026  

> **A self-review, not an audit.** Nobody outside the project checked what follows, and the code
> has changed since it was written. It is kept as a record of how the design was described at the
> time; where it and the code disagree, the code is right. Moved here from `docs/en/` in October 2026.

---

## 1. Summary

The review looked at how defence in depth and least privilege are applied across the layers. Each
property below rests on a mechanism that runs, rather than on a convention:
1. **Compilation-level module boundaries** (physical JVM separation without JDBC leakage to remote agents).
2. **Automated architecture tests (ArchUnit)** verifying layer boundaries.
3. **Multi-engine integration test suites (PostgreSQL, MySQL)** verifying schema parity and concurrency.
4. **A Content Security Policy (CSP) strict on scripts** — `script-src 'self'`, with neither `'unsafe-inline'` nor `'unsafe-eval'` — and **relaxed on styles**: `style-src` keeps `'unsafe-inline'`, because the interface still writes style attributes. An injected style can redress a page; it cannot execute.
5. **Supply Chain Security** enforced via Sigstore keyless signing, Gradle dependency locking (`gradle.lockfile`), and SBOM audits.
6. **A compliance evaluation** — 24 technical controls named after six frameworks (NIS 2, DORA, ISO 27001, PCI-DSS, EU CRA, SOC 2) — exported as an evidence bundle whose manifest is signed (`EvidenceVaultService`).
7. **Four-eyes triage and upstream VEX import** (`SECURITY_CHAMPION`, `VexIngestorService`, `CsafGeneratorService`): an exemption raised by a developer waits for a second person, and a VEX import is a triage decision recorded under the uploader's name.

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
        AUDIT["AuditChain (SHA-256 Hash Chain Integrity + Mirror)"]
        COMPLIANCE["ComplianceEngine (NIS 2, DORA, ISO 27001, PCI-DSS, EU CRA, SOC 2)"]
        VAULT["EvidenceVaultService (Signed ZIP / In-Toto / OpenVEX / CSAF 2.0)"]
        VEX["VexIngestorService (Cascade Suppression & 4-Eyes Triage)"]
        DB[(PostgreSQL / MySQL)]
    end

    subgraph Agent["Remote Agent (Isolated JVM)"]
        AGENT_RUN["vectispire-agent (No JDBC/Hibernate, Long Polling API)"]
    end

    subgraph Front["Frontend (Angular 22)"]
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
- **Property**: The remote agent daemon holds no JDBC driver, no Hibernate/JPA ORM, and no Spring Data on its classpath.
- **Consequence**: a compromised agent holds no database connection and has no use for `ENCRYPTION_KEY`; it reaches the control plane only through its API.
- **Validation**: Enforced by the Gradle build graph and verified by `AgentIsolationTest`.

### 2.2. Cryptography & Secrets Management (`SecretCipher`, `PasswordHasher`)
- **Authenticated AES-256-GCM Encryption**: All deployment private SSH keys and sensitive tokens are encrypted at rest with AES-GCM.
- **Row-Level AAD Binding**: Associated Authenticated Data incorporates the row identity (`ssh_key:<id>:private_key`), preventing ciphertext splicing attacks across database records.
- **Argon2id Password Hashing**: Implemented via BouncyCastle's lightweight API (19 MiB memory, 2 passes). Prevents 72-byte truncation inherent to bcrypt and avoids mutable global JCA providers.
- **Constant-Time Comparison**: `Arrays.constantTimeAreEqual` is used for the authentication and hash comparisons, so their duration does not reveal where two values differ.

### 2.3. SSRF & DNS Rebinding Mitigation (`OutboundUrlGuard`, `PinnedHttpSender`)
- **Strict Outbound Policies**: `OutboundPolicy` distinguishes internal vs public destinations and unconditionally bans link-local and cloud metadata ranges (`169.254.169.254`).
- **DNS Pinning**: The resolver validates all resolved IP addresses upfront and supplies the validated socket address directly to the HTTP client, so the address checked is the address connected to (no DNS-rebinding window).
- **No Automatic Redirects**: Prevents code exfiltration or internal network pivoting via `302 Found` responses.
- **ArchUnit Enforcement**: `ArchitectureTest` asserts that no component can instantiate arbitrary HTTP clients outside the security wrapper.

### 2.4. Scanner Sandboxing & Container Isolation
- **Least Privilege**: Analysis containers execute with `cap_drop: ALL`, `no-new-privileges`, strict memory and PID limits, read-only mounts, and disabled networking (`network: none`) for local scanners.
- **Digest Pinning**: All scanner images (Syft, Grype, Semgrep, Gitleaks) are pinned by exact **SHA-256 digest**.
- **Docker Socket Sanitization**: No scan container has access to `/var/run/docker.sock`. For container image scanning, Vectispire exports image tarballs locally and mounts them read-only.

### 2.5. Regulatory Compliance Engine & Evidence Vault (`ComplianceEngine`, `EvidenceVaultService`)
- **Scoring**: 24 technical controls, four per framework (NIS 2, DORA, ISO 27001, PCI-DSS, Cyber Resilience Act EU CRA, SOC 2), scored by 7 assessment categories; the same input yields the same verdict. It prepares an assessment, it is not one.
- **No dilution**: a single non-compliant control makes the framework non-compliant, whatever the average.
- **Evidence bundles**: ZIP archives with a signed manifest, In-Toto attestations, OpenVEX statements, OASIS CSAF 2.0 advisories, CycloneDX 1.5 SBOMs with embedded VEX, and the audit trail as a SHA-256 hash chain (tamper-evident, unkeyed — the bundle's manifest is what is signed).

### 2.6. Four-Eyes Triage Governance & Upstream VEX Ingestion (`IssueTriageService`, `VexIngestorService`)
- **Four-Eyes Principle**: Developer-initiated risk exemptions enter `PENDING_APPROVAL`, blocking CI/CD quality gates until explicitly approved by a `SECURITY_CHAMPION`, `CISO`, or `ADMIN`.
- **Upstream VEX import**: `POST /api/v1/vex/ingest` applies a vendor's OpenVEX or CycloneDX `not_affected` statements to the issues the uploader can see, as the uploader's triage decision, under four-eyes, with one audit entry per import.

---

## 3. Frontend Architecture & Security (Angular 22)

### 3.1. Session Management & In-Memory Token Handling (`SessionStore`)
- **In-Memory Signal Storage**: Authentication bearer tokens reside solely in Angular memory signals and are **never stored in `localStorage` or `sessionStorage`**.
- **XSS Mitigation**: an XSS flaw finds no token in persistent browser storage, and the token goes with the tab. (Script running in the page can still use the session while it is open.)
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

| Area | Enforcement & Verification Mechanism |
|---|---|
| **Layered Hexagonal Architecture** | ArchUnit (`ArchitectureTest.java`): Pure domain decoupled from framework dependencies |
| **Multi-Engine Database Parity** | Multi-dialect Flyway migrations tested on PostgreSQL and MySQL (`SchemaParityIntegrationTest`) |
| **Supply Chain & Dependency Locking** | Gradle dependency locking (`gradle.lockfile`), Git pre-commit hook, Syft SBOM, Grype CVE scanner, Sigstore keyless signing |
| **Fingerprint Determinism** | NUL byte (`\0`) delimiter preventing separator collisions (`IssueFingerprintTest`) |
| **Regulatory Compliance & Evidence** | 24 technical controls across NIS 2 / DORA / ISO 27001 / PCI-DSS / EU CRA / SOC 2, and a signed evidence bundle |
| **Real-Time Workload Supervision** | Agent Control Center, live running scan tracking, and pending queue diagnostics |

---

## 5. Summary of Implemented Enhancements

1. **Automated Pre-Commit Dependency Locking**:
   - ✅ *Delivered*: Git `.githooks/pre-commit` hook automatically computes Gradle write-locks and npm lockfiles on every commit.
2. **Real-Time Agent & Scan Queue Center**:
   - ✅ *Delivered*: Live KPI cards, active running scan timers, and queue routability alerts on `/agents`.
3. **Compliance Evidence Export**:
   - ✅ *Delivered*: PDF report and ZIP evidence bundle with a signed manifest.
4. **Exploitability Prioritization (FIRST.org EPSS & CISA KEV)**:
   - ✅ *Delivered*: Risk matrix combining CVSS, EPSS (30-day exploit probability & percentile), and CISA KEV status on `/epss`. It has no reachability term: there is no call-graph analysis, and the multiplier and top-tier clause that read the always-`UNKNOWN` column were removed, with the screen's reachability card and column.

