# In-Depth Audit Report: Documentation, Source Code & Security (English)

* **Project:** Vectispire — ASPM & Software Security Control Plane
* **Analysis Date:** August 24, 2026
* **Evaluator:** Antigravity AI Assistant / Pair-Programming Agent
* **Evaluation Scope:** Backend (`vectispire-java`), Frontend (`vectispire-angular`), Documentation (`docs/`), Architecture (`docs/architecture/`), E2E Suites (`vectispire-angular/e2e/`)

---

## 📊 1. Executive Summary & Scores

| Evaluation Domain | Score / 10 | Status | Assessment Summary |
|---|:---:|:---:|---|
| **Documentation & Architecture** | **9.8 / 10** | 🟢 **Exemplary** | Bertrand Florat 5-view model (`bflorat/modele-da`), C4 Structurizr DSL & scripts, STRIDE DFD, 13 ADRs, full FR/EN parity. |
| **Security & Cryptography** | **9.8 / 10** | 🟢 **Defense / Banking Grade** | Upstream Token-Bucket rate limiting (`Bucket4j`), Argon2id, AES-256-GCM, Vault KMS, container isolation (`network: none`), SHA-256 sealed audit. |
| **Code Quality & Architecture** | **9.5 / 10** | 🟢 **Enterprise Ready** | Spring Boot 4.1 / JDK 25, strict ArchUnit rules, Flyway multi-dialect (4 RDBMS), "None is not empty", Playwright E2E. |
| **Regulatory & Standards Compliance** | **9.7 / 10** | 🟢 **Certification Ready** | Built-in engines for EU CRA (Cyber Resilience Act), NIS 2, DORA, OWASP Top 10, VEX/CSAF 2.0, CycloneDX 1.6, four-eyes gate. |

---

## 📚 2. Documentation Evaluation

Vectispire's documentation serves as an industry reference for clarity, structural rigor, and compliance traceability.

### 2.1. Key Highlights
1. **Bertrand Florat Architecture Model (`docs/architecture/bflorat/`)**:
   - Structured into **5 self-contained architectural views**:
     - `01_application_view.md`: Functional mapping, component inventory, triage workflows, and VEX lifecycle.
     - `02_security_view.md`: Security controls matrix, RBAC, encryption at rest/in transit, DoS defenses.
     - `03_dimensioning_view.md`: Scalability metrics, database sizing, worker concurrency, and caching models.
     - `04_infrastructure_view.md`: Deployment topology (Docker, Kubernetes), network boundaries, secret storage.
     - `05_development_view.md`: Engineering practices, lifecycle governance, naming conventions, build cycles.
2. **Documentation-as-Code & C4 Structurizr Diagrams (`docs/architecture/c4/`)**:
   - Modeled directly in [`workspace.dsl`](../../architecture/c4/workspace.dsl) across 3 C4 levels (System Context, Containers, Components).
   - Automated vector and PNG rendering using [`generate-c4-diagrams.sh`](../../scripts/generate-c4-diagrams.sh).
3. **Formal STRIDE Threat Modeling**:
   - Comprehensive threat matrices in `docs/architecture/security/` covering every entity (E1-E4), process (P1-P5), data store (DS1-DS2), and data flow (F1-F16).
4. **Architectural Decision Records (ADRs 0001 through 0013)**:
   - Full context, decision, rejected options, and trade-offs documented (e.g., remote agent isolation without JDBC in ADR 0003, "None is not an empty list" in ADR 0007).
5. **Strict Bilingual Synchronization (FR / EN)**:
   - Complete parity across French and English trees for operational, security, and architectural documentation.

---

## 🛡️ 3. Security & Cryptographic Posture

Vectispire enforces a rigorous **Defense-in-Depth** and least-privilege architecture across all layers.

### 3.1. Implemented Security Controls
- **Anti-DoS & Brute-Force Defense (`LoginRateLimitFilter`)**:
  - Implements an upstream Token-Bucket filter (Bucket4j) evaluated before Spring Security and password hashing.
  - Instantly drops burst floods (HTTP 429 with `Retry-After` headers), safeguarding CPU resources from costly Argon2id hashing exhaustion.
  - Safe client IP resolution via `X-Forwarded-For` with bounded memory eviction on bucket storage.
- **Authentication & Credential Management**:
  - State-of-the-art **Argon2id** hashing for user credentials and API tokens.
  - TOTP MFA support and SCIM 2.0 / OIDC enterprise integration with automatic group-to-role provisioning.
- **Encryption at Rest & Key Management (KMS)**:
  - Integration tokens, Git deployment SSH keys, and secrets encrypted via **AES-256-GCM** with unique nonces.
  - Pluggable key providers (`VaultKmsProvider`, `EncryptionKeyFileDatabase`).
- **Watertight Scanner Container Sandboxing**:
  - Scanner containers run with `cap_drop: ALL` and `no-new-privileges`.
  - Workspace file systems mounted as **read-only (`read-only`)**.
  - **Network completely disabled (`network: none`)** for Gitleaks, Betterleaks, Checkov, and Semgrep, ensuring source code exfiltration is impossible.
  - Docker host socket is never mounted inside scanner containers.
  - Server forces internal `--config` definitions, neutralizing malicious `.gitleaks.toml` injection in target repositories.
- **Remote Agent Isolation (`vectispire-agent`)**:
  - Zero JDBC drivers present on the agent classpath.
  - The agent never receives `ENCRYPTION_KEY` and interacts strictly via outbound HTTP Long-Polling.
- **Sealed, Tamper-Evident Audit Log**:
  - Cryptographic **SHA-256 hash chain** linking each record to the previous one in `t_audit_log`.
  - Integrity verification via `verifyIntegrity()`.
- **Four-Eyes Approval Workflow**:
  - Mandatory dual-authorization for high-impact actions (risk acceptance, security policy revisions).

---

## ⚙️ 4. Code Quality & Architectural Rigor

### 4.1. Backend (`vectispire-java`)
- **Modern Paradigms**: Spring Boot 4.1, JDK 25 utilizing `records`, `sealed classes`, `Pattern Matching`, and immutable structures.
- **Enforced Layer Boundaries via ArchUnit (`ArchitectureTest`)**:
  - Automated compile-time verification of `domain <- scanning <- persistence <- repositories <- services <- api`.
  - Pure domain model without Spring or JPA coupling.
- **Resilience Against Silent Data Loss (ADR 0007)**:
  - Systematic return of `Optional<List<Finding>>`: failed scanners return `Optional.empty()` rather than `[]`, ensuring scanner faults never wipe out historical vulnerability findings.
- **Multi-Engine RDBMS Compatibility**:
  - Flyway migrations continuously verified across 4 real database engines (PostgreSQL, MySQL, MariaDB, SQLite) with strict validation (`ddl-auto: validate`).
- **Multi-Engine Secret Deduplication**:
  - Ingestion pipeline reconciles and deduplicates secret findings from multiple scanners (e.g., Gitleaks + Betterleaks) via `IssueFingerprint`.

### 4.2. Frontend (`vectispire-angular`)
- **Modular Angular 21 Architecture**:
  - Standalone components, reactive state handling (Signals / RxJS), Optimus UI design system.
- **Automated Playwright E2E Test Suite (`vectispire-angular/e2e/`)**:
  - Comprehensive end-to-end testing covering authentication (`auth.spec.ts`), four-eyes approval (`four-eyes-approval.spec.ts`), settings audit (`settings-audit.spec.ts`), and VEX triage (`vex-triage.spec.ts`).

---

## 📋 5. Regulatory & Standards Governance

Vectispire provides an automated compliance engine (`ComplianceService`):
- **European Regulations**:
  - **EU CRA (Cyber Resilience Act)**: Software supply-chain tracking, vulnerability lifecycle management, automated VEX generation.
  - **NIS 2 & DORA**: Third-party risk tracking, digital operational resilience, immutable audit logging.
- **ASPM & SBOM Standards**:
  - Ingestion and export support for **CycloneDX 1.6**, **SPDX 2.3**, **CSAF 2.0**, and **OpenVEX**.
  - **EPSS** (Exploit Prediction Scoring System) prioritization and reachability analysis.

---

## 🎯 6. Conclusion & Recommendations

Vectispire demonstrates **outstanding architectural maturity, security hardening, and code craftsmanship**. The combination of upstream rate limiting, container sandboxing, Playwright E2E validation, and built-in regulatory engines delivers an enterprise-grade ASPM control plane.

### Recommended Next Steps:
1. **Headless Playwright in CI**: Integrate headless Playwright test runs into the primary GitHub Actions workflow.
2. **OIDC Dynamic Client Registration**: Extend identity providers for streamlined multi-tenant provisioning.
