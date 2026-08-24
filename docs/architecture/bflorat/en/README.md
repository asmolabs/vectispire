# Vectispire Architecture Document (Bertrand Florat Template — bflorat/modele-da)

This directory contains the English version of the **Architecture Document (DA)** for the **Vectispire** platform, written according to the standardized **[`bflorat/modele-da`](https://github.com/bflorat/modele-da)** (Bertrand Florat) template.

This template is structured around **5 self-contained Business & Technical Views**:

---

## 📑 Architecture Document Summary (English)

| N° | Architecture View | Markdown Document | Scope & Description |
|---|---|---|---|
| **01** | **Application View** | [`01_application_view.md`](01_application_view.md) | Application components (Spring Boot / Angular), REST API, data model, `Finding` vs `Issue` reconciliation. |
| **02** | **Security View** | [`02_security_view.md`](02_security_view.md) | Argon2id auth, RBAC, AES-256-GCM encryption, SHA-256 audit sealing, container isolation & DFD STRIDE. |
| **03** | **Dimensioning & Perf.** | [`03_dimensioning_view.md`](03_dimensioning_view.md) | Non-functional requirements (NFRs), database capacity, leader lease locking, JVM/Docker memory caps, retention purge. |
| **04** | **Infrastructure & Deployment** | [`04_infrastructure_view.md`](04_infrastructure_view.md) | Multi-engine databases (PostgreSQL, MySQL, MariaDB, SQLite), Flyway migrations, Docker socket, remote agents. |
| **05** | **Development & Operations** | [`05_development_view.md`](05_development_view.md) | JDK 25 / Node 24 stack, ArchUnit constraints, CI/CD pipeline, Syft/Grype SBOM audit, operation runbooks. |
