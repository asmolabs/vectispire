# Documentation Technique — Zanshin

Ce document décrit l'architecture interne de Zanshin, son modèle de données, et le flux d'exécution du pipeline d'analyse de sécurité.

---

## 1. Architecture en Couches

Le système est découpé en deux composants distincts :
- Le **Control Plane** (Spring Boot 4.1 / JDK 25) dans `zanshin-java/`.
- L'**Interface Web** (Angular 21 / Optimus UI) dans `zanshin-angular/`.

```mermaid
flowchart TB
    subgraph front["Frontend Angular — zanshin-angular/src/app/"]
        Pages["Pages<br/>dashboard, security, quality, repositories, issues,<br/>containers, scans, ssh-keys, api-keys, agents,<br/>settings, users, audit-log, teams, compliance,<br/>gate-policies, rule-sets, history, inventory, owasp"]
    end

    subgraph api["api/ — Contrôleurs, DTOs, Guards"]
        Routes["Contrôleurs REST<br/>auth, scans, issues, gate, exports, quality,<br/>repositories, containers, dashboard, settings,<br/>users, ssh-keys, api-keys, audit-log, compliance,<br/>csaf, vex, agents, agents-admin, teams, rule-sets, owasp"]
    end

    subgraph services["services/ — Métier, Orchestration, Transactions"]
        Scan["ScanDispatcherService / ScanWorkerService<br/>ScanIngestorService"]
        Issue["IssueSyncService / IssueTriageService / VexIngestorService"]
        Comp["ComplianceService · EvidenceVaultService · CsafGeneratorService"]
        Enrich["EnrichmentService · EolService · LicenseService"]
        Ai["AiReviewService"]
        Notify["NotificationService · OutboxService"]
        Ticket["TicketService · TicketSweepService"]
        Ops["SchedulerService · LeaderElectionService<br/>RetentionService · MaintenanceService"]
        Auth["AuthService · PasswordService · SessionCleanupService<br/>ApiKeyAuthService · AuditLogService · SettingsService<br/>EncryptionService · BootstrapService · VisibilityService"]
    end

    subgraph repos["repositories/ — Accès aux Données (SQL)"]
        R["ScanRepository · IssueRepository · TargetRepository<br/>AuditLogRepository · SessionRepository · TeamRepository"]
    end

    subgraph persistence["persistence/ — Entités JPA, Migrations"]
        Ent["26 entités JPA · Migrations Flyway"]
    end

    subgraph domain["domain/ — Domaine Pur, Sans Dépendance Framework"]
        D["fingerprint · gate · audit chain · exports · csaf · triage<br/>compliance · url-guard · crypto · retention · scheduling · …"]
    end

    subgraph scanning["scanning/ — Exécution Conteneurs (Docker)"]
        S["ScanRunner · ContainerRunner<br/>syft · grype · gitleaks · checkov · semgrep"]
    end

    Pages -->|"/api sur HTTP"| Routes
    Routes --> services
    services --> repos
    repos --> persistence
    services --> scanning
    services --> domain
    repos --> domain
    scanning --> domain
```

### Règles d'Architecture Clés
1. **Domaine Pur** : La couche `common.domain` ne dépend d'aucun framework (pas de Spring, pas d'Hibernate, pas de JDBC). Cela garantit l'isolation, la testabilité exhaustive et la réutilisation sur l'agent distant.
2. **Isolation de l'Agent** : `zanshin-agent` ne dépend pas de `zanshin-core`. Aucun pilote JDBC ni accès base de données n'est présent sur le classpath de l'agent.
3. **Contrôle ArchUnit** : `ArchitectureTest` vérifie automatiquement à chaque build que les couches supérieures n'importent jamais de couches inférieures.

---

## 2. Modèle de Données & Schéma de Base de Données

Le schéma est géré par **Flyway** (`src/main/resources/db/migration/{vendor}/`) sur 4 moteurs de base de données :
- **PostgreSQL** : `BIGINT GENERATED ALWAYS AS IDENTITY`, `TIMESTAMPTZ`, `char(36)` UUID.
- **SQLite** : `INTEGER PRIMARY KEY AUTOINCREMENT`, `NUMERIC` (epoch ms), clés étrangères inline.
- **MySQL** : `BIGINT AUTO_INCREMENT`, `DATETIME(6)`, `BIT(1)`.
- **MariaDB** : `BIGINT AUTO_INCREMENT`, `DATETIME(6)`, `BOOLEAN`.

### Les 26 Tables de l'Application :
- **Cibles & Scans** : `t_repository`, `t_container`, `t_ssh_key`, `t_scan`, `t_ai_review_result`, `t_component`.
- **Vulnérabilités & Triage** : `t_issue`, `t_finding`, `t_issue_triage_event`, `t_gate_policy`, `t_semgrep_rule_set`.
- **Utilisateurs, Équipes & Accès** : `t_user`, `t_session`, `t_user_target`, `t_team`, `t_team_member`, `t_team_target`, `t_team_webhook`, `t_api_key`, `t_login_attempt`.
- **Système & Agents** : `t_agent`, `t_leader_lease`, `t_outbox_message`, `t_processed_message`, `t_audit_log`, `t_setting`.

---

## 3. Pipeline d'Analyse & Sécurité des Scanners

Chaque scanner s'exécute dans un conteneur éphémère Docker sous isolation stricte :
1. **Syft** : Génération du SBOM (Software Bill of Materials).
2. **Grype** : Analyse des dépendances et CVEs associées.
3. **Gitleaks** : Détection des secrets et identifiants exposés.
4. **Checkov / Semgrep** : Analyse statique (SAST) et Infrastructure-as-Code (IaC).

**Sécurité Conteneurs** :
- `cap_drop: ALL`, `no-new-privileges`.
- Montages en lecture seule (`read-only`).
- Réseau coupé (`network: none`) pour les scanners d'analyse locale.
- Images épinglées par digest SHA-256 immuable.

---

## 4. Conformité Réglementaire & Preuves d'Audit

Le moteur de conformité évalue en continu 5 référentiels majeurs :
- **NIS 2 Directive**, **DORA**, **ISO/IEC 27001:2022**, **PCI-DSS v4.0**, et **Cyber Resilience Act (EU CRA)**.
- **Export OASIS CSAF 2.0** (`/api/v1/csaf/aggregate.json`), **CycloneDX 1.5 BOM-Linked VEX** (`/api/v1/cyclonedx/aggregate.json`), et **OpenVEX v0.2.0** (`/api/v1/vex/aggregate.json`).
- **Ingestion VEX Amont Multi-Formats** (`POST /api/v1/vex/ingest`) pour l'extinction automatisée des vulnérabilités certifiées par les mainteneurs (OpenVEX / CSAF / CycloneDX).
- **Coffre de Preuves Scellé** (`/api/v1/compliance/evidence-bundle.zip`) incluant attestations in-toto, SBOMs, CSAF, OpenVEX, CycloneDX VEX, et piste d'audit cryptographique.

---

## 5. Gouvernance 4-Yeux & Rôles

- **Rôle `SECURITY_CHAMPION`** : Délégué sécurité d'équipe habilité à statuer sur les exemptions techniques.
- **Statut `PENDING_APPROVAL`** : Blocage préventif des Gates CI/CD sur toute dérogation initiée par un développeur jusqu'à validation par un pair qualifié.

---

## 6. Graphe de Dépendances & Rayon d'Impact (Blast Radius)

- **Moteur d'Impact (`BlastRadiusService`)** : Corrèle en mémoire l'arbre relationnel Cible (Dépôt Git / Conteneur) $\rightarrow$ Dépendance (Directe / Transitive) $\rightarrow$ CVE.
- **Calcul du Score de Rayon d'Impact** : Score 0-100 pondéré par la dispersion dans le parc, le caractère direct de l'inclusion, et le score CVSS maximal.
- **Endpoints API** :
  - `GET /api/v1/blast-radius/explore?q={package|CVE}` : Arbre relationnel et inventaire des cibles touchées.
  - `GET /api/v1/blast-radius/top-impact?limit=10` : Palmarès des composants à plus fort risque organisationnel.

---

## 7. Centre de Notifications Multi-Canaux & Outbox Transactionnelle

- **Canaux Supportés** :
  - **Slack** (`SlackNotificationChannel`, `SlackBlockKit`) : Alertes interactives formatées en blocs Block Kit.
  - **Microsoft Teams** (`TeamsNotificationChannel`, `TeamsCard`) : Adaptive Cards version 1.4 acheminées via Power Automate Workflow.
  - **Discord** (`DiscordNotificationChannel`, `DiscordEmbed`) : Rich Embeds avec couleur contextuelle selon sévérité.
  - **Email** (`MailNotificationChannel`) : Diffusion MIME/HTML sur listes de distribution.
  - **Webhook Générique / SIEM** (`NotificationService`) : JSON POST universel avec signature cryptographique HMAC-SHA256 (`X-Zanshin-Signature`).
- **Garanties Transactionnelles** :
  - Les messages sont écrits dans `t_outbox_message` dans la même transaction que le résultat de scan, avec politique de retry et backoff exponentiel isolé par canal.
- **Endpoints API** :
  - `GET /api/v1/notifications/channels` : Liste des canaux configurés et événements abonnés.
  - `POST /api/v1/notifications/test/{channelType}` : Déclenchement d'un test d'envoi immédiat avec diagnostic.


