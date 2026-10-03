workspace "Vectispire Architecture" "C4 Model Architecture diagrams for Vectispire Control Plane & Security Scanner Platform" {

    model {
        analyst = person "Security Analyst / Admin" "Monitors posture, triages vulnerabilities, configures compliance policies and team access."
        developer = person "Software Developer" "Views repository findings, inspects SCA/Secrets/SAST issues, and remediates vulnerabilities."
        ciPipeline = person "CI/CD Pipeline (Jenkins / GitHub Actions / GitLab CI)" "Queries the Quality Gate API (POST /api/v1/gate) to enforce security compliance before deployment."

        vectispire = softwareSystem "Vectispire Platform" "Application Security Posture Management (ASPM) & Compliance Control Plane." {
            webApp = container "Angular Frontend UI" "Provides security overview, repository posture, compliance matrices, issue triage, and administration interface." "Angular 22 / Optimus UI / TypeScript" "Web Browser"
            apiApp = container "Spring Boot Control Plane" "Manages scan scheduling, issue lifecycle, VEX triage, policy gate evaluations, and audit logging." "Spring Boot 4.1 / JDK 25" "Java Process" {
                # BEGIN modules — generated from the Spring Modulith model by ModularityTest; do not edit by hand.
                m_access = component "access" "Accounts, teams, visibility and the row guard, sessions, sign-in flows, second factors, OIDC, SCIM, API keys, bootstrap — and, in web.security, the vocabulary every module's routes use." "Spring Modulith module"
                m_agents = component "agents" "Agent administration, the agent row, and the agent protocol." "Spring Modulith module"
                m_ai = component "ai" "The model review and the advisor." "Spring Modulith module"
                m_audit = component "audit" "The audit log — writing it, its mirror, reading it back and judging its chain — and RequestActor." "Spring Modulith module" "Shared"
                m_checklists = component "checklists" "Security checklists — the organisation's templates, their versions and their items, imported from its own workbooks, and each project's checklist answered against them by people — and on its measured lines by Vectispire, from the scans and imports it is told of (RepositoryScanned, RepositoryReported, ports of scanning and plugins it implements) — with its proofs, its submission and its sign-off, and the measurements a line's rule takes of the project (decision 0032)." "Spring Modulith module"
                m_compliance = component "compliance" "Frameworks, statement of applicability, evidence, OWASP." "Spring Modulith module"
                m_config = component "config" "The application's configuration, outside every domain module." "Spring Modulith module"
                m_crypto = component "crypto" "Encryption at rest, the key's sources, Vault, the document signing key." "Spring Modulith module" "Shared"
                m_exports = component "exports" "VEX, CSAF, CycloneDX, attestation, the export documents." "Spring Modulith module"
                m_gate = component "gate" "The gate, its register, its stored policies and ActiveGatePolicies." "Spring Modulith module"
                m_inventory = component "inventory" "What targets are made of: components, SBOM diff, blast radius, licences, API contracts." "Spring Modulith module"
                m_issues = component "issues" "Sync, triage, decisions, SLA, history, the exceptions register, VEX import." "Spring Modulith module"
                m_maintenance = component "maintenance" "The periodic jobs' port: MaintenanceTask, and the tick that runs a cadence's tasks in their order." "Spring Modulith module" "Shared"
                m_notifications = component "notifications" "What a scan's delta says, and the channels that say it." "Spring Modulith module"
                m_outbound = component "outbound" "The one door out: PinnedHttpSender, OutboundJson, OutboundPost, OutboundDownload, the guard's configuration." "Spring Modulith module" "Shared"
                m_outbox = component "outbox" "The relay: OutboxService, and the two contracts it dispatches to, OutboxHandler and NotificationChannel, with GoneDestinationException." "Spring Modulith module" "Shared"
                m_platform = component "platform" "The shell: the settings screen, which composes the credentials and checks of ai, tickets, notifications and access; the audit-log and crypto routes the foundation may not keep (they need access's markers, and access uses the foundation); the exception handler, the SPA forwarding and the OpenAPI configuration." "Spring Modulith module"
                m_plugins = component "plugins" "Plugins — third-party analysers run as containers, emitting SARIF — their activation per project, and SARIF imported from declared internal sources (decision 0017, amended)." "Spring Modulith module"
                m_posture = component "posture" "Figures of risk: dashboard, scorecards, debt, quality, remediation, attack paths, the weekly digest." "Spring Modulith module"
                m_reporting = component "reporting" "The PDF pagination four domains' reports share (ReportCursor): how a page is laid out, not what it says." "Spring Modulith module" "Shared"
                m_reportplugins = component "reportplugins" "Report plugins (decision 0035) — so far its first lot: a project's export, the vectispire-project-export document a plugin will receive, built for a caller who sees the whole project, signed, and served on its own so an organisation can write its plugin against its own data." "Spring Modulith module"
                m_rules = component "rules" "Rule sets, the upstream catalogue, rule coverage." "Spring Modulith module"
                m_scanning = component "scanning" "The queue, dispatch, ingest, the built-in worker, scheduling, scan reads, retention." "Spring Modulith module"
                m_settings = component "settings" "The deployment's configuration: SettingsService, the first-install defaults, and what Vectispire says about itself (ProductVersion, ExportProperties, BrandingProperties)." "Spring Modulith module" "Shared"
                m_siem = component "siem" "The security event stream and its delivery through the outbox (decision 0025)." "Spring Modulith module"
                m_targets = component "targets" "Repositories, containers, solutions and projects, clone credentials, deletion — and the TargetDeleted event and TargetPurge phases every owner of a target's rows listens to." "Spring Modulith module"
                m_threatintel = component "threatintel" "KEV/EPSS feeds, enrichment, end of life." "Spring Modulith module"
                m_tickets = component "tickets" "The tracker client, the ticket links, the tracker's webhook and the ticket sweep." "Spring Modulith module"
                # END modules
            }
            db = container "Database Engine" "Stores targets, scans, findings, issues, VEX triage history, audit logs, and system settings." "PostgreSQL / MySQL (Flyway Migrations)" "Database"
            dockerDaemon = container "Docker Daemon & Scanners" "Runs isolated ephemeral containers for SCA, Secrets, IaC, and SAST analysis." "Docker Engine / ContainerRunner" "Container Engine"
            agent = container "Vectispire Remote Agent" "Executes scans on remote worker nodes using HTTP long-polling." "Spring Boot / Java 25" "Standalone Agent"
        }

        threatFeeds = softwareSystem "External Threat Feeds" "Public threat intelligence sources (CISA KEV, EPSS, endoflife.date)."
        webhooks = softwareSystem "Notification Systems" "Microsoft Teams, Email gateways, and signed HTTP webhooks."

        # Relationships (Level 1 & 2)
        analyst -> webApp "Uses for triage, compliance inspection, and system administration" "HTTPS"
        developer -> webApp "Views findings and remediates security issues" "HTTPS"
        ciPipeline -> apiApp "Evaluates Quality Gate verdicts (POST /api/v1/gate)" "HTTP/HTTPS (API Key)"

        webApp -> apiApp "Sends API requests & fetches posture state" "JSON / REST API over HTTP"
        apiApp -> db "Reads & writes domain entities, scans, issues, and audit logs" "JDBC / JPA Hibernate"
        apiApp -> dockerDaemon "Launches ephemeral scanner containers (Syft, Grype, Gitleaks, Checkov, Semgrep)" "Docker Socket / ContainerRunner"
        apiApp -> threatFeeds "Enriches vulnerabilities with KEV status, EPSS scores, and EOL metadata" "HTTPS"
        apiApp -> webhooks "Dispatches real-time alerts & outbox messages" "HTTP Webhooks / SMTP"

        agent -> apiApp "Fetches scan tasks via HTTP Long-Polling (GET /api/v1/agent/jobs)" "HTTP/REST API (Agent Key)"
        agent -> dockerDaemon "Executes analysis containers on remote worker machine" "Docker Socket"

        # Level 3: the modules' dependencies, as Spring Modulith reads them from the code. An edge into a
        # shared foundation module (settings, outbound, crypto, audit, outbox, reporting, maintenance) is
        # left out: every module may use them, and drawing those edges would bury the ones that are choices.
        # BEGIN dependencies — generated from the Spring Modulith model by ModularityTest; do not edit by hand.
        m_agents -> m_access "uses"
        m_agents -> m_rules "uses"
        m_agents -> m_scanning "uses"
        m_agents -> m_targets "uses"
        m_ai -> m_access "uses"
        m_ai -> m_issues "uses"
        m_ai -> m_threatintel "uses"
        m_checklists -> m_access "uses"
        m_checklists -> m_inventory "uses"
        m_checklists -> m_issues "uses"
        m_checklists -> m_plugins "uses"
        m_checklists -> m_scanning "uses"
        m_checklists -> m_targets "uses"
        m_compliance -> m_access "uses"
        m_compliance -> m_ai "uses"
        m_compliance -> m_exports "uses"
        m_compliance -> m_gate "uses"
        m_compliance -> m_inventory "uses"
        m_compliance -> m_issues "uses"
        m_compliance -> m_posture "uses"
        m_compliance -> m_rules "uses"
        m_compliance -> m_scanning "uses"
        m_compliance -> m_targets "uses"
        m_exports -> m_access "uses"
        m_exports -> m_gate "uses"
        m_exports -> m_inventory "uses"
        m_exports -> m_issues "uses"
        m_exports -> m_scanning "uses"
        m_exports -> m_targets "uses"
        m_gate -> m_access "uses"
        m_gate -> m_issues "uses"
        m_gate -> m_rules "uses"
        m_gate -> m_scanning "uses"
        m_gate -> m_targets "uses"
        m_inventory -> m_access "uses"
        m_inventory -> m_scanning "uses"
        m_inventory -> m_targets "uses"
        m_issues -> m_access "uses"
        m_issues -> m_scanning "uses"
        m_issues -> m_targets "uses"
        m_notifications -> m_access "uses"
        m_notifications -> m_issues "uses"
        m_notifications -> m_targets "uses"
        m_platform -> m_access "uses"
        m_platform -> m_ai "uses"
        m_platform -> m_checklists "uses"
        m_platform -> m_exports "uses"
        m_platform -> m_notifications "uses"
        m_platform -> m_plugins "uses"
        m_platform -> m_scanning "uses"
        m_platform -> m_targets "uses"
        m_platform -> m_tickets "uses"
        m_plugins -> m_access "uses"
        m_plugins -> m_issues "uses"
        m_plugins -> m_scanning "uses"
        m_plugins -> m_targets "uses"
        m_posture -> m_access "uses"
        m_posture -> m_gate "uses"
        m_posture -> m_inventory "uses"
        m_posture -> m_issues "uses"
        m_posture -> m_notifications "uses"
        m_posture -> m_scanning "uses"
        m_posture -> m_targets "uses"
        m_reportplugins -> m_access "uses"
        m_reportplugins -> m_checklists "uses"
        m_reportplugins -> m_compliance "uses"
        m_reportplugins -> m_gate "uses"
        m_reportplugins -> m_inventory "uses"
        m_reportplugins -> m_issues "uses"
        m_reportplugins -> m_scanning "uses"
        m_reportplugins -> m_targets "uses"
        m_rules -> m_access "uses"
        m_rules -> m_inventory "uses"
        m_rules -> m_issues "uses"
        m_rules -> m_scanning "uses"
        m_scanning -> m_access "uses"
        m_scanning -> m_targets "uses"
        m_siem -> m_access "uses"
        m_targets -> m_access "uses"
        m_threatintel -> m_access "uses"
        m_threatintel -> m_issues "uses"
        m_threatintel -> m_scanning "uses"
        m_threatintel -> m_targets "uses"
        m_tickets -> m_access "uses"
        m_tickets -> m_gate "uses"
        m_tickets -> m_issues "uses"
        m_tickets -> m_targets "uses"
        # END dependencies

        # What leaves the control plane, by the module that sends it — written by hand, outside the generated part.
        m_scanning -> dockerDaemon "Runs the scanners' containers (Syft, Grype, Gitleaks, Checkov, Semgrep)" "Docker Socket"
        m_threatintel -> threatFeeds "Reads the CISA KEV catalogue, the EPSS file and endoflife.date" "HTTPS"
        m_outbox -> webhooks "Delivers queued notifications and SIEM events" "HTTPS / SMTP / syslog"
    }

    views {
        systemContext vectispire "SystemContext" {
            include *
            autoLayout tb
            description "Level 1: System Context Diagram for Vectispire ASPM Platform"
        }

        container vectispire "Containers" {
            include *
            autoLayout tb
            description "Level 2: Container Diagram showing frontend, backend, database, Docker daemon, and agents"
        }

        component apiApp "Components" {
            include *
            autoLayout tb
            description "Level 3: the control plane modules, generated from the Spring Modulith model, shared foundation modules in a lighter tone"
        }

        styles {
            element "Person" {
                background #08427b
                color #ffffff
                shape Person
            }
            element "Software System" {
                background #1168bd
                color #ffffff
            }
            element "Container" {
                background #438dd5
                color #ffffff
            }
            element "Component" {
                background #85bbf0
                color #000000
            }
            element "Shared" {
                background #dde9f7
                color #000000
            }
            element "Database" {
                shape Cylinder
            }
        }
    }
}
