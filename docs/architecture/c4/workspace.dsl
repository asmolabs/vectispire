workspace "Vectispire Architecture" "C4 Model Architecture diagrams for Vectispire Control Plane & Security Scanner Platform" {

    model {
        analyst = person "Security Analyst / Admin" "Monitors posture, triages vulnerabilities, configures compliance policies and team access."
        developer = person "Software Developer" "Views repository findings, inspects SCA/Secrets/SAST issues, and remediates vulnerabilities."
        ciPipeline = person "CI/CD Pipeline (Jenkins / GitHub Actions / GitLab CI)" "Queries the Quality Gate API (POST /api/v1/gate) to enforce security compliance before deployment."

        vectispire = softwareSystem "Vectispire Platform" "Application Security Posture Management (ASPM) & Compliance Control Plane." {
            webApp = container "Angular Frontend UI" "Provides security overview, repository posture, compliance matrices, issue triage, and administration interface." "Angular 21 / Optimus UI / TypeScript" "Web Browser"
            apiApp = container "Spring Boot Control Plane" "Manages scan scheduling, issue lifecycle, VEX triage, policy gate evaluations, and audit logging." "Spring Boot 4.1 / JDK 25" "Java Process" {
                enterpriseApi = component "API Controllers Layer" "Handles HTTP endpoints (/api/v1/compliance, /api/v1/gate, /api/v1/scans, /api/v1/issues)." "Spring REST Controllers"
                scanRunnerComp = component "ScanRunner Engine" "Orchestrates repository clone and scanner container invocations." "Java / ScanRunner"
                scanIngestorComp = component "ScanIngestor Service" "Normalizes raw scanner outputs into findings and deduplicates secrets." "Java / ScanIngestor"
                issueSyncComp = component "IssueSync Service" "Calculates issue fingerprints (SHA-256) and reconciles state across scans." "Java / IssueSyncService"
                complianceComp = component "Compliance Service" "Evaluates NIS 2, DORA, ISO 27001, PCI-DSS frameworks at global & per-repo levels." "Java / ComplianceService"
                gateComp = component "PolicyGate Service" "Evaluates Quality Gate rules against target issue posture." "Java / PolicyGate"
                auditComp = component "AuditLog Service" "Maintains SHA-256 hash-chained immutable audit records." "Java / AuditLogService"
                cryptoComp = component "Encryption Service" "Encrypts SSH deployment keys at rest using AES-256-GCM." "Java / EncryptionService"
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

        agent -> apiApp "Fetches scan tasks via HTTP Long-Polling (GET /api/v1/agents/jobs)" "HTTP/REST API (Agent Key)"
        agent -> dockerDaemon "Executes analysis containers on remote worker machine" "Docker Socket"

        # Component Relationships
        enterpriseApi -> complianceComp "Requests compliance summaries"
        enterpriseApi -> gateComp "Requests policy gate evaluation"
        enterpriseApi -> scanRunnerComp "Triggers manual scans"
        scanRunnerComp -> dockerDaemon "Runs Syft, Grype, Gitleaks, Checkov, Semgrep"
        scanRunnerComp -> scanIngestorComp "Passes raw ScanArtifacts"
        scanIngestorComp -> issueSyncComp "Provides normalized Findings"
        issueSyncComp -> db "Persists Findings, Issues, and Triage events"
        complianceComp -> db "Queries target issue posture & metrics"
        gateComp -> db "Queries open issues & SLA overdue status"
        auditComp -> db "Appends SHA-256 hash-chained audit log rows"
        cryptoComp -> db "Encrypts/Decrypts private keys"
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
            description "Level 3: Component Diagram for Spring Boot Control Plane (vectispire-core)"
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
            element "Database" {
                shape Cylinder
            }
        }
    }
}
