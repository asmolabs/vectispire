# Modélisation des Menaces STRIDE basée sur DFD (Data Flow Diagram) — Vectispire

Ce document présente l'analyse formelle des menaces de **Vectispire** basée sur la modélisation par
**Diagramme de Flux de Données (DFD)** et la cartographie des risques **STRIDE par Entité
Individuelle du Système**.

---

## 1. Diagramme de Flux de Données (DFD - Data Flow Diagram)

```mermaid
flowchart TB
    subgraph TB1["Frontière de Confiance 1 : Périmètre Externe / Edge (TB1)"]
        E1["E1 : Analyste Security / Administrateur"]
        E2["E2 : Pipeline CI/CD (Jenkins / GitLab / GitHub)"]
        E3["E3 : Dépôt Git Distant / Registre d'Images (Code Hostile)"]
    end

    subgraph TB2["Frontière de Confiance 2 : Plan de Contrôle Backend (TB2)"]
        P1["P1 : Contrôleur API & Authentification (/api/v1)"]
        P2["P2 : Orchestrateur de Scan (ScanRunner)"]
        P3["P3 : Ingesteur & Réconciliateur (ScanIngestor / IssueSync)"]
        P4["P4 : Moteur de Conformité & Gate (ComplianceService / PolicyGate)"]

        DS1[("DS1 : Base de Données SQL<br/>(Dépôts, Scans, Issues, t_audit_log, Sessions)")]
        DS2[("DS2 : Espace de Stockage Éphémère<br/>(Workspace / tmp / Repositories)")]
    end

    subgraph TB3["Frontière de Confiance 3 : Conteneurs de Scan Isolés (TB3)"]
        P5["P5 : Conteneurs d'Analyse (Syft, Grype, Gitleaks, Checkov, Semgrep)"]
    end

    subgraph TB4["Frontière de Confiance 4 : Agent Distant (TB4)"]
        E4["E4 : Agent Distant Worker (Vectispire Agent)"]
    end

    %% Flux de données (Data Flows)
    E1 -->|"F1 : Authentification & Triage VEX (HTTPS)"| P1
    E2 -->|"F2 : Évaluation Gate (POST /api/v1/gate - API Key)"| P1
    E3 -->|"F3 : Clonage Code / Pull Archive Image"| DS2

    P1 -->|"F4 : Lecture / Écriture Sessions, Utilisateurs & Rôles"| DS1
    P1 -->|"F5 : Déclenchement de Scan (Queue t_scan)"| DS1
    P1 -->|"F6 : Évaluation de Conformité & Gate"| P4
    P4 -->|"F7 : Lecture des Issues & Posture Cibles"| DS1

    P2 -->|"F8 : Prise en charge des Scans Queued (Leader Lease)"| DS1
    P2 -->|"F9 : Préparation Workspace & Montage Source"| DS2
    P2 -->|"F10 : Lancement des Conteneurs d'Analyse éphémères"| P5
    DS2 -->|"F11 : Montage Read-Only du Code Source"| P5

    P5 -->|"F12 : Restitution des Artefacts Bruts (ScanArtifacts)"| P2
    P2 -->|"F13 : Transmissions des Artefacts pour Ingestion"| P3
    P3 -->|"F14 : Normalisation, Empreintes & Écriture Scellée"| DS1

    E4 -.->|"F15 : Long-Polling Job Fetch (GET /api/v1/agent/jobs)"| P1
    E4 -->|"F16 : Lancement des Conteneurs d'Analyse Locaux"| P5
```

---

## 2. Matrice des Menaces STRIDE par Entité Individuelle

---

### Entité E1 : Analyste Security / Administrateur

| Catégorie STRIDE | Scénario de Menace / Vecteur d'Attaque | Impact Potentiel | Mesure de Contrôle & Mitigation Implémentée |
|---|---|---|---|
| **Spoofing** | Usurpation de session utilisateur par vol de cookie JWT ou attaque par force brute sur l'endpoint `/api/v1/auth/login`. | Accès non autorisé au dashboard d'administration, falsification des triages VEX. | Mots de passe hachés en **Argon2id** (coût mémoire élevé), suivi des tentatives dans `t_login_attempt` avec blocage automatique, sessions chiffrées en DB (`t_session`). |
| **Repudiation** | Un utilisateur modifie la qualification d'une vulnérabilité critique en `NOT_AFFECTED` puis nie en être l'auteur. | Absence de responsabilité et impossibilité d'imputer la validation d'un risque. | Enregistrement obligatoire du `user_id`, horodatage ISO et écriture immuable dans `t_issue_triage_event` et dans le journal scellé `t_audit_log`. |
| **Elevation of Privilege** | Un utilisateur au rôle restreint tente d'accéder aux fonctionnalités d'administration ou de gestion des clés. | Contournement du contrôle d'accès basé sur les rôles (RBAC). | Contrôle de sécurité strict Spring Security `@PreAuthorize` et validation du champ `role` (`ROLE_ADMIN` vs `ROLE_USER`) sur chaque endpoint sensible. |

---

### Entité E2 : Pipeline CI/CD (Jenkins / GitLab / GitHub Actions)

| Catégorie STRIDE | Scénario de Menace / Vecteur d'Attaque | Impact Potentiel | Mesure de Contrôle & Mitigation Implémentée |
|---|---|---|---|
| **Spoofing** | Vol d'un jeton d'API d'intégration CI/CD stocké dans les secrets du pipeline. | Interrogation frauduleuse des API de Gate et exfiltration de la posture de sécurité des projets. | Clés d'API stockées sous forme de **hash Argon2id** (`vectispire_`), expirations configurables et périmètres (scopes) stricts. |
| **Information Disclosure** | Fuite d'informations confidentielles dans la réponse de l'évaluation du Quality Gate (`POST /api/v1/gate`). | Divulgation de la liste des vulnérabilités non corrigées à des tiers non autorisés. | La réponse du Gate ne contient que le verdict binaire (`PASSED`/`FAILED`), les règles enfreintes et les compteurs d'issues, sans divulguer les secrets ou codes sources. |

---

### Entité E3 : Dépôt Git Distant / Image de Conteneur (Code Hostile)

| Catégorie STRIDE | Scénario de Menace / Vecteur d'Attaque | Impact Potentiel | Mesure de Contrôle & Mitigation Implémentée |
|---|---|---|---|
| **Tampering** | Le code scanné inclut un fichier de configuration `.gitleaks.toml` malveillant pour ignorer la détection des secrets. | Masquage de failles de sécurité et contournement des contrôles d'audit. | **Règles imposées côté serveur** : `SecretsScanner` exécute un `--config` interne et ignorent la configuration du dépôt scanné ([ADR 0006](../../fr/decisions/0006-semgrep-rules-written-here.md)). |
| **Elevation of Privilege** | Tentative d'exploitation d'une faille du parser de l'analyseur pour s'échapper du conteneur et accéder au socket Docker hôte. | Prise de contrôle totale du serveur hôte Vectispire. | **Aucun conteneur d'analyse ne monte le socket Docker**. Exécution avec `cap_drop: ALL`, `no-new-privileges` et montage du répertoire source en lecture seule (`read-only`). |

---

### Entité E4 : Agent Distant Worker (Vectispire Agent)

| Catégorie STRIDE | Scénario de Menace / Vecteur d'Attaque | Impact Potentiel | Mesure de Contrôle & Mitigation Implémentée |
|---|---|---|---|
| **Spoofing** | Un agent non autorisé tente de se connecter au plan de contrôle pour récupérer des travaux de scan. | Exfiltration du code des projets ou falsification des rapports d'analyse. | Authentification obligatoire par jeton d'agent révoquable (`t_agent`) et protocole exclusif HTTP Long-Polling (`/api/v1/agent/jobs`). |
| **Elevation of Privilege** | Un agent distant compromis tente d'exécuter des requêtes SQL directement sur la base de données centrale. | Lecture/modification non autorisée de la base de données d'entreprise. | **Isolation stricte de l'agent (`vectispire-agent`)** : aucun pilote JDBC ni dépendance DB n'existe sur le classpath de l'agent. L'agent ne possède pas la clé `ENCRYPTION_KEY` ([ADR 0003](../../fr/decisions/0003-long-polling-for-agents.md)). |

---

### Processus P1 : Contrôleur API REST & Couche de Sécurité Backend

| Catégorie STRIDE | Scénario de Menace / Vecteur d'Attaque | Impact Potentiel | Mesure de Contrôle & Mitigation Implémentée |
|---|---|---|---|
| **Denial of Service** | Bombardement de requêtes HTTP sur l'API d'authentification ou de déclenchement de scans. | Épuisement des threads du serveur d'applications et indisponibilité de la plateforme. | Traitement asynchrone des scans via la table `t_scan`, rate-limiting par IP et baux de leadership (`t_leader_lease`). |
| **Information Disclosure** | Fuite d'informations sensibles via les traces d'erreurs (stack traces) lors d'exceptions API. | Divulgation de la structure interne de l'application ou des versions de bibliothèques. | Gestion globale des exceptions Spring (`@ControllerAdvice`) retournant des réponses d'erreur JSON normalisées et assainies. |

---

### Processus P2 : Orchestrateur de Scan (`ScanRunner`)

| Catégorie STRIDE | Scénario de Menace / Vecteur d'Attaque | Impact Potentiel | Mesure de Contrôle & Mitigation Implémentée |
|---|---|---|---|
| **Elevation of Privilege** | L'orchestrateur utilise la clé SSH du serveur hôte pour cloner des dépôts réservés. | Clonage non autorisé de projets confidentiels non assignés à la cible. | Désactivation par défaut de la clé hôte (`host-ssh: false`) et isolation stricte des clés SSH d'accès chiffrées par cible (`t_ssh_key`). |
| **Denial of Service** | Un projet gigantesque ou une boucle infinie dans une règle SAST bloque l'orchestrateur indéfiniment. | Blocage du worker et annulation des scans suivants. | Limites de ressources strictes (RAM max, CPU quota) et timeout d'exécution appliqués sur chaque conteneur par `ContainerRunner`. |

---

### Processus P3 : Ingesteur & Réconciliateur (`ScanIngestor` / `IssueSyncService`)

| Catégorie STRIDE | Scénario de Menace / Vecteur d'Attaque | Impact Potentiel | Mesure de Contrôle & Mitigation Implémentée |
|---|---|---|---|
| **Tampering** | Un scanner plante et renvoie une liste vide `[]`, entraînant la clôture du backlog d'issues. | Suppression silencieuse des failles non corrigées dans le suivi historique. | **Principe "None is not empty"** ([ADR 0007](../../fr/decisions/0007-none-is-not-an-empty-list.md)) : Un scan échoué renvoie `Optional.empty()` et laisse le backlog inchangé. |
| **Tampering** | Injection de doublons d'issues lors du traitement des résultats des scanners. | Pollution du backlog et perte des qualifications VEX existantes. | Calcul d'empreinte unique déterministe ([`IssueFingerprint`](../../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/domain/issues/IssueFingerprint.java)) avec déduplication par emplacement `(filePath + line)`. |

---

### Processus P4 : Moteur de Conformité & Quality Gate (`ComplianceService` / `PolicyGate`)

| Catégorie STRIDE | Scénario de Menace / Vecteur d'Attaque | Impact Potentiel | Mesure de Contrôle & Mitigation Implémentée |
|---|---|---|---|
| **Tampering** | Tentative de modification du résultat du verdict de Gate dans la base de données. | Passage en production d'un composant vulnérable. | Les verdicts sont calculés de manière dynamique et déterministe en mémoire par `PolicyGateService` sans stocker de verdict modifiable en base. |
| **Information Disclosure** | Exposition des scores de conformité réglementaire (NIS 2, DORA, ISO 27001) à des utilisateurs non autorisés. | Divulgation de faiblesses organisationnelles à des tiers. | Filtrage strict par visibilité (`VisibilityService`) et restriction d'accès aux rapports d'exportation PDF. |

---

### Processus P5 : Conteneurs d'Analyse Isolés (Syft, Grype, Gitleaks, Checkov, Semgrep)

| Catégorie STRIDE | Scénario de Menace / Vecteur d'Attaque | Impact Potentiel | Mesure de Contrôle & Mitigation Implémentée |
|---|---|---|---|
| **Information Disclosure** | Le conteneur d'analyse tente de transmettre le code source ou les secrets détectés vers un serveur externe. | Exfiltration de la propriété intellectuelle et d'identifiants valides. | **Isolation réseau totale (`network: none`)** pour tous les conteneurs d'analyse de secrets (Gitleaks), IaC (Checkov) et SAST (Semgrep). |
| **Elevation of Privilege** | Un binaire d'analyse compromis tente de modifier le système de fichiers de l'hôte. | Altération du système de fichiers du serveur. | Répertoire source monté en **lecture seule (`read-only`)**, exécution sous utilisateur non privilégié avec `cap_drop: ALL`. |

---

### Stockage DS1 : Base de Données Relational SQL (`t_repository`, `t_issue`, `t_audit_log`, `t_ssh_key`)

| Catégorie STRIDE | Scénario de Menace / Vecteur d'Attaque | Impact Potentiel | Mesure de Contrôle & Mitigation Implémentée |
|---|---|---|---|
| **Information Disclosure** | Vol des clés SSH privées lors d'un dump de la base de données SQL ou d'une sauvegarde leakée. | Compromission des accès Git de l'entreprise. | Chiffrement obligatoire au repos de toutes les clés SSH et secrets d'intégration en **AES-256-GCM** via `EncryptionService`. |
| **Information Disclosure** | Conservation indéfinie des rapports bruts de secrets (`Gitleaks`) contenant des jetons en clair. | Fuite d'identifiants valides en cas d'accès direct à la base. | Purge automatique des payloads bruts (`scan.cves`) par la tâche de rétention. Les entités `Finding` et `Issue` ne conservent **que le fichier et la ligne**, jamais la valeur du secret en clair. |
| **Tampering** | Suppression ou modification malveillante d'entrées du journal d'audit (`t_audit_log`). | Effacement des traces d'actions d'administration répréhensibles. | **Chaîne de hachage SHA-256** reliant chaque entrée à la précédente. La méthode `verifyIntegrity()` décèle immédiatement toute rupture. |

---

### Stockage DS2 : Espace de Stockage Éphémère (`Workspace` / `tmp`)

| Catégorie STRIDE | Scénario de Menace / Vecteur d'Attaque | Impact Potentiel | Mesure de Contrôle & Mitigation Implémentée |
|---|---|---|---|
| **Information Disclosure** | Maintien des répertoires temporaires de clonage sur le disque hôte après la fin de l'analyse. | Lecture locale du code source ou de secrets par d'autres processus système. | Nettoyage récursif garanti du dossier `Workspace` dans le bloc `finally` de `ScanRunner`. |
| **Tampering** | Modification du code source cloné dans l'espace temporaire avant l'exécution du scanner. | Falsification des constats d'analyse. | L'espace de travail est créé dans un répertoire temporaire sécurisé avec des permissions strictes (`0700`) accessibles uniquement par l'utilisateur du processus Vectispire. |

---

### Flux de Données en Transit (Data Flows : F1 à F16)

| Flux DFD | Catégorie STRIDE | Scénario de Menace / Vecteur d'Attaque | Impact Potentiel | Mesure de Contrôle & Mitigation Implémentée |
|---|---|---|---|---|
| **F1, F2 (API HTTP)** | **Information Disclosure** | Interception des identifiants ou des jetons d'API en transit sur le réseau. | Vol de sessions utilisateur ou de jetons d'accès CI. | Communication HTTPS obligatoire avec TLS 1.3/1.2 et en-têtes de sécurité stricts (HSTS, CSP, X-Content-Type-Options). |
| **F12, F14 (Ingestion)** | **Tampering** | Injection de doublons d'issues ou altération des constats lors du transfert vers la base. | Pollution du backlog et perte des décisions VEX. | Empreinte déterministe ([`IssueFingerprint`](../../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/domain/issues/IssueFingerprint.java)) avec déduplication par emplacement `(filePath + line)`. |
| **F15 (Long-Polling Agent)** | **Elevation of Privilege** | Un agent distant tente d'injecter des instructions SQL à travers le flux de récupération de tâches. | Injection SQL et accès direct aux données. | L'agent communique exclusivement au format JSON DTO structuré via l'API REST sans aucun accès JDBC ou SQL direct ([ADR 0003](../../fr/decisions/0003-long-polling-for-agents.md)). |
