# 01 — Vue d'ensemble

## Ce que fait Vectispire

Vectispire surveille la sécurité d'un ensemble de **cibles** — dépôts Git et images de conteneurs —
en les soumettant périodiquement à une batterie d'analyseurs, et suit ce qu'il trouve **d'un scan à
l'autre**.

Ce dernier point est ce qui le différencie d'un simple script exécutant Grype en CI. Un analyseur
renvoie une liste ; Vectispire renvoie un **backlog** : ce qui est apparu, ce qui a été qualifié et
par qui, ce qui est présent depuis six scans, ce qui a disparu. Un rapport dit ce qui existe
aujourd'hui ; un backlog dit ce qui a changé, ce qui est la seule information sur laquelle on agit.

Le second usage est le **verdict de conformité** : `POST /api/v1/gate` indique à un pipeline de
build si une cible passe les contrôles selon une politique explicite. C'est là que Vectispire cesse
d'être un tableau de bord pour devenir une décision.

Trois principes façonnent tout le reste :

**Tout est local.** Les analyseurs s'exécutent dans des conteneurs éphémères sur la même machine,
avec le réseau coupé lorsque l'outil n'a rien à récupérer. Aucun code source ne sort. Ce n'est pas
une contrainte subie : c'est ce qui rend l'outil déployable là où la sécurité applicative est
réellement un sujet, et c'est pourquoi les règles Semgrep sont intégrées au binaire plutôt que
téléchargées ([décision 0006](decisions/0006-semgrep-rules-written-here.md)).

**Le déploiement par défaut est un seul processus et un seul fichier.** Un simple `docker run` et
l'outil est opérationnel. Tout ce qui est distribué — plusieurs instances, agents distants, un
moteur serveur — est possible, et refusé au démarrage lorsque la configuration ne le permet pas
([04](04-runtime-and-deployment.md)).

**Ce qui n'a pas été observé n'est pas sain.** Un analyseur qui plante n'a rien trouvé, et confondre
son silence avec un résultat vide revient à déclarer la cible corrigée. Cette distinction traverse
l'ensemble de la codebase ([décision 0007](decisions/0007-none-is-not-an-empty-list.md)).

## Les composants

```mermaid
flowchart TB
    subgraph proc["Plan de contrôle Vectispire (Spring Boot)"]
        API["API HTTP<br/>vectispire-core/api/"]
        SVC["Services<br/>vectispire-core/services/"]
        REPO["Repositories<br/>vectispire-core/repositories/"]
        SCHED["Planificateur<br/>SchedulerService — tick périodique"]
    end

    UI["Interface Angular<br/>vectispire-angular/src/app/"]
    DB[("Base de données<br/>PostgreSQL ou MySQL (SQLite pour les tests)")]
    DOCKER["Démon Docker<br/>conteneurs d'analyse éphémères"]
    AGENT["Agent distant<br/>protocole à quatre routes"]
    FEEDS["Flux publics<br/>EPSS, CISA KEV, endoflife.date"]
    HOOK["Webhook / Gestionnaire de tickets"]

    UI -->|"/api sur HTTP"| API
    API --> SVC
    SCHED --> SVC
    SVC --> REPO
    REPO --> DB
    SVC --> DOCKER
    SVC -.->|"sortant, optionnel"| FEEDS
    SVC -.->|"via l'outbox"| HOOK
    AGENT -->|"HTTP long-polling<br/>jamais la base de données"| API
    AGENT --> DOCKER
```

**Deux artefacts, une seule API.** Un backend Spring Boot et un frontend Angular ; le navigateur
dialogue avec la même API HTTP que les pipelines CI et les agents distants.

### Les couches et la règle d'isolation

```
api/ ──► services/ ──► repositories/ ──► persistence/ ──► base de données
           │                                  │
           └──────────────┬───────────────────┘
                          ▼
                       domain/          (pur, ne dépend de rien)
```

Une règle stricte garantit la testabilité : **une couche ne connaît que la couche située
immédiatement en dessous.**

## Le déroulement d'un scan

```mermaid
sequenceDiagram
    participant D as Déclencheur<br/>(planificateur, UI, API)
    participant Q as File d'attente (table t_scan)
    participant R as ScanRunner
    participant I as ScanIngestor
    participant S as IssueSync

    D->>Q: insère une ligne "queued"
    Note over Q: retourne immédiatement
    R->>Q: verrouille le scan (bail + propriétaire)
    R->>R: clone / résout l'image
    R->>R: SBOM, vulnérabilités, secrets, IaC, SAST
    R-->>I: ScanArtifacts (null = n'a pas tourné)
    I->>I: normalise dans Finding
    I->>S: synchronise depuis le scan
    S->>S: calcule l'empreinte, réconcilie, ouvre / résout
```

### Les analyseurs

| Étape | Outil | Réseau | Produit |
|---|---|---|---|
| SBOM | `anchore/syft` | ouvert (registre, démon) | inventaire des composants |
| Vulnérabilités | `anchore/grype` | ouvert (base de vulnérabilités) | constats `vulnerability` |
| Secrets | `gitleaks` | **coupé** | constats `secret` |
| IaC | `bridgecrew/checkov` | **coupé** | constats `iac` |
| Code source | `semgrep/semgrep` | **coupé** | constats `sast` et `quality` |
| Licences | *(aucun)* | — | dérivé du SBOM |
| Fin de vie | endoflife.date | sortant, optionnel | constats `eol` |
| Revue IA | Ollama local | local, optionnel | constats `ai_review` |
