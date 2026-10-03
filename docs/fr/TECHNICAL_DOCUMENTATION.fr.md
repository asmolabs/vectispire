# Vectispire — Documentation Technique

Ce document décrit l'architecture interne de Vectispire, son schéma de base de données et le
déroulement du pipeline d'analyse à l'exécution. Pour les fonctionnalités et le démarrage rapide,
voir [`README.md`](../../README.md). Pour le raisonnement derrière les choix structurels, voir
[`docs/architecture/`](../architecture/fr/) et son
[registre de décisions](../architecture/fr/decisions/).

---

### Origine & Philosophie du Nom : *Vectispire*

Le nom **Vectispire** est la synthèse de deux piliers de la sécurité de la chaîne d'approvisionnement logicielle :
- **`Vectis`** *(latin pour « levier de sécurité et verrou »)* : la plateforme agit comme le **levier cryptographique de sécurité et le gardien de politique** de votre chaîne de livraison. Elle impose des barrières strictes de qualité et de sécurité, signe des attestations in-toto, génère des signatures DSSE Cosign, des SBOM déterministes et des déclarations VEX vérifiables (OASIS CSAF 2.0, OpenVEX, CycloneDX) avec une chaîne d'audit cryptographique à intégrité vérifiable.
- **`Spire`** *(la vigie ASPM élevée et l'horizon de posture)* : la plateforme offre un **point de vue panoramique et surélevé** sur l'ensemble de votre portefeuille applicatif — cartographie des arbres de dépendances multi-niveaux, mesure de la dispersion du rayon d'impact, évaluation des conflits de copyleft des licences open source, et suivi de la vélocité de remédiation des vulnérabilités (MTTR) sur tous les dépôts Git et flottes de conteneurs.

---

## 1. Architecture en couches

Deux artefacts, construits par des chaînes d'outils différentes : un control plane Spring Boot dans
`vectispire-java/` et un frontal Angular dans `vectispire-angular/` qui lui parle via la même API
HTTP qu'utilisent un pipeline de CI ou un agent distant.

```mermaid
flowchart TB
    subgraph front["Frontal Angular — vectispire-angular/src/app/"]
        Pages["Pages<br/>dashboard, security, quality, repositories, issues,<br/>containers, scans, ssh-keys, api-keys, agents,<br/>settings, users, audit-log, teams, compliance,<br/>gate-policies, rule-sets, history, inventory, owasp"]
    end

    subgraph api["api/ — contrôleurs, DTO, gardes"]
        Routes["Contrôleurs<br/>auth, scans, issues, gate, exports, quality,<br/>repositories, containers, dashboard, settings,<br/>users, ssh-keys, api-keys, audit-log, compliance,<br/>csaf, cyclonedx, vex, agents, agents-admin, teams, rule-sets, owasp,<br/>sbom, remediation"]
    end

    subgraph services["services/ — orchestration, transactions"]
        Scan["ScanDispatcherService / ScanWorkerService<br/>ScanIngestorService"]
        Issue["IssueSyncService / IssueTriageService / VexIngestorService"]
        Comp["ComplianceService · EvidenceVaultService · CsafGeneratorService · CycloneDxGeneratorService"]
        Remed["SbomDiffService · SecurityDebtService"]
        Enrich["EnrichmentService · EolService · LicenseService"]
        Ai["AiReviewService"]
        Notify["NotificationService · OutboxService"]
        Ticket["TicketService · TicketSweepService"]
        Ops["SchedulerService · LeaderElectionService<br/>RetentionService · MaintenanceService"]
        Auth["AuthService · PasswordService · SessionCleanupService<br/>ApiKeyAuthService · AuditLogService · SettingsService<br/>EncryptionService · BootstrapService · VisibilityService"]
    end

    subgraph repos["repositories/ — accès aux données, aucune règle métier"]
        R["ScanRepository · IssueRepository · TargetRepository<br/>AuditLogRepository · SessionRepository · TeamRepository"]
    end

    subgraph persistence["persistence/ — entités, dialectes, types du pilote"]
        Ent["33 entités JPA · migrations Flyway"]
    end

    subgraph domain["domain/ — pur, ne dépend de rien"]
        D["fingerprint · gate · chaîne d'audit · exports · csaf · cyclonedx · triage<br/>compliance · url-guard · crypto · retention · scheduling · …"]
    end

    subgraph scanning["scanning/ — lance des conteneurs, aucune base"]
        S["ScanRunner · ContainerRunner<br/>syft · grype · gitleaks · checkov · semgrep"]
    end

    Pages -->|"/api en HTTP"| Routes
    Routes --> services
    services --> repos
    repos --> persistence
    services --> scanning
    services --> domain
    repos --> domain
    scanning --> domain
```

**L'injection de dépendances est celle de Spring**, par constructeur. Chaque collaborateur dont une
classe a besoin est un paramètre sans lequel elle ne peut pas être construite, ce qui est aussi ce
qui rend les campagnes unitaires possibles : un test passe un bouchon là où le conteneur passe un
bean, et rien n'a à être intercepté.

**Le découpage en couches est imposé, pas documenté.**
[`ArchitectureTest`](../../vectispire-java/vectispire-core/src/test/java/com/asmolabs/vectispire/core/ArchitectureTest.java)
lit le graphe d'imports avec ArchUnit et fait échouer la campagne quand une couche importe
au-dessus d'elle, ou qu'une classe de `domain` importe un framework.

**L'isolation de l'agent est plus forte que ce test.** `vectispire-agent` ne dépend pas de
`vectispire-core`, donc aucun pilote JDBC n'est sur son classpath de compilation et la violation
échoue à la compilation plutôt qu'à une campagne que quelqu'un pourrait supprimer — une propriété
de sécurité, pas une règle de style, voir la
[décision 0003](../architecture/fr/decisions/0003-long-polling-for-agents.md). Une règle écrite
seulement dans un document est vraie le jour où elle est écrite et fausse six mois plus tard.

`domain` est pur parce qu'il porte les calculs où une erreur ne lève aucune exception mais détruit
des données : l'empreinte d'une anomalie, la chaîne d'audit, le verdict de la gate, les formats
d'export. Il ne dépend que du JDK, de BouncyCastle et de Jackson.

## 2. Schéma de base de données

Le schéma appartient aux **migrations Flyway**, sous
[`src/main/resources/db/migration/`](../../vectispire-java/vectispire-core/src/main/resources/db/migration/) — du SQL natif, écrit une
fois dans `common/` avec des placeholders de type par moteur quand seuls les types de colonne
diffèrent, et une fois par moteur (`postgresql`, `mysql`) quand la structure diverge
([ADR 0027](../architecture/fr/decisions/0027-common-migrations-with-type-placeholders.md) ; le jeu
`sqlite` est parti avec la fixture, [ADR 0034](../architecture/fr/decisions/0034-mysql-replaces-the-sqlite-fixture.md)). `ddl-auto` vaut `validate`
et le reste : Hibernate ne doit jamais altérer le schéma à l'exécution.

**Le moteur est choisi par `VECTISPIRE_DB_URL` et rien d'autre** — Hibernate et Flyway le lisent
tous deux depuis l'URL JDBC, il n'existe donc aucun réglage de dialecte séparé à tenir en phase
avec elle. MySQL est le défaut, le moteur que livre `docker-compose.yml`. Les quatre
passent l'intégralité de la campagne d'intégration
([décision 0009](../architecture/fr/decisions/0009-four-engines.md), [décision 0013](../architecture/fr/decisions/0013-flyway-multi-dialect-migrations.md)).
[`SchemaParityIntegrationTest`](../../vectispire-java/vectispire-core/src/integrationTest/java/com/asmolabs/vectispire/core/persistence/SchemaParityIntegrationTest.java)
demande sur chaque moteur si les entités et le schéma s'accordent.

### Le modèle des analyses et des anomalies

```mermaid
erDiagram
    REPOSITORY ||--o{ SCAN : "est analysé par"
    CONTAINER  ||--o{ SCAN : "est analysé par"
    SCAN       ||--o{ FINDING : "produit"
    SCAN       ||--o{ ISSUE : "ouvre (first_seen)"
    SCAN       ||--o{ AI_REVIEW_RESULT : "porte"
    SCAN       }o--o| AGENT : "réclamé par"
    ISSUE      }o--|| REPOSITORY : "concerne"
    ISSUE      }o--|| CONTAINER : "concerne"
    REPOSITORY ||--o| SSH_KEY : "clone avec"
    REPOSITORY ||--o| GATE_POLICY : "évalué par"
    CONTAINER  ||--o| GATE_POLICY : "évalué par"

    REPOSITORY {
        int id PK
        string url
        string name
        string branch
        string sub_path
        uuid ssh_key_id FK
        int scan_interval_minutes
        string scan_cron
        bool scan_manual_only
        string required_agent_label
        datetime last_scheduled_scan_at
    }
    CONTAINER {
        int id PK
        string image
        string platform
        int scan_interval_minutes
        string scan_cron
        bool scan_manual_only
        string required_agent_label
        datetime last_scheduled_scan_at
    }
    SCAN {
        int id PK
        int repo_id FK
        int container_id FK
        string status "queued|scanning|completed|failed"
        string branch
        json sbom "purgé par la rétention"
        json cves "purgé par la rétention"
        json summary "compteurs, conservés"
        string claimed_by
        datetime claimed_at
        datetime lease_expires_at
        int attempts
        datetime not_before "reprenable à partir de, après une tentative échouée"
        string examined_types "types intégrés dont l'étape a produit ; null = non enregistré"
        text error
        datetime created_at
    }
    FINDING {
        int id PK
        int scan_id FK
        string type "vulnerability|secret|iac|license|eol|sast|quality|ai_review"
        string severity
        string identifier "CVE ou id de règle"
        string purl
        string package_name
        string package_version
        bool is_direct_dependency
        string file_path
        int line
        float cvss_score
        float epss_score
        bool is_kev
        string fix_state
        string fix_versions
        text description
        string source
    }
    ISSUE {
        int id PK
        string fingerprint UK "unique par cible"
        int repo_id FK
        int container_id FK
        string state "open|resolved"
        string triage_status "vocabulaire VEX"
        string triage_justification
        text triage_comment
        string triaged_by
        datetime triaged_at
        datetime triage_expires_at
        int times_seen
        datetime first_seen_at
        datetime last_seen_at
        string ticket_ref
        string ticket_url
        string reachability "dormante : rien ne l'écrit, toujours UNKNOWN"
    }
    AI_REVIEW_RESULT {
        int id PK
        int scan_id FK
        string model
        string status
        text content
        text error
    }
    GATE_POLICY {
        int id PK
        string target_kind "global|repository|container"
        int target_id
        int version
        bool is_active
        string fail_on_severity
        bool fail_on_kev
        bool fixable_only
        bool include_triaged
        bool include_ai_review
        string note
        string created_by
    }
    AGENT {
        uuid id PK
        string name
        string kind "embedded|remote"
        string labels "séparés par des virgules"
        string credentials_mode "local|delegated"
        bool enabled
        int max_concurrent
        uuid api_key_id FK
        string hostname
        string platform
        string version
        text sealing_public_key
        datetime last_seen_at
    }
```

### Les tables de service

Hors du modèle principal, et chacune porteuse :

| Table | Ce qu'elle contient | Pourquoi elle existe |
|---|---|---|
| `user` | comptes, mot de passe **Argon2id**, rôle, `must_change_password` | — |
| `session` | le **SHA-256** du jeton comme clé primaire — jamais le jeton, `created_at`, `last_seen_at`, `expires_at`, IP, agent utilisateur | une session **révocable** : un jeton qu'on ne peut pas invalider, et personne ne peut plus être déconnecté. Stocker le jeton lui-même ferait de chaque dump de cette table un jeu de sessions vivantes |
| `team_webhook` | le canal de notification d'une équipe | sa propre table plutôt qu'une colonne sur `team` : une URL de webhook est une capacité porteuse qui n'a rien à faire dans chaque requête sur les équipes — et `addColumn` sur `team` détruisait les clés étrangères des tables d'accès sur la fixture SQLite d'alors |
| `team` / `team_member` / `team_target` | les équipes, qui en fait partie, ce qu'elles possèdent | visibilité restreinte, rendue administrable : un compte voit l'union de ce que possèdent ses équipes et de ce qui lui a été assigné directement. La table par compte demeure pour l'exception qu'une équipe ne peut pas exprimer |
| `login_attempt` | `counter_key`, `occurred_at` | anti-bourrage compté par utilisateur **et** par client ; un seul axe se contourne |
| `api_key` | empreinte **Argon2id**, préfixe d'affichage, portées, restriction de cible, expiration | le secret brut est renvoyé une fois et jamais stocké. Le préfixe est ce qui rend ici une empreinte à coût mémoire abordable : il réduit la recherche à quelques lignes avant hachage |
| `ssh_key` | chiffré AES-GCM lié à sa ligne par les données associées | sans ce lien, le chiffré de la clé A recopié dans la ligne B se déchiffre parfaitement |
| `setting` | clé/valeur, dont les quatre fenêtres de remédiation | le catalogue `Setting` décide de ce qui est exposé. Une échéance est un réglage et non une colonne : c'est une politique qu'une organisation écrit, et la stocker par anomalie figerait chacune sur la politique en vigueur le jour de sa découverte |
| `audit_log` | empreinte de l'entrée, empreinte précédente, IP, agent utilisateur | chaînée : rend détectable une modification **sélective** |
| `outbox_message` | charge utile, `status`, `attempts`, `next_attempt_at`, `team_id` (nul = le webhook global) | écrite dans la transaction qui produit le résultat, de sorte qu'un plantage avant le POST ne perd rien |
| `processed_message` | `message_id`, `agent_id` | **créée par `V1` et jamais écrite** : plus rien ne la mappe. Le compte rendu répété d'un agent est refusé par le scan lui-même — le résultat n'est enregistré que tant que le scan est `scanning` et loué à cet agent (`ScanQueue.holdForWrite`), et l'enregistrer met fin aux deux, si bien qu'une seconde copie n'écrit rien et que `times_seen` ne bouge pas. La table reste parce que `V1` n'est jamais modifiée |
| `leader_lease` | `name`, `holder`, `expires_at` | une seule instance porte le tic périodique ; une table plutôt qu'un verrou consultatif parce qu'elle est **observable** |

## 3. Pipeline d'analyse

Déclencher n'exécute pas. Un déclenchement insère une ligne `queued` et rend la main ; une boucle
de travail la réclame et l'exécute. C'est ce qui permet à un agent distant, ou à une seconde
instance, de prendre le travail
([décision 0002](../architecture/fr/decisions/0002-the-database-carries-the-queue.md)).

```mermaid
sequenceDiagram
    participant T as Déclencheur<br/>(ordonnanceur, UI, API)
    participant Q as table scan
    participant W as ScanWorkerService
    participant R as ScanRunner
    participant I as ScanIngestorService
    participant S as IssueSyncService
    participant DB as Base de données

    T->>Q: INSERT scan(status="queued")
    T-->>T: rend la main immédiatement
    W->>Q: réclame (mise à jour conditionnelle + bail)
    W->>R: run(task)
    R->>R: clone (depth 1) ou export de l'image
    R->>R: syft → grype → gitleaks → checkov → semgrep
    R-->>W: ScanArtifacts (null = n'a pas tourné)
    W->>I: ingestion
    I->>DB: INSERT findings, UPDATE scan(summary)
    I->>S: synchronisation depuis l'analyse
    S->>S: empreinte, réconciliation, ouverture / résolution
    S->>DB: ligne d'outbox, dans la même transaction
    Note over W,DB: Un scanner en échec inscrit un échec sur l'analyse<br/>et laisse son artefact nul. L'analyse s'achève quand même.
```

Les points que le diagramme ne montre pas :

- **`null` n'est pas `[]`.** Dans `ScanArtifacts`, `[]` est l'affirmation positive *« l'étape a
  tourné et n'a rien trouvé »*, qui **résout** les anomalies de ce type ; `null` signifie qu'elle
  n'a pas tourné, et le backlog est laissé intact. Un portage qui normaliserait les nuls en listes
  vides résoudrait silencieusement des centaines d'anomalies de sécurité sans la moindre erreur
  ([décision 0007](../architecture/fr/decisions/0007-none-is-not-an-empty-list.md)).
- **L'échec ne se lit pas seulement dans le code de sortie.** Une exécution Semgrep où la plupart
  des fichiers ont expiré sort en 0 avec une liste courte. `errors[]` et `paths.scanned` sont
  inspectés, et au-delà de 25 % d'erreurs le résultat est `null`.
- **Semgrep produit deux types d'anomalies en une passe.** Le `metadata.category` de chaque règle
  tranche : `security` devient une anomalie `sast`, soumise à la gate comme n'importe quelle
  vulnérabilité ; tout le reste devient `quality`, qu'aucune politique ne peut faire entrer dans un
  verdict ([décision 0005](../architecture/fr/decisions/0005-quality-never-blocks-the-gate.md)).
  Les deux viennent de la même exécution, donc elles entrent ensemble dans la liste des types
  analysés.
- **La configuration des analyseurs vient de Vectispire, jamais de la cible.** gitleaks se rabat
  sur le `.gitleaks.toml` du dépôt analysé quand aucun `--config` ne lui est donné, et Semgrep
  honore le `.gitignore` de l'arbre analysé sauf indication contraire — dans les deux cas, le dépôt
  audité déciderait de ce qu'on cherche en lui.
- **Les règles sont recopiées dans l'espace de travail de l'analyse.** Contre-intuitif mais
  obligatoire : les chemins de volume sont résolus par le *démon* Docker, donc un répertoire situé
  dans l'image de Vectispire est invisible pour le conteneur de scan voisin. Voir
  [`RulePlacement`](../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/scanning/RulePlacement.java),
  qui fusionne aussi le `VECTISPIRE_SEMGREP_RULES_DIR` de l'exploitant.
- **Secrets, IaC et SAST ne tournent jamais sur une image de conteneur.** Ils cherchent dans du
  code source ; les déclarer analysés résoudrait silencieusement tout l'historique de cette cible
  pour ces types. Ils restent `null`.

## 4. Les scanners

Chacun est un conteneur éphémère, épinglé **par digest**, avec `cap_drop: ALL`,
`no-new-privileges`, des plafonds de mémoire et de PID, et le réseau coupé quand l'outil n'a rien
à aller chercher.

| Étape | Image | Réseau | Produit |
|---|---|---|---|
| SBOM | `anchore/syft` | ouvert (registre) | inventaire des composants |
| Vulnérabilités | `anchore/grype` | ouvert (base de vulnérabilités) | anomalies `vulnerability` |
| Secrets | `gitleaks` | **coupé** | anomalies `secret` |
| IaC | `bridgecrew/checkov` | **coupé** | anomalies `iac` |
| Code source | `semgrep/semgrep` | **coupé** | anomalies `sast` et `quality` |
| Licences | *(aucune)* | — | dérivé du SBOM |
| Fin de vie | endoflife.date | sortant, sur activation | anomalies `eol` |
| Revue IA | Ollama local | local, sur activation | anomalies `ai_review` |
| Plugins | les vôtres, épinglés par digest, par projet | **coupé** sauf déclaration justifiée | anomalies `plugin` — produit, non applicable ou absent |

Il y a **un** exécuteur, [`ScanRunner`](../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/scanning/ScanRunner.java), et il
lance Docker. Une conception antérieure avait une interface `ScannerEngine` avec trois
implémentations ; le portage n'a gardé que celle sur Docker et la
[décision 0010](../architecture/fr/decisions/0010-one-scan-runner.md) abandonne la couture plutôt
que de la reconstruire autour d'une implémentation unique. Déplacer l'exécution ailleurs se fait
en lançant un agent ailleurs.

**Un plugin est un scanner de plus, pas une exception aux scanners**
([décision 0017](../architecture/fr/decisions/0017-custom-checks-as-container-images.md)) : le même
`ContainerRunner` et la même forme fermée, sous le propriétaire de l'espace de travail, l'arbre analysé
en lecture seule et rien d'autre de l'espace de travail, un seul répertoire accessible en écriture pour
son SARIF. Il ne tourne que là où l'un de ses langages déclarés est présent ; sinon il est *non
applicable*, un troisième état à côté de « a tourné » et « n'a pas tourné », qui ne résout rien et ne
fait rien échouer. Le SARIF d'un outil interne — jamais d'un service hors de l'organisation — est
importé par une source déclarée.

**Aucun conteneur d'analyse ne voit la socket Docker.** L'étape de SBOM d'image la montait
autrefois pour que Syft tire l'image lui-même — ce qui revient à donner root sur l'hôte à un
processus dont l'entrée est hostile par définition. Vectispire tire et exporte désormais l'image,
et présente au conteneur une archive en lecture seule.

### Revue de code par IA (Ollama), désactivée par défaut

[`AiReviewService`](../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/ai/AiReviewService.java) est un
complément léger aux scanners, pas un moteur SAST : une invite, aucune reproductibilité garantie.
L'échantillon envoyé est une concaténation triée et filtrée par extension de fichiers source
plafonnée à 40 000 caractères — sans découpage, donc les gros dépôts sont tronqués.

Trois choses le concernant sont des décisions de sécurité, pas des fonctionnalités :

- **Le garde d'URL est inversé ici.** Cet endpoint reçoit le code source du dépôt analysé, donc le
  risque n'est pas qu'il pointe vers l'intérieur mais vers l'**extérieur**. Une URL publique bien
  formée est exactement ce à quoi ressemble un canal d'exfiltration, donc une destination publique
  est refusée sauf autorisation explicite.
- **Ses constats n'entrent dans aucun verdict de gate par défaut.** Un dépôt hostile peut orienter
  un modèle à qui on a remis son code, et un `critical` inventé ferait échouer la construction de
  quelqu'un.
- **Un LLM n'est pas une frontière de confiance.** L'échantillon est encadré par un délimiteur
  explicite et l'invite demande au modèle de *signaler* une tentative d'injection plutôt que d'y
  obéir. C'est une atténuation, et la raison pour laquelle son verdict ne bloque rien.

La liste des modèles est lue en direct depuis le `GET /api/tags` d'Ollama, de sorte que ce que
l'exploitant a réellement tiré est ce qui devient sélectionnable ; un repli à deux entrées est
affiché comme *suggestion* quand Ollama est injoignable, jamais comme installé. L'analyse est
défensive — une réponse qui ne se parse pas donne une liste vide et ne lève jamais.

## 5. Référence des services et des repositories

| Service | Responsabilité |
|---|---|
| `ScanDispatcherService` | Réclame les analyses de façon transactionnelle et remet les tâches aux agents ; porte la décision sur les identifiants (`credentialsMode`) et le scellement. |
| `ScanWorkerService` | Le worker intégré : réclame, exécute, ingère. |
| `ScanIngestorService` | Normalise les artefacts en lignes `Finding` et met l'analyse à jour. Connaît la base ; ne lance aucun conteneur. |
| `IssueSyncService` | Réconcilie les constats avec les anomalies d'une analyse à l'autre : empreinte, `times_seen`, ouverture/résolution. Écrit la ligne d'outbox dans la même transaction. |
| `IssueTriageService` | Applique une décision de triage validée, et fait expirer celles qui ont dépassé leur date de revue. |
| `EnrichmentService` | Scores EPSS et statut KEV, tous deux lus dans les flux stockés — un scan n'interroge aucun tiers. Avant la première synchronisation d'un flux, il ne pose rien : inconnu, jamais zéro. |
| `ThreatIntelFeedService` | Le catalogue CISA KEV : récupéré hors de toute transaction (`KevCatalogSource`, `VECTISPIRE_KEV_URL`), refusé s'il n'est pas complet ou s'il est plus ancien que celui en usage, stocké — les nouvelles entrées 500 par instruction — puis appliqué aux constats ouverts 500 à la fois, chaque page dans sa propre transaction sous le verrou de la ligne de synchronisation, de sorte que `CRITICAL_KEV_DETECTED` n'est émis qu'une fois pour un constat nouvellement listé, quel que soit le nombre de synchronisations en cours. Toutes les six heures via `KevCatalogueSyncTask`, une seule instance élue par une mise à jour conditionnelle ; audité sous `THREAT_INTEL_SYNCED`, échec compris. |
| `EpssFeed` | Le fichier EPSS quotidien du FIRST : téléchargé hors de toute transaction (`EpssFileSource`, `VECTISPIRE_EPSS_URL`, une redirection vers la même origine), lu en flux par `EpssFile` — refusé s'il n'est pas complet (somme de contrôle gzip, au moins 100 000 lignes et neuf dixièmes du fichier en usage, scores dans [0, 1], 128 Mio décompressés au plus) ou s'il est plus ancien que celui en usage — écrit sous une nouvelle génération de `t_epss_score` par transactions de 5 000 lignes, basculé par une seule mise à jour conditionnelle, puis appliqué aux constats ouverts page par page ; la génération remplacée est conservée jusqu'à l'application du fichier suivant — un lecteur qui a lu la ligne de synchronisation juste avant la bascule retrouve ses lignes — et celle d'avant est supprimée par lots. Un bail sur la ligne de synchronisation garantit une seule synchronisation à la fois. Quotidien via `EpssScoresSyncTask` ; chaque tentative auditée sous `THREAT_INTEL_SYNCED`. |
| `EolService` · `LicenseService` | Correspondance de fin de vie, et liste de licences interdites sur les données SBOM déjà collectées. |
| `AiReviewService` | Voir §4. |
| `NotificationService` · `OutboxService` | Choisit ce qui mérite un message, et relaie l'outbox avec un backoff plafonné. |
| `TicketService` · `TicketSweepService` | Ouvre un ticket de suivi par anomalie qui ferait échouer une construction, sous la même politique de gate — pas de second seuil. |
| `SchedulerService` | Le tic périodique : analyses dues, rétention, expiration de triage, outbox, balayage des tickets. |
| `LeaderElectionService` | Le bail qui fait qu'exactement une instance exécute ce tic. |
| `RetentionService` · `MaintenanceService` | Purge des charges utiles brutes, et entretien périodique. |
| `AuthService` · `PasswordService` · `SessionCleanupService` | Connexion, bridage, hachage, expiration des sessions. |
| `ApiKeyAuthService` | Vérification des clés, portées, restriction de cible, expiration. |
| `AuditLogService` | Entrées d'audit chaînées. L'enregistrement ne lève jamais : un échec de journalisation ne doit pas casser l'action auditée. |
| `EncryptionService` | AES-GCM au repos, avec le contexte lié à la ligne, et rotation multi-clés. |
| `SettingsService` · `BootstrapService` | Réglages clé/valeur, et création du compte au premier démarrage. |

Un repository par entité lue pour elle-même, dans le `persistence` de son module et nommé
d'après l'entité — `ScanRepository`, `IssueRepository`, `AuditLogRepository`, `SessionRepository`… —
chacun une fine enveloppe autour des requêtes dont ses appelants ont réellement besoin. Il n'y a pas de repository
de base générique. Un service n'écrit aucun SQL, et un repository ne porte aucune règle métier ;
`ArchitectureTest` impose les deux.

## 6. Le frontal

Angular 22 et TypeScript 6.0 avec [Optimus UI](https://github.com/openng-org/optimus-ui) 2, le fork
communautaire de PrimeNG v21 — PrimeTek a archivé PrimeNG et fait passer la v22 sous licence
commerciale ; Optimus 2 est ce fork porté sur Angular 22. La coque vient du gabarit Sparked
(MIT), le portage par OpenNG du gabarit Sakai de PrimeTek sur Optimus, et ses utilitaires Tailwind de
`@openng/optimus-ui-tailwindcss`, le fork MIT de `tailwindcss-primeui` par OpenNG.
Les icônes sont `@openng/icons`, le fork MIT de `primeicons` 7.0.0 par OpenNG : primeicons 8.x a suivi PrimeNG sous licence propriétaire, ce que le passage à Optimus visait précisément à éviter. Voir
[`vectispire-angular/README.md`](../../vectispire-angular/README.md).

Les modèles de vue que le navigateur reçoit sont typés et calculés côté serveur
([`core/api.models.ts`](../../vectispire-angular/src/app/core/api.models.ts)) : des valeurs finies, pas
de l'arithmétique. En particulier le verdict de gate affiché sur l'écran Sécurité est celui que
renvoie `POST /api/v1/gate`, parce que les deux passent par le même `PolicyGate` — et non par une
seconde implémentation en SQL, qui s'accorderait aujourd'hui et divergerait dès l'ajout d'un
drapeau de politique.

`npm test` commence par `scripts/check-assets.mjs`, qui refuse toute référence à un domaine tiers
dans `index.html` et `styles.scss` et vérifie que les polices déclarées existent et sont de vrais
`woff2`. Pas du zèle : la CSP refuse les feuilles de style tierces, et une telle référence ne casse
rien de visible — la requête est bloquée, la page se rabat sur la police système, et rien ne le
signale. C'est exactement ainsi qu'une typographie n'a jamais atteint la production.

Le même script échoue sur toute classe d'icône `pi-*` que le `openng-icons.css` installé ne définit
pas : une classe inconnue affiche une case vide sans rien signaler non plus, et quatre étaient
livrées vides de cette façon.

## 7. Approche des tests

`./gradlew build` exécute les suites unitaires, d'architecture et HTTP ; les suites de contexte et
HTTP tournent sur MySQL, le moteur que livre `docker-compose.yml` — un conteneur Testcontainers, donc
Docker doit tourner, ou le serveur que nomme `VECTISPIRE_TEST_DB_URL`, comme le fait le job `jvm` de
la CI avec un service. Sans l'un ni l'autre elles échouent plutôt que de s'ignorer, et Hibernate
valide le schéma à chaque démarrage de contexte
([ADR 0034](../architecture/fr/decisions/0034-mysql-replaces-the-sqlite-fixture.md)). La suite de
l'interface est `npm test`.

Sur un poste de développement, le conteneur peut être gardé d'une exécution à l'autre et partagé par
tous les worktrees : `echo testcontainers.reuse.enable=true >> ~/.testcontainers.properties` (ou
`TESTCONTAINERS_REUSE_ENABLE=true`). Les suites démarrent alors `vectispire-test-mysql`, étiqueté
`com.asmolabs.vectispire.test=mysql`, une seule fois, puis le trouvent en marche, hors de portée du
ramasse-conteneurs de Testcontainers (Ryuk). Chaque JVM de test travaille toujours dans une base à
elle, `vectispire_test_<secondes epoch>_<aléa>`, supprimée quand la JVM se termine ; la JVM suivante
supprime celles qu'une JVM tuée a laissées, une fois vieilles d'un jour, et rien d'autre.
`docker rm -f vectispire-test-mysql` retire le conteneur. La CI ne réutilise pas : elle nomme un
service du job par `VECTISPIRE_TEST_DB_URL`, et la campagne d'intégration garde un serveur neuf par
classe, parce qu'une vérification de concurrence y compte les attentes de verrou du serveur entier.
Le détail est dans
[`vectispire-java/README.md`](../../vectispire-java/README.md#one-mysql-kept-across-runs-on-your-machine).

Les campagnes d'intégration démarrent un moteur réel via **testcontainers**, appliquent toutes les
migrations et annulent chaque test dans sa propre transaction — de sorte que le schéma sous test
est celui que la production recevra, et que les cas ne peuvent pas se voir entre eux.

```bash
cd vectispire-java && ./gradlew integrationTest                # MySQL (-Pdialect=postgres)
cd vectispire-java && ./gradlew integrationTestAll             # les deux moteurs
```

Deux règles que le harnais s'impose à lui-même :

- **Il ne s'esquive pas quand Docker manque.** Une exécution qui ne vérifie rien doit échouer
  bruyamment. C'est un défaut que ce harnais a déjà eu.
- **Une garantie de concurrence non exécutée contre un serveur réel n'est pas une garantie.** Dix
  réclamants simultanés contre un moteur réel, c'est ce qui a révélé que six d'entre eux
  revenaient bredouilles pendant que vingt analyses attendaient — invisible sur SQLite et à la
  lecture attentive.

## 8. Graphe de dépendances & explorateur de rayon d'impact

- **Moteur d'analyse du rayon d'impact (`BlastRadiusService`)** : cartographie relationnelle en mémoire reliant Cible (dépôt Git / image de conteneur) $\rightarrow$ Dépendance de paquet (directe ou transitive) $\rightarrow$ Avis de sécurité CVE.
- **Score de risque organisationnel** : score de 0 à 100 pondérant la dispersion des cibles dans la flotte, l'inclusion directe ou transitive, et le score CVSS maximal. L'atteignabilité n'en est pas un terme : aucune analyse n'établit si le code vulnérable d'un composant est appelé — il n'y a pas d'analyse de graphe d'appels — et le rapport ne porte aucune atteignabilité par cible.
- **Endpoints REST** :
  - `GET /api/v1/blast-radius/explore?q={package|CVE}` : graphe complet nœuds/arêtes des dépendances et ventilation des cibles impactées.
  - `GET /api/v1/blast-radius/top-impact?limit=10` : paquets au plus fort rayon d'impact dans l'entreprise.

## 9. Plan de remédiation

- **Ce à quoi il répond.** La liste des constats dit ce qui ne va pas ; le plan de remédiation dit
  ce qu'on en fait. Une ligne est une action — une montée de version — et non une vulnérabilité :
  quatorze constats de la même bibliothèque sur six dépôts ne sont pas quatorze décisions, et une
  équipe qui n'a que la liste des constats trie du bruit au lieu de réduire du risque.
- **Classement (`SecurityDebtService.rank`)** : levier = (CVE distincts x 2 + critiques x 3 +
  élevés x 1,5) / effort, l'effort valant 1 h plus 0,1 h par CVE distinct. Les égalités se
  départagent par le nom du paquet, pour que deux exécutions sur les mêmes données s'accordent. Dix
  lignes au plus, et le parc est classé sur des lignes agrégées — les identifiants et les noms de
  cibles ne sont lus que pour les survivants.
- **Version conseillée.** Prise dans les `fix_versions` que les scanners remontent sur chaque
  constat, et comparée par `Versions` plutôt que comme du texte : « 2.9.0 » passe après « 2.17.1 »
  dans un tri de chaînes, et la conseiller laisserait la faille ouverte. Nulle quand aucun constat
  n'annonce de correctif, et l'écran le dit au lieu de conseiller une mise à jour inexistante. Ce
  champ portait auparavant la chaîne littérale `latest-patch` pour tous les paquets.
- **Points d'entrée REST** :
  - `GET /api/v1/remediation/high-impact-fixes?repoId=&containerId=&limit=` : l'ordre de travail
    classé, cadré par la visibilité. `limit` vaut 10 par défaut et est ramené dans [1, 50]
    plutôt que refusé — un plan n'est pas un endroit où répondre 400.
  - `GET /api/v1/remediation/debt` : les totaux qui donnent son échelle au plan.
- **Écran** : `/remediation`, ouvert à tout compte connecté. Chaque ligne se déplie sur les CVE
  qu'elle ferme — chacun renvoyant vers la liste filtrée — et sur les cibles concernées.

## 10. Centre de notifications multi-canaux & outbox transactionnelle

- **Canaux de notification pris en charge** :
  - **Slack** (`SlackNotificationChannel`, `SlackBlockKit`) : cartes Block Kit interactives avec en-tête, ventilation des constats et liens profonds directs.
  - **Microsoft Teams** (`TeamsNotificationChannel`, `TeamsCard`) : Adaptive Cards v1.4 envoyées via des workflows Power Automate.
  - **Discord** (`DiscordNotificationChannel`, `DiscordEmbed`) : Rich Embeds avec codes couleur dynamiques par sévérité.
  - **Courriel** (`MailNotificationChannel`) : remise multipart HTML/texte vers des listes de diffusion.
  - **Webhook générique / SIEM** (`NotificationService`) : POST JSON standard avec vérification de signature HMAC-SHA256 (`X-Vectispire-Signature`).
- **Résilience & garantie d'outbox** :
  - Les lignes d'outbox sont insérées dans `t_outbox_message` dans la transaction exacte qui réconcilie les résultats d'analyse. Les remises utilisent un backoff exponentiel plafonné avec isolation par destination.
- **Endpoints REST** :
  - `GET /api/v1/notifications/channels` : vue d'ensemble des canaux configurés et des événements souscrits.
  - `POST /api/v1/notifications/test/{channelType}` : test de remise simulée immédiate avec résultats de diagnostic.

## 11. Conseiller IA local d'explication des vulnérabilités et de triage

- **Moteur d'explication et de remédiation (`AiReviewService`, `AiAdvisorController`)** :
  - Génère des explications contextuelles de vulnérabilité, ce que l'on sait de son exploitation, une commande de mise à niveau suggérée lorsqu'une version corrigée est enregistrée et que le purl du composant désigne un écosystème pour lequel elle peut être écrite — une seule commande, pour cet écosystème (Maven, npm, PyPI, Cargo, NuGet, Composer, Go), aucune sinon — et une suggestion de statut VEX — `affected` ou `under_investigation`, jamais une justification ; `affected` seulement pour une CVE listée que porte une anomalie, jamais pour un identifiant qu'aucune anomalie visible ne porte. Aucune atteignabilité n'est transmise au modèle ni au repli, puisque rien ne la calcule : le repli indique que l'exposition n'a pas été évaluée, et `not_affected` n'est jamais proposé, même lorsqu'un modèle le répond.
  - **L'exploitation est lue dans les flux enregistrés, jamais supposée.** L'inscription KEV vient du catalogue CISA synchronisé (`deterministic.kev` : `LISTED`, `NOT_LISTED`, ou `UNKNOWN` avant la première synchronisation et pour un identifiant qui n'est pas une CVE) et le score EPSS du fichier EPSS en vigueur (`deterministic.exploitProbability`, null s'il est inconnu) ; l'indicateur et le score propres à une anomalie sont utilisés lorsqu'elle les porte. Une valeur inconnue est affichée comme inconnue à l'écran et envoyée au modèle comme `unknown`, avec la consigne de ne pas l'estimer. Un composant, une version ou une version corrigée que personne n'a enregistré vaut null, et aucune mise à niveau n'est proposée sans version corrigée.
  - Fonctionnement double : le modèle configuré (Ollama ou une API compatible OpenAI, tenue à une adresse interne sauf acceptation du risque distant) ou un repli déterministe instantané. L'explication d'une CVE que le parc ne porte pas est toujours la déterministe : rien la concernant n'est envoyé à un modèle.
- **Endpoints REST** :
  - `GET /api/v1/ai-advisor/status` : état du moteur d'inférence IA local et modèles disponibles.
  - `POST /api/v1/ai-advisor/explain/issue/{issueId}?language=` : explication contextuelle et déclaration VEX pour une anomalie persistée.
  - `POST /api/v1/ai-advisor/explain/cve/{cveId}?language=` : explication à la volée pour tout identifiant CVE — à partir de la première anomalie visible qui le porte, ou de sa seule inscription KEV et de son score EPSS dans les flux enregistrés. Les paramètres `reachability`, `packageName`, `currentVersion` et `fixVersion` ne sont plus lus : la parole de l'appelant était imprimée comme les faits de l'avis. La route n'accepte aucune clé d'intégration.
  - Le modèle est prié de répondre dans la langue du lecteur — celle de l'écran, transmise en `language` (`en`, `fr` ; anglais en son absence, toute autre valeur refusée en 400). Aucun réglage de compte ni d'instance n'enregistre de langue.

## 12. Risque juridique des licences open source & matrice de copyleft

- **Matrice de compatibilité croisée et de contamination virale (`LicenseConflictMatrix`, `LicenseGovernanceService`)** :
  - Identifie les risques de copyleft viral (GPL-3.0, AGPL-3.0) qui imposent juridiquement de divulguer du code source propriétaire lors de la distribution.
  - Classe les exigences de liaison dynamique pour le copyleft faible (LGPL, MPL, EPL) et les avis d'attribution permissifs (MIT, Apache-2.0, BSD).
  - Conseils de remédiation juridique actionnables par cible (recommandations de remplacement ou isolation architecturale du composant).
  - Ce que coûtent les lectures de tout le parc : les résumés (`GET /api/v1/licenses/summary` sans cible, celui du dossier de preuves) et le terme de licences de la fiche du portefeuille (`LicenseGovernanceService.violations`, son `total`, lu avec celui de chaque cible en un passage) sont comptés sur les décomptes de licences par cible que tient le classement de maturité (`violationsByTarget`, section 13), les analyses rattachées à aucune cible décomptées ensemble pour un lecteur qui voit tout le parc ; le `GET /api/v1/licenses/inventory` d'un lecteur restreint est lu sur les seules analyses de ses cibles ; l'inventaire et les conflits sans cible d'un administrateur relisent toujours le SBOM et les lignes de composants de chaque analyse, sous forme des seules colonnes utiles (`ScanCatalog.ScanSbom`, `ComponentName`) plutôt que d'entités.
- **Endpoints REST** :
  - `GET /api/v1/licenses/conflicts?proprietary=true` : liste détaillée des incompatibilités juridiques détectées et justifications de risque.
  - `GET /api/v1/licenses/matrix` : règles de référence officielles de compatibilité croisée des licences.

## 13. Tendances de posture de sécurité & analyse MTTR multi-échelons

- **Moteur d'analyse de posture (`PostureTrendAnalytics`, `DashboardController`)** :
  - Calcul en Java pur, par jour calendaire, du délai moyen de remédiation (MTTR) ventilé par échelon de sévérité (Critical, High, Medium, Low).
  - Indicateur de vélocité de résolution nette suivant la vitesse de résolution face au rythme de découverte.
  - Tableau de maturité des cibles classant dépôts et conteneurs selon **le score et la note de leur scorecard** (`A_PLUS` à `F`, `SecurityGrade`) : `SecurityScorecardService.gradeEach` exécute le calcul même de la fiche par cible (décision 0036 : `100 × e^(−points de risque / 55)`, points de risque 25 par problème exploité quelle que soit sa sévérité, 10 par critique, 4 par haute, 0,5 par moyenne, 0,125 par basse, 4 par licence non autorisée ; tout problème exploité plafonne à 54 ; jamais moins de 1 ; triage réglé — `not_affected`, `fixed` — exclu) sur une lecture groupée de l'allocation de l'appelant (`IssueCatalog.countForGradingByTarget`, que les fiches lisent aussi), les cibles des scans terminés restreintes en Java, et les violations de licence de chaque cible visible (`LicenseGovernanceService.violationsByTarget` : le compte même de l'inventaire, conservé par cible sous forme du nombre d'entrées déclarant chaque licence et recompté seulement quand un recensement des scans de la cible, lu à chaque affichage — nombre, identifiant le plus récent, statuts, SBOM conservés, scans à SBOM pourvus de composants — a bougé ; la politique juge les licences à chaque lecture, et un décompte n'est jamais servi au-delà de l'allocation du lecteur) ; `PostureScoreboards` ne fait que lister et ordonner. Le classement liste toute cible visible portant un problème ouvert ou un scan terminé — une cible scannée sans constat à 100, `A_PLUS` — et celles dont les problèmes sont tous clos. Une cible sans scan terminé est classée en dernier comme `NO_DATA`, sans score, comme sur sa fiche : l'absence n'est pas le vide (décision 0007). `openMedium` et `openLow` sont affichés et pèsent 0,5 et 0,125 ; un problème sans sévérité compte comme moyen. Chaque ligne porte ses `riskPoints`, qui départagent deux scores égaux, le moins d'abord. L'ancienne règle propre au classement (100 moins 25/10/3/1 par problème ouvert, A ≥ 90…) a disparu : elle saturait à 0 et contredisait la fiche et la pastille.
  - **Distinct du scorecard de sécurité** (`SecurityScorecardService`, `GET /api/v1/scorecards/...`), qui note de A+ à F sur les problèmes ouverts dont le triage n'est pas réglé — la formule de la décision 0036, ses `riskPoints` à côté du score — et alimente la pastille README publique, la lettre seule. Aucune cible avec un scan terminé, c'est `NO_DATA`, sans score ; un projet ou une solution est noté par sa cible analysée la plus faible (`weakestTarget`), plafonné à la part analysée ; le portefeuille (`/scorecards/global`) n'a pas de note — la répartition des notes de ses cibles, sa cible la plus faible et ses points de risque. La page « Dépôts » du guide utilisateur donne la règle complète.
- **Endpoints REST** :
  - `GET /api/v1/dashboard/posture-analytics?days=30` : MTTR agrégé par sévérité, taux de résolution nette, séries temporelles quotidiennes et classements de maturité des cibles.

## 14. Découverte de la surface d'attaque & inventaire des API exposées

- **Moteur d'extraction statique d'API et de routes (`ApiDiscoveryScanner`, `ApiInventoryService`)** :
  - Analyse statique sans AST, par expressions régulières, découvrant les endpoints HTTP sur Spring Boot (`@GetMapping`, `@PostMapping`, `@RequestMapping`), Express / NestJS (`app.get`, `router.post`), FastAPI / Flask (`@app.get`, `@bp.route`) et Go Gin (`r.GET`, `group.POST`).
  - Analyseur de spécifications OpenAPI 3.0 / Swagger 2.0 (`ApiContract`) lisant les contrats JSON/YAML.
  - Extracteur de routes Kubernetes Ingress associant les chemins d'hôtes publics directement aux services découverts.
- **Détection des API fantômes et de la dérive de surface d'attaque** :
  - Identifie automatiquement les **API fantômes** (endpoints HTTP actifs découverts dans le code source mais absents des spécifications OpenAPI).
  - Signale les **endpoints sensibles non protégés** (par exemple les routes `/admin`, `/actuator`, `/debug`, `/metrics`, `/env` non authentifiées) rattachés aux risques de l'OWASP API Security Top 10 (API1 : BOLA, API2 : authentification défaillante, API9 : gestion inadéquate des actifs).
  - Synthétise dynamiquement des spécifications OpenAPI 3.0.3 conformes à partir des routes découvertes dans le code, pour les services hérités non documentés.
- **Endpoints REST** :
  - `GET /api/v1/attack-surface` : synthèse globale inter-dépôts de la surface d'attaque, inventaire des frameworks et endpoints exposés à haut risque.
  - `DELETE /api/v1/attack-surface` : purge atomique de tous les endpoints et contrats découverts sur la plateforme.
  - `GET /api/v1/repositories/{id}/apis` : endpoints découverts, contrats et statut d'API fantôme pour un dépôt.
  - `DELETE /api/v1/repositories/{id}/apis` : purge des endpoints et contrats d'un dépôt précis.
  - `GET /api/v1/repositories/{id}/apis/export/openapi` : export de la spécification OpenAPI 3.0.3 synthétisée pour un dépôt.

## 15. Documentation OpenAPI 3.0 & référence REST

- **Documentation de référence statique** :
  - [`docs/fr/api/rest_api_reference.md`](api/rest_api_reference.md) : référence bilingue complète de tous les endpoints REST, en-têtes, corps de requête, réponses et exemples `curl`.
- **OpenAPI 3.0 & Swagger UI facultatifs** :
  - En déploiement de production, Swagger UI et `/v3/api-docs` sont **strictement désactivés par défaut** (`springdoc.swagger-ui.enabled: false`) pour éviter une exposition inutile.
  - Ils s'activent en développement ou en pré-production via `VECTISPIRE_SWAGGER_UI_ENABLED=true` et `VECTISPIRE_API_DOCS_ENABLED=true`.
  - Qui peut les lire est un second réglage, fermé par défaut : `vectispire.security.anonymous-api-docs` décide si un appelant anonyme y a droit. Le catalogue complet des endpoints est exactement la reconnaissance qu'un control plane comme celui-ci signale chez les autres.
