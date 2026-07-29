# ADR-001 : Analyses de sécurité multi-scanners avec backends Docker local / API locale / API cloud

**Statut :** Proposé
**Date :** 2026-07-28
**Décideurs :** Laurent Boucher

## 1. Constat — revue du design actuel

Zanshin est aujourd'hui une application Reflex (Python full-stack, état géré côté serveur) avec persistance SQLAlchemy/SQLite. L'injection de dépendances est manuelle via `IoCContainer` (`zanshin/container.py`), instancié par requête depuis `get_container()`. Deux types de cibles sont supportés : `ZanshinRepository` (dépôt Git, avec clé SSH chiffrée) et `Container` (image Docker/registry).

Le pipeline de scan (`ScanProcessor.process_scan`) est linéaire et synchrone (exécuté dans un thread pool) :

1. clone du dépôt (GitPython) ou résolution de l'image ;
2. génération du SBOM via un conteneur éphémère `anchore/syft` (`docker.containers.run`) ;
3. scan du SBOM via un conteneur éphémère `anchore/grype` ;
4. agrégation des sévérités et écriture du résultat dans `Scan` (colonnes JSON `sbom`, `cves`, `summary`).

Un mécanisme de triage manuel existe déjà : `VexDecision` (statut affected/not_affected/fixed/under_review, justification, commentaire) — c'est une base VEX correcte, à réutiliser plutôt qu'à remplacer.

**Points forts** : séparation repository/service propre, chiffrement des secrets (SSH, à vérifier pour les futures clés API) via `EncryptionService` (AES-GCM), scan 100 % local/offline (aucune fuite de code vers un tiers), notion de VEX déjà présente.

**Points faibles / risques identifiés** :

- Le scan est câblé en dur sur Docker + Syft/Grype : aucune abstraction ne permet d'ajouter un autre moteur (secrets, SAST, IaC) ou un autre mode d'exécution (API locale, API cloud) sans dupliquer `ScanProcessor`.
- Les résultats (`sbom`, `cves`) sont des blobs JSON opaques : impossible de faire des requêtes (ex. "toutes les CVE critiques non traitées tous projets confondus") sans reparser du JSON en mémoire.
- Aucun timeout/retry sur les appels `docker.containers.run` : un conteneur Syft/Grype qui bloque bloque le scan indéfiniment.
- Le modèle `ApiKey` (`zanshin/models/api_key.py`) n'a pas de colonne pour stocker une valeur/hash de secret — en l'état il ne peut pas servir à authentifier un appelant externe ni à stocker une clé vers un service tiers. À corriger avant tout usage réel.
- Un seul type d'analyse (SCA/vulnérabilités de dépendances). Pas de détection de secrets, pas de SAST, pas d'IaC, pas d'enrichissement de risque (EPSS, KEV).

## 2. Objectif : une plateforme de sécurité applicative unifiée (ASPM)

Les plateformes ASPM (Application Security Posture Management) du marché agrègent plusieurs scanners sous un même tableau de bord : SCA, SAST, secrets, IaC, scan d'images conteneurs, CSPM, licences, détection de paquets malveillants, DAST/attack-surface, avec triage automatique basé sur l'exploitabilité (reachability analysis : le call-graph détermine si une vulnérabilité est réellement atteignable) et enrichissement EPSS/CISA-KEV pour prioriser au-delà du simple score CVSS. Côté architecture, ce type de plateforme propose généralement trois modes d'exécution : scan cloud éphémère (conteneur qui clone, scanne, puis s'auto-détruit, sans stockage du code), un scanner local/on-prem (CLI) pour les environnements qui ne veulent rien envoyer à l'extérieur, et des plugins IDE légers — tous remontant vers le même tableau de bord cloud via une API d'authentification dédiée.

Pour Zanshin, l'objectif réaliste n'est pas de reproduire une telle plateforme dans son intégralité, mais d'en adopter le même principe directeur : **une couche de scan pluggable**, capable de router chaque type d'analyse vers Docker local (déjà en place), une API locale auto-hébergée, ou une API cloud tierce — au choix, par type d'analyse et par sensibilité des données.

## 3. Décision proposée : abstraction `ScannerEngine`

Introduire une interface commune (Protocol Python) découplant "quoi scanner" de "comment/où c'est exécuté" :

```python
class ScannerEngine(Protocol):
    def generate_sbom(self, target: ScanTarget) -> Sbom: ...
    def scan_vulnerabilities(self, sbom: Sbom) -> list[Finding]: ...
    def scan_secrets(self, target: ScanTarget) -> list[Finding]: ...   # nouveau
    def scan_iac(self, target: ScanTarget) -> list[Finding]: ...       # nouveau
```

`ScanProcessor` devient un orchestrateur qui appelle l'implémentation configurée par type d'analyse, au lieu d'appeler `docker.containers.run` directement.

### Options considérées

| Dimension | A. Docker local (actuel) | B. API locale auto-hébergée | C. API cloud tierce |
|---|---|---|---|
| Complexité | Faible (déjà fait) | Moyenne (service HTTP à opérer) | Faible côté Zanshin, dépend d'un tiers |
| Confidentialité du code | Maximale (rien ne sort) | Maximale (reste sur le réseau interne) | Le SBOM (pas le code) part chez le tiers |
| Coût opérationnel | Spin-up conteneur à chaque scan (lent) | Service persistant, plus rapide | Aucun (facturation usage) |
| Fonctionnalités avancées (EPSS, KEV, reachability) | Non | Possible si le service les implémente | Oui, out-of-the-box selon le fournisseur |
| Dépendance à Docker-in-Docker | Oui (contrainte de déploiement) | Non | Non |

**Décision** : garder A comme backend par défaut (aucune régression), ajouter B pour lever la contrainte Docker-in-Docker et accélérer les scans répétés, et C en option opt-in pour l'enrichissement (EPSS/KEV, gratuits) et, plus tard, pour un moteur SCA alternatif. Le choix du backend est configurable par type d'analyse via une nouvelle table de configuration (section 4), pas figé dans le code.

## 4. Modèle de données à faire évoluer

- **`Finding`** (nouvelle table) : `scan_id`, `type` (vuln/secret/iac/license), `severity`, `identifier` (CVE/rule id), `package`/`purl`, `file_path`, `source` (grype/gitleaks/osv/.../...), `epss_score`, `is_kev` (bool), `status` (open/ignored/fixed), `vex_decision_id` (FK nullable). Complète les blobs `sbom`/`cves` existants (conservés tels quels pour l'audit brut) par une structure requêtable.
- **`VexDecision`** : ajouter `finding_id` (FK) pour relier proprement une décision à un finding normalisé plutôt qu'à un triplet (repo, vuln_id, package) reconstitué.
- **`ScanProviderConfig`** (nouvelle table) : `name`, `analysis_type` (sca/secrets/iac/enrichment), `mode` (docker/local_api/cloud_api), `base_url`, `encrypted_api_key` (réutilise `EncryptionService`, même pattern que `SSHKey`), `enabled`, `priority`. Remplace avantageusement l'usage détourné de `Setting` (clé/valeur générique) pour ce cas précis.
- **`ApiKey`** : ajouter une colonne de secret (hash, pas la valeur en clair) — actuellement le modèle ne permet pas d'authentifier quoi que ce soit ; à corriger si l'objectif est aussi d'exposer une API Zanshin programmatique.

## 5. Nouveaux types d'analyse à couvrir

- **Secrets** (gitleaks) : gain rapide, même pattern d'exécution que Syft/Grype (conteneur éphémère), risque faible. Priorité 1.
- **Licences** : déjà présent dans le SBOM Syft (champ licence par composant) — pas besoin d'un nouveau scanner, juste une règle d'évaluation (liste noire/blanche) sur les données déjà collectées.
- **IaC** (checkov ou `trivy config`) : même pattern conteneurisé, pertinent si des dépôts contiennent du Terraform/K8s.
- **SAST** (semgrep) : nécessite le code source cloné (déjà disponible pour les dépôts Git), mais un pipeline distinct du flux SBOM — impact plus large sur `ScanProcessor`.
- **Paquets malveillants / supply-chain** : les flux existent (OSV malicious packages, Socket.dev) mais sont réalistement des services cloud — à ne considérer qu'en option C.
- Hors périmètre assumé : CSPM (posture cloud), DAST, scan d'API, pentest continu — nécessiteraient un accès aux comptes cloud / crawling web, hors nature "basé SBOM" de Zanshin.

## 6. Enrichissement et triage basés sur le risque

- Appeler l'API EPSS (first.org, gratuite, sans clé) et le flux CISA KEV (JSON public, gratuit) pour peupler `epss_score`/`is_kev` sur chaque `Finding` après un scan Grype — permet de prioriser au-delà du seul CVSS, sans toucher au moteur de scan. Bon candidat pour la première intégration "API cloud".
- Étendre les règles d'ignore au-delà du VEX par repo : règles globales par CVE ou par package (à la manière des règles d'exclusion globales que proposent certaines plateformes ASPM), en plus des décisions VEX par (repo, vulnérabilité, paquet) déjà supportées.
- La reachability analysis complète (call-graph/taint) est un chantier lourd, à ne pas viser avant d'avoir SAST en place — à documenter comme non-objectif court terme.

## 7. Sécurité et exploitation

- Pour les scanners qui lisent le **code source** (secrets, SAST), garder le mode local (Docker ou API locale) par défaut ; un mode cloud doit rester strictement opt-in avec avertissement explicite dans les paramètres, contrairement au SCA où seul le SBOM (métadonnées de dépendances, pas le code) transite.
- Ajouter timeouts/retries sur les exécutions (actuellement absents sur `docker.containers.run`), avec repli automatique vers le backend local si un backend cloud est indisponible.
- Réutiliser `EncryptionService` (déjà solide, AES-GCM) pour toute nouvelle clé API stockée — ne pas réinventer un mécanisme de chiffrement.
- Un backend "API locale" permettrait à terme de retirer l'exigence d'accès au socket Docker en production (un privilège fort), en déportant l'exécution des scanners vers un service dédié.

## 8. Roadmap proposée

1. **Fondation** : extraire l'interface `ScannerEngine`, refactorer `ScanProcessor` pour l'utiliser (backend Docker inchangé fonctionnellement), introduire la table `Finding` en parallèle des blobs JSON existants.
2. **Secrets + licences** : ajouter gitleaks (mode Docker, même pattern que Syft/Grype) et exploiter les données de licence déjà présentes dans le SBOM.
3. **Enrichissement cloud gratuit** : intégrer EPSS + CISA KEV pour scorer les findings existants (première brique "API cloud", sans risque de fuite de code).
4. **Backend API locale** : service interne exposant Syft/Grype/gitleaks en HTTP (ou Trivy en mode serveur), pour accélérer les scans et lever la contrainte Docker-in-Docker.
5. **Backend cloud tiers (optionnel)** : intégration à une API cloud tierce (ou OSV.dev pour la partie SCA) via `ScanProviderConfig`, strictement opt-in, avec gestion de clé API chiffrée.
6. **IaC puis SAST** : étendre au-delà du flux SBOM vers une analyse du code source cloné.

## 9bis. Statut d'implémentation (2026-07-28)

Phase 1 (Fondation) implémentée :

- Interface `ScannerEngine` (`zanshin/services/scanners/base.py`) + implémentation `DockerScannerEngine` reprenant le comportement existant à l'identique.
- Sélection du backend par config (`zanshin/services/scanners/factory.py`), lue depuis la table `setting` existante (clé `scan_backend`, valeur par défaut `"docker"`) — un seul backend existe encore, mais le point d'extension est en place.
- `ScanProcessor` refactoré pour dépendre de `ScannerEngine` au lieu d'appeler Docker directement.
- Nouvelle table `Finding` (normalisée), peuplée automatiquement après chaque scan Grype, en plus des blobs `sbom`/`cves` existants.
- Correction du modèle `ApiKey` : ajout de `key_hash`/`prefix`, nouveau `ApiKeyService` (hash bcrypt, secret affiché une seule fois). Auparavant le secret affiché était en réalité l'id de la ligne, réaffiché en permanence dans le tableau — ce n'était donc jamais vraiment secret.
- `Base.metadata.create_all` ajouté au démarrage (`zanshin/zanshin.py`) : aucun outil de migration n'existait dans le code Python (le schéma était auparavant géré par l'implémentation précédente de cette application). Ce mécanisme ne crée que les tables manquantes et ne modifie jamais les tables existantes — insuffisant pour de futures évolutions de colonnes (ex. `VexDecision.finding_id`), qui nécessiteront un vrai outil de migration (Alembic recommandé).

Testé sur une copie isolée de `zanshin/database.sqlite` : les nouvelles tables (`finding`, `api_key`) se créent correctement, les tables et données existantes restent inchangées (mêmes colonnes, mêmes lignes).

Phase 2 (secrets) implémentée :

- `ScannerEngine.scan_secrets()` + implémentation Docker (gitleaks, même pattern d'exécution conteneurisé que Syft/Grype : `--no-git` car les dépôts sont clonés en `depth=1`, `--exit-code=0` pour ne pas faire échouer le conteneur quand des secrets sont trouvés — ce n'est pas une erreur d'exécution).
- Branché dans `ScanProcessor` uniquement pour les scans de dépôts (pas les images conteneurs, voir section 5), résultats persistés en `Finding(type="secret", source="gitleaks")`.
- UI (`depots.py`) : colonne "Secrets" dans l'historique global des scans, et section dédiée dans la fenêtre de détail d'un scan. Les vues "Dépôts" (liste) et "Détails d'un dépôt" n'ont pas encore ce badge — évolution simple à ajouter si utile (même requête `count_by_scan_ids_and_type`).
- Testé (parsing gitleaks JSON, cas rapport vide/absent, agrégation des comptes par scan) sur une copie isolée de la base.
- Badges "Secrets" complétés sur la liste des dépôts et le détail d'un dépôt (rattrapage de la limite notée précédemment).

Phase 3 (enrichissement EPSS/KEV) implémentée :

- `EnrichmentService` (`zanshin/services/enrichment_service.py`) : appelle l'API EPSS (first.org) et le catalogue CISA KEV — deux API gratuites, publiques, qui ne reçoivent que des identifiants CVE (jamais de code ni de SBOM), donc sans le compromis de confidentialité d'un backend SAST/secrets cloud (section 6/7).
- Exécuté après un scan de dépôt, en tâche non bloquante : toute erreur réseau est journalisée et absorbée (`try/except` dans `ScanProcessor`), un scan déjà réussi ne peut jamais être basculé en échec à cause de l'enrichissement.
- Activable/désactivable via le réglage `enrichment_enabled` (table `setting`, activé par défaut) — utile pour un déploiement strictement air-gapped.
- Cache du catalogue KEV au niveau de la **classe** `EnrichmentService`, pas de l'instance : `IoCContainer` est recréé à quasiment chaque requête (`get_container()`), un cache d'instance n'aurait donc jamais été réutilisé.
- UI : colonnes EPSS et "Exploitée activement" (KEV) dans le détail d'un scan, à côté de chaque CVE.
- Testé sur une copie isolée : calcul correct des scores, court-circuit quand le réglage est désactivé, résilience à une panne réseau simulée (aucune exception ne remonte), réutilisation effective du cache KEV entre deux instances du service.
- Non couvert : pas d'interface de réglages (page `settings`) pour changer `scan_backend`/`enrichment_enabled` sans passer par la base — aucune page de ce type n'existe encore dans l'app.

Phase 5 (backend cloud, partiel) implémentée : `OsvScannerEngine` (`scan_backend=osv`).

- Génération SBOM et scan de secrets restent locaux (délégués par composition à `DockerScannerEngine` — Syft a de toute façon besoin d'accéder au système de fichiers/à l'image, il n'y a pas d'équivalent cloud sensé sans tout envoyer).
- Seul le matching de vulnérabilités change : au lieu de Grype en local, appel de l'API cloud gratuite OSV.dev, un paquet (purl) à la fois. Seuls des identifiants de paquets partent vers le tiers, jamais le code ni le SBOM complet.
- La réponse OSV est traduite dans le même format que la sortie Grype (`{"matches": [...]}`) pour que `ScanProcessor`, la table `Finding` et l'UI (dialogue CVE) fonctionnent sans modification, quel que soit le backend utilisé.
- Bug détecté et corrigé pendant l'implémentation : `_build_findings` codait en dur `source="grype"` sur chaque `Finding`, quel que soit le backend réel. Corrigé pour lire une clé `engine_source` que chaque backend renseigne — nommée ainsi (pas `source`) car la sortie JSON native de Grype utilise déjà `source` pour tout autre chose (le type de cible scannée) ; réutiliser ce nom aurait fait planter le parsing partagé.
- Limite connue : OSV n'expose pas de sévérité normalisée aussi fiable que Grype (pas de champ CVSS numérique direct sans parser un vecteur) — seul `database_specific.severity` (renseigné notamment par les entrées GHSA) est utilisé ; sinon la sévérité tombe à "unknown" (bucket déjà géré par le reste du pipeline).
- Testé sur des données simulées : traduction correcte des réponses OSV, agrégat inchangé de `_summarize_findings`/`_build_findings` sur les deux formes (Grype réelle et OSV traduite), résilience à un échec réseau par paquet (le scan continue pour les autres paquets).
- Non fait : le backend "API locale" (Phase 4) reste à faire — c'est lui qui supprimerait la dépendance à Docker, pas le backend OSV.

Page de réglages ajoutée (`/settings`) : le lien "Paramètres" existait déjà dans le sidebar (`zanshin/ui/layout.py`) mais pointait vers une route jamais enregistrée — page morte depuis la migration. `zanshin/ui/pages/settings.py` permet maintenant de choisir `scan_backend` (docker/osv) et d'activer/désactiver `enrichment_enabled` depuis l'UI, avec un avertissement explicite quand le mode cloud (OSV) est sélectionné.

Conformité des licences implémentée (complète la dette laissée par la Phase 2) : `LicenseComplianceService` évalue une liste noire configurable (réglage `license_blocklist`, vide par défaut) sur les licences déjà présentes dans le SBOM Syft — aucun nouvel outil de scan, contrairement aux secrets. S'applique aux scans de dépôts **et** d'images (contrairement aux secrets, qui ne s'appliquent qu'aux dépôts), puisque Syft produit des données de licence dans les deux cas. Réglage exposé dans la page Paramètres ; résultats affichés dans la fenêtre de détail d'un scan (`Finding(type="license", source="syft")`). Non ajouté : colonne "Licences" sur les listes (dépôts/historique/détail dépôt) — gardé au niveau du détail de scan pour ne pas surcharger ces tableaux déjà denses, sachant que la fonctionnalité est inactive tant qu'aucune liste noire n'est configurée.

Phase 6 (IaC) implémentée : `ScannerEngine.scan_iac()` + implémentation Docker (checkov), même pattern conteneurisé que gitleaks (`--soft-fail` pour ne pas faire échouer le conteneur quand des checks échouent — c'est le résultat attendu, pas une erreur d'exécution). `OsvScannerEngine` délègue au backend local, comme pour les secrets (pas d'alternative cloud sensée). Branché dans `ScanProcessor` pour les scans de dépôts uniquement, résultats en `Finding(type="iac", source="checkov")`, section dédiée dans le détail de scan (sévérité, check, ressource, fichier).

Point de vigilance : le format de sortie JSON de checkov (objet unique vs liste selon le nombre de frameworks détectés) a été géré défensivement, mais je n'ai pas pu exécuter checkov réellement dans cet environnement (pas de Docker/réseau externe disponible ici) — le format exact peut varier légèrement selon la version installée. Testé uniquement sur des sorties simulées ; à valider sur un premier vrai scan de dépôt contenant du Terraform/Kubernetes. Si le format diffère, `scan_iac` échoue proprement (log + liste vide) plutôt que de faire planter le scan.

Phase 4 (backend "API locale") implémentée : `scan_backend=local_api`.

- **Décision de topologie (validée avec Laurent) :** le service `scan-api/` (nouveau, répertoire séparé à la racine) tourne sur la **même machine** que Zanshin, avec un **volume partagé** entre les deux. Zanshin transmet des chemins de fichiers, jamais le contenu — pas d'upload HTTP. Alternative "machine séparée avec upload" explicitement écartée (plus de travail, pas testable ici, pas nécessaire pour l'objectif visé).
- `scan-api/main.py` (FastAPI) exécute Syft/Grype/gitleaks/checkov **directement en sous-processus** (pas de Docker imbriqué) — les mêmes commandes exactes que `DockerScannerEngine`, juste sans le wrapper `docker run`. C'est ce qui retire le besoin d'accès au socket Docker du processus Zanshin lui-même : c'est le sidecar qui a les outils installés.
- `LocalApiScannerEngine` (nouveau, côté Zanshin) appelle ce service en HTTP. `ScannerEngine.get_workspace_root()` ajouté à l'interface (retourne `None` par défaut) : c'est ce qui permet à `ScanProcessor` de créer son répertoire de travail directement dans le volume partagé quand ce backend est actif, plutôt que dans le répertoire temporaire par défaut du système.
- Réglages exposés dans la page Paramètres : URL du service (`local_scan_api_url`) et chemin du répertoire partagé (`local_scan_api_shared_dir`).
- `scan-api/README.md` documente le modèle de déploiement, un exemple `docker-compose.yml`, la configuration côté Zanshin, et un avertissement de sécurité (le service n'a aucune authentification — à ne jamais exposer publiquement).
- **Limite importante à connaître avant mise en prod :** ce service et son `Dockerfile` ont été écrits sans accès à Docker ni au réseau externe dans cet environnement. La logique HTTP/JSON du service (`main.py`) a été testée avec FastAPI `TestClient` et les appels aux outils simulés (mockés) — donc le code Python est solide. En revanche, les étapes d'installation des outils dans le `Dockerfile` (scripts d'installation Syft/Grype, URL/version de gitleaks) n'ont pas pu être exécutées réellement : à vérifier et à construire une première fois avant de faire confiance à l'image. Le style de vérification a été le même partout dans ce chantier (voir plus haut pour les mêmes limites sur checkov) : logique applicative testée, intégration avec les binaires externes non exécutée faute d'environnement.

Phase 7 (gestion des utilisateurs, journal d'audit, suite de tests) implémentée, hors chantier initial de cet ADR mais dans le prolongement direct :

- `UserService` (CRUD utilisateurs, rôles SUPERUSER/ADMIN/USER) et page `/users`, avec garde-fous (impossible de supprimer son propre compte ou le dernier `SUPERUSER` actif).
- `AuditLogService`, branché sur la table légataire `audit_logs` (héritée d'une implémentation précédente de cette application, jamais utilisée jusqu'ici), et page `/audit-log` en lecture seule pour les admins.
- Suite de tests pytest (`tests/`) couvrant l'intégralité de la couche services/repositories/scanners (~93 % de couverture sur `zanshin/`, hors couche UI Reflex), exécutée exclusivement sur base SQLite en mémoire.

Phase 8 (revue de code par IA, optionnelle) implémentée, en complément du chantier scanners plutôt qu'en remplacement :

- `AiReviewService` (`zanshin/services/ai_review_service.py`) : envoie du code source à un modèle exécuté localement via [Ollama](https://ollama.com), avec un prompt système "security architect" (`review_code()`). Désactivé par défaut (`ai_review_enabled`), configurable depuis la page Paramètres (activation, URL du serveur Ollama, choix du modèle).
- Choix du modèle volontairement non figé : `list_available_models()` interroge en direct `GET /api/tags` sur le serveur Ollama configuré, pour ne proposer que ce que l'opérateur a réellement téléchargé (`ollama pull ...`) — pas de liste fixe. Une petite liste de repli (`gemma4:12b-it-qat`, `gemma4:e4b-it-qat`) n'est affichée que si Ollama est injoignable, à titre de suggestion.
- Modèle recommandé par défaut : Gemma 4 12B QAT (`gemma4:12b-it-qat`, librairie officielle Ollama, quantification 4-bit Q4_0, ~7,2 Go, ~9-10 Go RAM/VRAM nécessaires). Gemma 4 E4B QAT (`gemma4:e4b-it-qat`, ~6,1 Go) est proposé comme alternative plus légère pour du matériel contraint, avec une qualité de revue attendue plus faible (modèle "edge/mobile" au sens de Google/Ollama, pas un dense 4B entraîné pour maximiser la capacité).
- Un modèle initialement envisagé ("Bonsai 27B", quantification proche de 1-bit) a été écarté après vérification : uniquement disponible via des publications tierces non officielles, avec un risque de compatibilité documenté par l'auteur du modèle lui-même (format nécessitant potentiellement un fork llama.cpp non standard). Gemma 4 a été retenu à la place : modèles officiels de la librairie Ollama, sans risque de compatibilité connu.
- **Intégration au pipeline de scan** (mise à jour) : `ScanProcessor` appelle désormais `AiReviewService` quand `ai_review_enabled` est actif — repo scans uniquement (même raisonnement que secrets/IaC, section 5 : pas de code source pour un scan d'image). Un échantillon des fichiers source est constitué de façon volontairement simple (concaténation triée, filtrage par extension, exclusion de `.git`/`node_modules`/`.venv`/`__pycache__`/`dist`/`build`, plafond de 40 000 caractères sans chunking/RAG) — adapté à une "revue minimale", pas un substitut à un vrai pipeline SAST.
- Nouvelle table `ai_review_result` (une ligne par scan, `scan_id` unique) : modèle utilisé, prompt, réponse brute du LLM, statut (`completed`/`failed`), erreur. Table neuve plutôt que colonne ajoutée à `Finding` — évite toute migration manuelle (voir la contrainte déjà documentée sur `create_all`).
- Résilience : un échec de la revue IA (Ollama injoignable, erreur modèle...) est enregistré sur la ligne `ai_review_result` (`status="failed"`, `error=...`) mais ne fait jamais échouer le scan lui-même — même contrat que `EnrichmentService`.
- UI : section "Revue de code par IA" dans la fenêtre de détail d'un scan (`depots.py`), affichée uniquement quand une revue existe pour ce scan — texte de la réponse du modèle, ou message d'erreur si la revue a échoué.
- Non fait : pas de nouveau type de `Finding` pour la revue IA (reste un texte narratif à part, pas un finding normalisé par sévérité) ; pas de badge sur les listes (dépôts/historique), gardé au niveau du détail de scan comme pour les licences.

## 9. Prochaines étapes immédiates

1. Valider le schéma de la table `Finding` et son articulation avec `VexDecision`.
2. Choisir un vrai outil de migration (Alembic recommandé) avant toute nouvelle évolution de colonne sur une table existante.
3. Vérifier de bout en bout le service `scan-api/` (Dockerfile, versions d'outils) sur une infrastructure disposant de Docker/réseau externe.
4. Valider en conditions réelles la revue de code par IA (temps de réponse Ollama sur un vrai dépôt, qualité perçue des retours) avant d'envisager de la transformer en findings normalisés.
