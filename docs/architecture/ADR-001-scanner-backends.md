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
- **Normalisation des résultats** : le prompt système demande désormais une réponse au format JSON strict (tableau d'objets `severity`/`title`/`file_path`/`description`/`recommendation`). `AiReviewService.parse_findings()` transforme ce texte en données structurées de façon défensive (tolère les blocs de code markdown, ignore les éléments mal formés, normalise la sévérité vers le même vocabulaire que Grype/OSV/gitleaks/checkov — `critical`/`high`/`medium`/`low`/`negligible`/`unknown` — et ne lève jamais d'exception : une réponse qui ne parse pas donne simplement une liste vide). `ScanProcessor._run_ai_review` crée ensuite une ligne `Finding(type="ai_review")` par élément parsé (sévérité, titre, chemin de fichier, `source="ollama:<modèle>"`), en plus de la ligne `ai_review_result` qui garde la narration complète (reformatée à partir des éléments parsés quand le parsing réussit, texte brut sinon). Le detail de scan affiche donc à la fois la narration et un tableau de findings normalisés (sévérité/titre/fichier), dans le même style que les tableaux secrets/IaC/licences.
- Toujours pas de badge sur les listes (dépôts/historique) pour la revue IA — gardé au niveau du détail de scan, comme pour les licences.
- **Mode de déploiement Ollama configurable** : réglage `ai_review_deployment_mode` (`local`/`docker`, défaut `local`), sélectionnable en Réglages — purement informatif (n'affecte pas la connexion HTTP réelle, pilotée uniquement par `ai_review_ollama_url`), mais affiche un avertissement adapté : sur Mac Apple Silicon, Docker Desktop n'a pas de passthrough GPU/Metal, donc un Ollama en conteneur tourne en CPU uniquement et sera plus lent qu'une installation native. Un fichier `docker-compose.ollama.yml` est fourni à la racine du dépôt pour le mode Docker (section GPU NVIDIA commentée, pour Linux).

## 9ter. Correctifs issus de la revue d'architecture (vague 1, 2026-08-06)

Six correctifs, issus d'une revue transversale du projet. Ils ne changent aucune décision d'architecture ci-dessus ; ils corrigent des défauts d'implémentation, dont deux fuites de secrets.

1. **Isolation des artefacts de scan (fuite de secrets + revue IA inopérante).** `sbom.json` (écrit pour Grype) et le rapport gitleaks (qui contient chaque secret détecté **en clair**) étaient écrits dans le même répertoire que le checkout git — donc dans l'arbre parcouru par `_collect_ai_review_sample`. Conséquences : les secrets détectés partaient vers le modèle Ollama, et un SBOM Syft (qui dépasse presque toujours les 40 000 caractères du plafond) consommait tout le budget avant le premier fichier source, de sorte que la « revue de code » portait en réalité sur le SBOM. Corrigé structurellement, pas par une liste de noms de fichiers à exclure : le checkout va dans un sous-répertoire `source/` du workspace (constante `SOURCE_SUBDIR`), les artefacts restent à la racine, et tout ce qui parcourt le code source est donc incapable de les atteindre, quels que soient les artefacts ajoutés plus tard. Côté sidecar `scan-api/`, le rapport gitleaks est désormais écrit dans le scratch du service (il est relu et renvoyé en JSON, il n'a jamais eu besoin d'être sur le volume partagé).
2. **`lazy="joined"` sur `ZanshinRepository.scans` / `Container.scans`.** Chaque `find_all()` chargeait en eager tout l'historique de scans, blobs `sbom`/`cves` compris, pour afficher une liste de noms. Remplacé par des requêtes de colonnes (`ScanSummary`, `ScanHistoryRow` dans `ScanRepository`) : le coût d'affichage d'une liste ne dépend plus du volume de sortie brute stockée. Les relations subsistent pour la cascade de suppression (couverte par un test). Au passage : `ScanRepository.delete_by_id`, que l'UI d'historique appelait depuis toujours sans qu'il existe (échec silencieux derrière un toast « Erreur de suppression »).
3. **`EncryptionService` : fail-closed.** Sans `ENCRYPTION_KEY`, le service chiffrait avec `"my-secret-encryption-key-32bytes"` — valeur publiée dans ce dépôt, donc protection nulle pour les clés SSH privées stockées. Le chiffrement lève désormais `MissingEncryptionKeyError` ; le déchiffrement conserve l'ancienne clé en repli pour ne pas rendre illisibles les données existantes (rotation transparente : une valeur ré-enregistrée passe sous la nouvelle clé). La dérivation (troncature/padding NUL) est laissée inchangée à dessein — la modifier rendrait indéchiffrable tout l'existant.

   **Mise à jour ultérieure : le repli a été supprimé.** Le raisonnement « on garde l'ancienne clé au déchiffrement pour ne rien condamner » laissait la compromission active : le code source suffisait toujours à ouvrir la base, et la rotation transparente promise ne se produisait que si quelqu'un ré-enregistrait la valeur — ce qui n'était signalé nulle part. La constante est retirée. Ce qui la remplace est un vrai mécanisme de rotation, `ZANSHIN_PREVIOUS_ENCRYPTION_KEYS` : la différence n'est pas cryptographique, elle porte sur qui décide — lire un secret hérité demande un acte explicite de quelqu'un ayant accès à l'environnement, au lieu de fonctionner par défaut pour quiconque détient le fichier. Et l'état est désormais visible : la page *Clés SSH* montre les lignes qui dépendent encore d'une clé précédente, au lieu d'une ligne de journal.
4. **Bases SQLite retirées du suivi git.** `zanshin/database.sqlite` et `backend/database.sqlite` étaient versionnés (`.gitignore` ne couvrait que `*.db`) : hashes bcrypt et clés SSH chiffrées (avec la clé du point 3) se trouvent donc dans l'historique. Retirés de l'index, `.gitignore` étendu. **L'historique git n'a pas été réécrit** : les commits antérieurs contiennent toujours ces fichiers — cf. Prochaines étapes. Conséquence directe traitée : un clone neuf n'ayant plus de compte, `zanshin/bootstrap.py` crée le SUPERUSER initial depuis `ZANSHIN_BOOTSTRAP_USERNAME`/`_PASSWORD` quand la table `user` est vide.
5. **Autorisation par event handler.** Dans Reflex, chaque handler est adressable individuellement par le client : vérifier `logged_in` dans un `on_mount` protège l'affichage d'une page, pas les handlers derrière. `trigger_scan`, `delete_repository`, les réglages et la création de clés API étaient appelables sans authentification. `zanshin/ui/auth.py` fournit `@requires_login` / `@requires_admin`, appliqués à tout handler qui lit ou écrit en base (les setters de vue pure sont laissés tels quels). Les décorateurs préservent le *type* de la fonction (plain/generator/coroutine/async generator) et sa signature (`__signature__` explicite, car `getfullargspec` ne suit pas `__wrapped__`) : c'est ce dont Reflex se sert pour dispatcher et pour mapper les arguments d'événement.
6. **Validation des URL de dépôt.** `git clone` résout la syntaxe `<transport>::<adresse>` via un remote helper, et le helper `ext::` exécute son adresse comme commande shell : ajouter un dépôt valait exécution de code arbitraire. `zanshin/services/git_url.py` établit une liste blanche des transports qui ne font que *récupérer* (https, ssh, forme scp `git@hôte:chemin`), appliquée à l'enregistrement (`RepositoryService.save`, retour immédiat à l'opérateur) **et** juste avant le clone (point de passage obligé, qui couvre aussi les lignes créées avant cette validation).

Risque résiduel assumé, non corrigé ici : le clone reste en `StrictHostKeyChecking=no` (pas de `known_hosts` persistant à confronter, les dépôts étant clonés à neuf à chaque scan).

## 9quater. Vague 2 — du scanner à la gestion de posture (2026-08-06)

Cinq chantiers, dans l'ordre où ils se débloquent l'un l'autre. Le constat de départ : le produit savait détecter et afficher, mais l'opérateur n'avait aucun moyen d'**agir**. `VexDecision` existait, était testée, et n'était écrite par personne (0 ligne dans tous les déploiements) ; `Finding.status` était écrit une fois à `"open"` et jamais relu. Le README annonçait le triage VEX comme livré.

### 1. Alembic (débloque tout le reste)

`Base.metadata.create_all` ne savait que créer des tables entières, ce qui a forcé chaque fonctionnalité précédente à inventer une table plutôt qu'ajouter une colonne (`ai_review_result` en est l'exemple explicite). Remplacé par Alembic, avec `render_as_batch=True` (SQLite ne sait pas `ALTER` en place).

Le point délicat était l'adoption : les tables existantes ont été créées par l'implémentation précédente, donc rejouer la migration de référence sur une base peuplée échouerait sur « table already exists ». `zanshin/schema.py` distingue trois cas au démarrage — base vierge (on rejoue tout), base antérieure à Alembic (on **estampille** `0001` puis on applique la suite), base déjà gérée (on applique le delta). Vérifié sur une copie de la base réelle avant toute exécution : les 416 findings et 12 scans sont intacts.

`alembic check` (échec si un modèle n'a pas sa migration) est devenu exploitable après deux corrections : les index composites de `issue` sont déclarés sur le modèle et non seulement dans la migration, et la comparaison de type est désactivée **pour les deux types custom uniquement** (`GUID`, `SafeDateTime`), que SQLite renvoie en NUMERIC/TIMESTAMP à la réflexion — sans ça le check échouait en permanence et ne voulait plus rien dire.

### 2. Cycle de vie et triage (le cœur)

Nouvelle table `issue` : un problème sur une cible, suivi d'un scan à l'autre. Identité par empreinte SHA-256 de (cible, type, identifiant, purl ou nom de paquet, fichier) — **la version du paquet en est volontairement exclue** : une dépendance restée vulnérable pendant trois versions correctives est un problème avec un historique, pas trois problèmes, et une décision de triage ne doit pas s'évaporer au prochain patch.

Deux axes strictement séparés, et c'est la décision de conception importante :

- `state` (`open`/`resolved`) : ce que les scanners **observent**. Écrit uniquement par le pipeline.
- `triage_status` (vocabulaire VEX : `under_review`/`affected`/`not_affected`/`fixed`) : ce qu'un humain a **décidé**. Écrit uniquement par `IssueService.triage`.

Les confondre est l'erreur classique : un finding masqué et un finding réellement corrigé se ressembleraient, et « résolu » ne voudrait plus rien dire.

Règles de résolution, celles qui font qu'on peut faire confiance au chiffre :

- Un type non scanné n'est **jamais** résolu. `scanned_types` est fourni par l'appelant, pas déduit des findings présents : « le scanner de secrets a tourné et n'a rien trouvé » doit résoudre les secrets, « aucun secret parce qu'on n'en a pas cherché » ne doit rien toucher. Aucune déduction depuis les findings ne peut distinguer les deux cas.
- Seul un scan **terminé** résout quoi que ce soit. Un scan échoué ou interrompu n'observe rien. Ce n'est pas théorique : la première version du backfill a marqué les 416 problèmes « résolus » parce que les trois derniers scans de la base réelle étaient bloqués en `scanning` (voir chantier 4).
- Un problème résolu qui réapparaît est **réouvert**, pas recréé : c'est une régression, pas une découverte. Un verdict `fixed` est alors effacé (factuellement contredit) ; un `not_affected` survit, car il porte sur l'exposition du code, pas sur la présence du paquet.

La migration `0002` **rejoue l'historique** depuis les findings existants (plus ancien scan d'abord) plutôt que de partir d'une table vide : sinon le premier scan après mise à jour annoncerait comme « nouveau » tout ce que le déploiement traîne depuis des mois — exactement le signal que la fonctionnalité existe pour rendre fiable. Le backfill réutilise `build_fingerprint` de l'application plutôt que de réimplémenter le hash en SQL : deux définitions de l'identité divergeraient.

`Scan` porte `new_issues_count`/`resolved_issues_count`, affichés en colonne « Évolution » de l'historique. Nouvelle page `/issues` (backlog, filtres, tri, dialogue de triage) : c'est la moitié du produit qui manquait. `VexDecision` est laissée en place, vide et inutilisée, supersédée — la supprimer demanderait une migration destructive pour zéro donnée.

### 3. Findings actionnables

`vulnerability.fix.versions`, `vulnerability.cvss` et le lien de référence étaient présents dans la sortie des scanners et jetés. Extraits par `zanshin/services/remediation.py` vers `Finding`/`Issue`.

Le point non évident : pour un paquet système, l'enregistrement principal de Grype est l'avis de la **distribution** (RHSA, DSA), qui porte la sévérité éditeur et la version corrigée du paquet mais ni CVSS ni description — celles-ci vivent sur l'enregistrement NVD lié, dans `relatedVulnerabilities`. Ne lire que l'enregistrement principal donne donc un CVSS nul sur précisément les findings que produisent le plus les scans d'images. Le repli lit les enregistrements liés pour tout **sauf** le correctif, qui doit rester celui de la distribution : c'est la version empaquetée que l'opérateur peut réellement installer.

Le backend OSV traduit vers les mêmes clés (`fix.versions` depuis les événements de plage, vecteur CVSS depuis `severity`), donc `extract_remediation` lit les deux backends par un seul chemin. Pas de score numérique côté OSV : il publie le vecteur, en dériver le score demanderait un calculateur CVSS — dépendance réelle pour une valeur que l'UI sait déjà afficher en vecteur.

### 4. Fiabilité d'exécution

- `asyncio.get_event_loop()` + `run_in_executor` → `executor.submit`. L'appel était déprécié (il émettait déjà « There is no current event loop ») et ne servait qu'à atteindre ce même pool : rien n'attendait le résultat, donc aucune boucle d'événements n'était nécessaire.
- Timeout par conteneur de scan (`ZANSHIN_SCAN_TIMEOUT_SECONDS`, 900 s). Sans lui, un scanner bloqué occupait un worker du pool pour la vie du processus ; cinq et l'application ne scanne plus rien, silencieusement. docker-py implémentant `wait` par une requête HTTP, le timeout remonte en exception `requests` : distinguer un vrai timeout d'un démon injoignable importe, sinon `Scan.error` désigne la mauvaise cause.
- Réconciliation au démarrage : tout scan encore `pending`/`scanning` appartient à un processus qui n'existe plus. La base réelle en avait trois, et ce n'était pas qu'un badge faux — « le dernier scan de cette cible » est ce que lit la résolution des problèmes. Plus un ramasse-miettes périodique pour un worker bloqué sans redémarrage.

### 5. Ordonnanceur

`scan_interval_minutes`, `scan_cron` et `last_scheduled_scan_at` existaient depuis le début, l'UI collectait un intervalle pour chaque cible, et personne ne les lisait — dans un outil dont la prémisse est que *de nouvelles vulnérabilités apparaissent dans du code inchangé*. Un thread démon, tick d'une minute, qui dispatche via les mêmes `trigger_scan` que l'UI (un scan planifié et un scan manuel sont indistinguables en aval : même pool, même processeur, même synchro des problèmes). `last_scheduled_scan_at` est estampillé **avant** dispatch, sinon un scan plus long qu'un intervalle serait relancé à chaque tick.

Pas d'APScheduler ni de Celery : un processus unique avec SQLite n'a pas besoin d'un ordonnanceur distribué, et cela ajouterait un broker à exploiter. **`scan_cron` reste ignoré** (il faudrait un parseur cron, donc une dépendance) : l'ordonnanceur le journalise explicitement au lieu de faire silencieusement autre chose que ce que l'opérateur a saisi.

### Transverse : tests de contrat et CI

`tests/scanners/test_engine_contract.py` exécute une suite unique contre les trois implémentations de `ScannerEngine`. L'abstraction promettait la substituabilité sans que rien ne la vérifie, et deux divergences réelles existaient : le sidecar codait `linux/amd64` en dur alors que le backend Docker avait été rendu configurable (donc changer de backend changeait silencieusement l'architecture auditée, et donc les CVE trouvées), et il écrivait le rapport gitleaks dans l'arbre scanné après que le backend Docker avait arrêté de le faire. Les deux corrigées. À l'inverse, `registry:` contre `docker:` est une divergence **justifiée** — le sidecar n'a pas de démon Docker à traverser, c'est sa raison d'être — et reste dans les tests propres à chaque backend.

CI (`.github/workflows/ci.yml`) : tests, construction du schéma depuis les migrations sur base vierge, `alembic check` (dérive modèles/migrations), et aller-retour `downgrade base`/`upgrade head`. `reflex compile --dry` en est volontairement absent (il exige un `.web` provisionné, donc node/bun : lent et instable en CI pour un contrôle rapide et fiable en local).

## 9quinquies. Vague 3 — du produit utilisable au produit intégrable (2026-08-06)

Cinq chantiers, dans l'ordre où ils se débloquent : d'abord supprimer du code, ensuite en ajouter.

### D. Nettoyages rendus possibles par Alembic

Trois dettes n'existaient que par absence d'outil de migration.

- **`scan.error` : `String(255)` → `Text`.** Cette largeur arbitraire imposait à `docker_engine` un répartiteur de budget (`MAX_ERROR_MESSAGE`, `MIN_ERROR_DETAIL`, `_ellipsize`, `_build_message`) dont le seul rôle était de faire tenir les mots du scanner dans la colonne, en arbitrant entre tronquer le libellé ou tronquer l'explication. ~35 lignes supprimées, et deux tests qui vérifiaient la troncature remplacés par un test qui vérifie que **rien** n'est tronqué : la sortie d'un scanner est précisément ce qu'on ne veut jamais couper.
- **Colonnes fantômes supprimées** : `finding.status` (écrite une fois à `"open"`, jamais relue depuis que `Issue` porte l'état), `finding.vex_decision_id` et la table `vex_decision` (vide dans tous les déploiements). Deux modèles concurrents pour le même concept, c'est un piège pour le prochain lecteur.
- **`datetime.utcnow()`** centralisé dans `zanshin/clock.py` (18 appels). Le retour reste **naïf UTC** et pas timezone-aware, à dessein : tous les horodatages déjà stockés sont naïfs, et l'ordonnanceur comme le cycle de vie des problèmes comparent du stocké à « maintenant » — mélanger les deux lève `TypeError` au premier comparatif. Passer en aware demande une migration de données de chaque colonne d'horodatage ; l'entonnoir est là pour que ce soit un jour un changement d'une fonction. Zéro avertissement de dépréciation restant.
- **Index manquant** sur `finding.scan_id`, filtré à chaque affichage de liste (`count_by_scan_ids_and_type`).
- **Unicité réelle sur `user.username`** : le modèle la déclarait, la table héritée ne l'avait pas, donc elle reposait sur un lire-puis-écrire dans `UserService` — deux créations simultanées du même login passaient toutes les deux.

**Dérive héritée corrigée (migration 0004).** `alembic check` exécuté contre la base de développement — et non contre une base construite depuis les migrations — a révélé que `user`, `repository`, `container` et `scan` manquaient d'index, de clés étrangères et de contraintes d'unicité que les modèles déclarent, et que `scan.sbom`/`cves`/`summary` étaient typées `TEXT` au lieu de `JSON`. Rien de visible (SQLite n'applique pas les types déclarés), mais deux schémas pour une seule base de code, dont un que la CI ne peut pas voir. La migration est **conditionnelle** : elle n'agit que là où l'élément est réellement absent, donc elle ne fait rien du tout sur une base construite depuis `0001`. Vérifiée sur une copie de la base réelle (comptages identiques, `scan.sbom` identique à l'octet), et `alembic check` passe désormais sur la base réelle migrée.

### Correctif urgent découvert en chemin

`scheduler.start()` était appelé à l'**import** de `zanshin/zanshin.py`. Or `reflex compile --dry` importe ce module : **compiler l'application déclenchait un vrai scan de conteneur**. Le scan 13 de la base de développement a été créé exactement comme ça. Déplacé dans une tâche de cycle de vie Reflex (`app.register_lifespan_task`), qui ne s'exécute que quand l'application sert réellement.

Effet secondaire utile : ce scan accidentel a validé la vague 2 sur de vraies données Grype — 421 findings, **13 nouveaux problèmes et 8 résolus** par rapport à la référence du 29 juillet.

### A. API HTTP et policy gate

`zanshin/api/`, montée sur l'app Reflex via `api_transformer`, donc même processus et même port que l'UI. Chaque route est un adaptateur mince appelant le **même service que l'UI** : un scan déclenché par la CI et un scan déclenché par un bouton empruntent le même chemin, seule garantie que les deux restent cohérents.

- Authentification par jeton porteur. `ApiKeyService.verify_key` comparait en bcrypt contre **chaque** clé stockée — un hash volontairement lent par clé, à chaque appel — alors que la colonne `prefix` existait précisément pour l'éviter. Recherche par préfixe désormais, et `last_used_at` enfin écrit (rien ne pouvait l'écrire : aucun endpoint n'existait à qui présenter une clé).
- Les échecs d'authentification sont volontairement indiscernables entre eux (absent / malformé / faux → même 401) : distinguer confirmerait quels préfixes existent.
- **Gate** (`zanshin/services/policy_gate.py`, logique pure) : seuil de sévérité, KEV, « seulement ce qui a un correctif », et respect du triage. Trois décisions valent d'être dites : un problème trié `not_affected` ne fait **pas** échouer un build par défaut (un gate qui ignore le triage se fait désactiver) ; `fixable_only` existe mais n'est **pas** le défaut (il tolérerait silencieusement une vulnérabilité activement exploitée sans correctif, soit exactement le cas qui exige un humain) ; le gate répond **200** avec `passed: false`, parce qu'une politique violée est une réponse, pas une erreur de transport.

### B. Notifications

`NotificationGateway` ne faisait que journaliser, ce qui se défendait tant que la seule chose à dire était « un scan a fini » — un message dont personne n'a besoin. Ce qui a rendu les notifications utiles, c'est le delta de la vague 2 : « 3 nouveaux problèmes, 1 activement exploité, correctif disponible » est actionnable.

Webhook HTTP générique plutôt qu'intégration Slack : un POST JSON documenté atteint Slack, Teams, Discord, Mattermost, un bus interne ou un script de trois lignes ; un format propriétaire achèterait un joli rendu à un endroit au prix de tous les autres. Un champ `text` est inclus pour que les sinks de chat affichent quelque chose de lisible. Rien n'est envoyé quand un scan ne change rien — c'est la seule façon qu'un canal reste lu. L'URL est traitée comme un secret (jamais journalisée : Slack, Teams et Discord y encodent un jeton).

### C. Exports

- **OpenVEX** : une sérialisation, pas une traduction — c'était l'intérêt de stocker le triage dans le vocabulaire du standard. Trois règles de véracité : pas de statement sans identifiant de vulnérabilité, pas de `not_affected` sans sa justification obligatoire, et un problème résolu jamais trié est déclaré `fixed` et non « en cours d'investigation » (le scanner ne le voit plus ; affirmer l'inverse tromperait exactement le lecteur visé). Un verdict humain, lui, survit à la résolution.
- **CSV** : une colonne par champ stocké, pas une sélection — les gens qui demandent du CSV veulent pivoter eux-mêmes.
- **SBOM** : servi tel que Syft l'a produit. Pas de conversion CycloneDX/SPDX : ce serait une redérivation lossy de ce que l'outil sait émettre nativement, donc c'est une option **au moment du scan**, pas au moment de l'export.

### E. Pagination

L'écran des problèmes lisait 500 lignes en dur sans afficher de total : au-delà, la liste était tronquée en silence — exactement le travers que je reprochais ailleurs, introduit par moi en vague 2. Pagination avec total affiché (« 1–50 sur 429 »), offset remis à zéro à chaque changement de filtre, et ordre **total** dans la requête (`Issue.id` en dernier critère) sans lequel une ligne peut apparaître sur deux pages ou sur aucune.

### Non fait, et pourquoi

Le refactor des view-models de l'UI (`dict[str, str]` + conversions `str()` dans 5 pages, `depots.py` à ~1400 lignes) reste à faire. Ce n'est pas un oubli : c'est ~1000 lignes de remaniement sur la seule couche sans harnais de test, donc un risque de régression réel pour un gain interne. À faire avec la mise en place d'un harnais de test Reflex, pas avant.

## 9sexies. Dette structurelle résorbée (2026-08-06)

Les trois points laissés ouverts par la revue de la vague 3.

### Container paresseux

`IoCContainer` construisait ses vingt-six dépendances dans `__init__`, et il est
créé à chaque événement UI et à chaque requête API : cliquer sur un filtre payait
tout le graphe, dont `get_scanner_engine()`, qui lit `scan_backend` en base. Passé
en `cached_property` — l'accès reste `container.user_service`, mais rien n'est
construit sans être demandé. Effet de bord notable : un `scan_backend` invalide ne
casse plus que le scan, alors qu'il cassait tous les écrans (c'est la raison pour
laquelle le bootstrap devait câbler ses trois objets à la main).

### Rétention des données brutes

`Scan.sbom`/`Scan.cves` n'étaient jamais supprimés : 18 Mo pour treize scans, et
une croissance monotone tant que l'ordonnanceur tourne. `RetentionService` purge
les blobs hors des N derniers scans **par cible** *et* du délai d'âge — les deux
seuils, parce qu'un dépôt scanné deux fois par an garde ses données et qu'un dépôt
scanné toutes les heures reste borné ; aucune des deux règles seule ne fait les
deux. Ce qui survit toujours : `summary`, `findings_count`, tous les `Finding` et
tous les `Issue`. La projection normalisée *est* l'historique durable — c'était
l'objet de la vague 2 — donc purger un blob ne coûte aucune histoire, aucun
triage, aucun delta.

Deux corollaires :

- **Les dialogues de détail sont désormais construits depuis les `Finding`**, plus
  depuis `Scan.cves`. C'est ce qui rend la purge invisible pour l'UI, et c'était de
  toute façon absurde : on reparsait du JSON spécifique à un outil pour retrouver
  des données déjà normalisées à côté.
- **Bug trouvé par les tests** : `scan.sbom = None` sur une colonne `JSON` écrit le
  littéral JSON `null`, pas un `NULL` SQL (SQLAlchemy, `none_as_null=False` par
  défaut). `find_prunable` retrouvait donc éternellement les scans déjà purgés — la
  purge n'était pas idempotente. Corrigé sur le modèle (`JSON(none_as_null=True)`)
  et dans le service, qui ignore aussi les lignes déjà porteuses d'un `null` JSON.

### View-models typés, et un harnais de test UI

Chaque écran portait ses lignes en `list[dict[str, str]]` : les constructeurs
stringifiaient tout (`"critical": str(crit)`) et les templates comparaient des
chaînes (`rx.cond(r["critical"] != "0", ...)`). Trois coûts : les nombres
n'étaient plus des nombres, une clé mal orthographiée échouait *silencieusement* au
rendu, et la forme d'une ligne n'existait nulle part. Remplacé par des dataclasses
(la forme que Reflex recommande aujourd'hui) dans `zanshin/ui/view_models.py` — huit
pages converties, badges partagés extraits dans `components.py` (trois tableaux de
`depots.py` avaient divergé sur les couleurs).

J'avais écarté ce chantier en vague 3 « faute de harnais de test ». Le harnais
existe :

```python
root = rx.State(_reflex_internal_init=True)
state = root._get_state_from_cache(MyState)      # pas get_state : pas d'EventContext requis
MyState.event_handlers["load"].fn(state)         # la fonction, pas l'EventHandler
```

Trois détails non évidents : le substate doit venir du root (assigner une var
héritée sur un substate détaché lève, Reflex la renvoyant au `parent_state`) ;
`get_state()` passe par le state manager et exige un `EventContext` vivant, d'où
`_get_state_from_cache` ; et toute page doit être importée **avant** la création du
root, Reflex enregistrant les substates à la définition de classe. Voir
`UIHarness` dans `tests/conftest.py`.

Les deux moitiés de l'UI sont donc couvertes par des moyens différents : les
loaders par ces tests, les templates par `reflex compile --dry`, qui échoue sur un
attribut inexistant d'une ligne typée — ce qu'un `dict` ne permettait pas.

**La couverture affichée passe de 94 % à 82 %.** Elle n'a pas baissé : elle mesure
enfin la couche UI, qui était exclue en bloc de `pyproject.toml`. Seul
`zanshin/zanshin.py` (le point d'entrée) reste omis.

### Correctif de sécurité au passage

Les URL de référence viennent de Grype (`dataSource`) et d'OSV
(`references[].url`), donc de flux d'avis et de métadonnées que l'auteur d'un
paquet contrôle. Elles étaient rendues telles quelles dans `rx.link(href=...)` :
un `javascript:` était à un clic de s'exécuter dans le navigateur d'un analyste,
avec sa session. `safe_external_url` n'autorise que `http`/`https` (point 8 de la
revue de sécurité).

## 9septies. Revue de sécurité — correctifs (2026-08-06)

Revue faite « en tant qu'architecte de sécurité », puis corrigée. Ordre : les trous
d'authentification/autorisation d'abord, les défauts de conception ensuite.

**S1 — `scan-api` : lecture arbitraire de fichiers, sans authentification (critique).**
`require_shared_path` ne vérifiait que l'*existence* du chemin. `POST /scan/secrets
{"path": "/"}` faisait donc parcourir tout le conteneur par gitleaks, qui **renvoie
les secrets trouvés en clair dans la réponse**. Aucune authentification, et un bind
`0.0.0.0`. Deux verrous désormais : chaque chemin doit se résoudre (`realpath` +
`commonpath`, ce qui ferme aussi l'évasion par lien symbolique) dans
`ZANSHIN_SHARED_ROOT`, et chaque requête doit porter `ZANSHIN_SCAN_API_TOKEN`. Sans
jeton configuré, le service répond 503 à tout : un scanner non authentifié joignable
sur un réseau est pire qu'un scanner en panne.

**S2 — une clé API valait tous les droits, et tout USER pouvait en créer une
(critique).** La page `/api-keys` était `@requires_login`. Une clé donne l'API
entière sans portée propre, donc c'était une élévation de privilège par conception —
et c'est moi qui avais posé ce garde-fou trop bas en vague 1. Page passée en
`@requires_admin`, lien déplacé dans la section Administration.

**S3 — aucune limitation des tentatives de connexion (critique).** bcrypt coût 12
arrête un script naïf, pas un attaquant patient sur une politique à huit caractères.
`LoginThrottle` compte les échecs récents par utilisateur **et** par client : sur le
seul utilisateur, n'importe qui verrouille un compte connu en échouant exprès ; sur
le seul client, un botnet répartit ses tentatives. Vérifié **avant** le hachage, pour
qu'un compte verrouillé ne coûte pas un tour de bcrypt — sinon la lenteur volontaire
du hachage devient un moyen de dépenser le CPU du serveur gratuitement. Compteurs en
mémoire, et la limite est documentée : ils repartent à zéro au redémarrage.

**S5 — le gate acceptait les findings inventés par le LLM (élevé).**
`find_open_by_target` ne filtrait pas par type : un `Finding(type="ai_review")` de
sévérité `critical`, produit par un modèle à qui l'on a donné le code du dépôt, faisait
échouer un build. Un dépôt hostile pouvait donc influencer le verdict CI, et le bruit
LLM aurait fini par faire désactiver le gate. Exclus par défaut, `include_ai_review`
pour qui décide autrement. Défaut de ce que j'avais livré en vague 3.

**S4 — SSRF par trois réglages (élevé).** `url_guard` valide le schéma, résout le nom
et refuse le link-local (`169.254.0.0/16`, les métadonnées d'instance) **même** quand
le privé est autorisé — parce que c'est précisément l'adresse que l'attaque veut. Deux
règles pour deux usages : le webhook exige une destination publique
(`notification_allow_private_url` pour un bus interne), Ollama et le sidecar acceptent
le privé. Toutes les adresses résolues sont vérifiées, pas la première : un nom peut
renvoyer une publique et une privée. Limite assumée et documentée : la fenêtre de DNS
rebinding entre la vérification et la requête n'est pas fermée (il faudrait épingler
l'adresse résolue dans le client HTTP).

**S6 — durcissement des conteneurs de scan (élevé).** `cap_drop: ALL`,
`no-new-privileges`, plafonds mémoire et PID, et `network_disabled` là où l'outil n'a
rien à récupérer (gitleaks, checkov, SBOM de répertoire) — Grype a besoin de sa base
de vulnérabilités et syft du registre ou du démon. Cela ne supprime pas le socket
Docker (seul le backend `local_api` le fait), mais ôte les escalades faciles.

**S7 — analyseurs épinglés par digest (élevé).** Les quatre images étaient en
`:latest` alors qu'elles s'exécutent avec le socket Docker monté : qui contrôle
`anchore/syft:latest` contrôle la machine. Et un scan n'était pas reproductible.
Épinglées par digest d'index multi-arch, surchargeables par variable
d'environnement pour la mise à jour.

**Correctifs moyens.** URL de référence filtrées (`javascript:` cliquable, fait au
passage du refactor précédent) ; permissions de la base ramenées à 600 au démarrage
(hashes bcrypt et clés SSH chiffrées, créées en 644 par le umask) ; en-têtes de
sécurité dont une CSP réelle — l'application affiche des chaînes issues des scanners
et des flux d'avis, donc la CSP décide si une injection est inerte ou exécutée avec
la session de l'analyste ; HSTS **volontairement absent** (Zanshin s'atteint souvent
en HTTP sur une adresse interne, un HSTS rendrait cette origine définitivement
injoignable) ; audit des déclenchements de scan et des **refus d'autorisation**, qui
n'étaient qu'une ligne de log ; un seul scan en vol par cible, l'API répondant 409
et non 404 ou 500.

**Deux bugs trouvés par les tests, pas par la relecture** : `_Bucket.prune` lisait la
constante de module au lieu de la fenêtre de l'instance (une fenêtre personnalisée
était silencieusement ignorée), et `/health` déclarait `Dict[str, str]` en renvoyant
un booléen.

### Reste ouvert

Absence de cloisonnement entre équipes (une clé peut désormais être restreinte à une
cible, mais un *compte* voit toujours tout). Les autres points de cette liste — session
sans expiration, injection de prompt, audit sans IP ni intégrité — sont traités en
9octies.

## 9octies. Deuxième revue de sécurité (2026-08-06)

Revue de l'application *après* les correctifs S1–S7, donc sur ce qui restait quand les
trous d'authentification étaient bouchés. Dix points, corrigés en une passe.

**R1 — le websocket acceptait toutes les origines.** `cors_allowed_origins` valait `*`
par défaut. Une page tierce visitée par un utilisateur pouvait ouvrir une connexion et
faire créer de l'état serveur à volonté. Elle ne pouvait pas *voler* la session (le
jeton client est un UUID4 en `localStorage`, hors de portée d'une autre origine), donc
ce n'est pas un CSRF : c'est une création d'état non bornée, un déni de service.
Origines désormais explicites (`ZANSHIN_ALLOWED_ORIGINS`).

**R2 — l'URL Ollama pouvait pointer n'importe où (exfiltration).** La revue IA envoie
jusqu'à 40 000 caractères du code source scanné à l'URL du réglage. Le garde d'URL
existant vérifiait l'inverse de ce qu'il fallait ici : il empêchait d'atteindre
l'*interne* (SSRF), alors que le risque est d'atteindre l'*externe*. `require_private`
ajouté à `url_guard`, et l'URL est **revalidée au moment de l'envoi**, pas seulement à
l'enregistrement — un réglage écrit directement en base ne doit pas devenir un canal
d'exfiltration. Un opérateur qui veut vraiment un Ollama distant l'active explicitement
(`ai_review_allow_remote_url`).

*Sous-décision, trouvée par un test :* un nom qui ne résout pas est **refusé** quand
`require_private` est demandé. Échouer ouvert est défendable pour « est-ce privé ? »
(la requête échouerait de toute façon) ; ça ne l'est pas pour « ceci *doit* être privé »,
où le contrôle est la seule chose entre le code source et un hôte externe. Coût assumé :
une URL doit être résolvable par le serveur pour être enregistrée.

**R3 — une clé API restait tout-ou-rien.** S2 avait réservé la *création* aux
administrateurs, sans rien changer à ce qu'une clé pouvait faire : la clé d'un pipeline
lisait les problèmes de tous les projets, déclenchait des scans partout et exportait
l'inventaire complet. Trois axes ajoutés : portées (`read`/`scan`/`export`), restriction
à une cible (`repository:id` ou `container:id`, le *type* comptant autant que
l'identifiant puisque les identifiants sont par table), et expiration. La restriction
narrow aussi les *listes* — refuser les routes par cible en laissant `/issues` tout
renvoyer n'aurait rien restreint. 403 et non 404 : c'est ce qui permet à un pipeline de
distinguer « ma clé est ailleurs » de « cette cible a disparu ».

**R4 — un chiffré était valide dans n'importe quelle ligne.** AES-GCM sans données
associées : quiconque pouvait écrire en base copiait la clé de déploiement chiffrée du
dépôt B dans la ligne du dépôt A, et A était ensuite cloné avec la clé de B, sans
erreur. Le contexte (`ssh_key:{id}:private_key`) est désormais lié au chiffré. Le
déchiffrement retente sans AAD pour les valeurs antérieures — les refuser aurait rendu
inutilisables des clés réelles — et journalise ces cas. Conséquence de conception :
`create_key` enregistre deux fois, l'identifiant de ligne faisant partie de l'AAD.

**R5 — aucun quota sur l'API.** `/gate` charge tout le backlog ouvert d'une cible à
chaque appel : une boucle avec une clé légitime suffit. Fenêtre fixe en mémoire, par
clé — la clé est l'identité responsable, et c'est ce qu'un opérateur peut révoquer.
Fenêtre fixe plutôt que token bucket pour pouvoir répondre `Retry-After`.

**R6 — la documentation OpenAPI était publique.** `/openapi.json` et `/docs` livraient
la carte complète des routes et des charges utiles à qui atteignait le port. Servies
maintenant sous `/api/v1/`, derrière la même clé que le reste.

**R7 — le mot de passe de provisionnement ne mourait jamais.**
`ZANSHIN_BOOTSTRAP_PASSWORD` a vécu dans un fichier d'environnement, un compose, une
variable de CI, peut-être un dépôt : c'est un secret de provisionnement, pas un mot de
passe. Le compte le plus intéressant à attaquer portait donc le secret le plus
susceptible d'avoir fuité. `must_change_password` ajouté, posé par le bootstrap **et
par toute réinitialisation administrateur** (celui qui a tapé le nouveau mot de passe le
connaît). Le compte n'est pas bloqué à la connexion : il entre et atterrit sur
`/change-password` — une connexion qui réussit puis refuse d'avancer est indiscernable
d'une application cassée. Le mot de passe actuel est exigé même en étant connecté : une
session ouverte sur un poste déverrouillé ne doit pas suffire à prendre le compte.

**R8 — session sans expiration.** `authenticated_at` en état, TTL de 12 heures par
défaut, vérifié au chargement de page. Une estampille absente ou illisible compte comme
expirée : échouer ouvert rendrait le contrôle décoratif, et le coût d'échouer fermé est
une reconnexion.

*Défaut trouvé en écrivant le test :* `check_auth` faisait `return BaseState.logout(self)`.
Sur une classe d'état Reflex, c'est un accès d'attribut sur un `EventHandler` — ça
construit une spécification d'événement au lieu de rien nettoyer. La session finissait
par être vidée, mais au tour suivant, après que la page ait monté et que ses autres
`on_mount` aient chargé les données que la session expirée n'était pas censée voir.
`_clear_session()` est maintenant une méthode ordinaire, appelable directement.

**R9 — l'audit ne portait ni provenance ni intégrité.** « Alice a échoué à se
connecter » sans plus : pour un événement d'authentification, c'est la différence entre
« elle s'est trompée deux fois » et « quelqu'un parcourt la liste des comptes depuis un
hôte ». IP et user-agent ajoutés, et chaque entrée porte l'empreinte de la précédente.
Ce chaînage ne rend pas le journal append-only — qui peut écrire la table peut réécrire
toute la chaîne — mais il rend l'édition *sélective* détectable, et c'est la menace
réaliste quand la ligne intéressante est une parmi des milliers. `verify_chain()`
signale la première rupture. Les entrées antérieures au chaînage sont déclarées
non vérifiables plutôt que rétro-hachées : backfiller des empreintes serait fabriquer
une preuve.

*Défaut trouvé en écrivant le test :* l'empreinte couvre l'horodatage, mais celui-ci
venait du défaut de colonne, appliqué au flush — donc *après* le calcul. Chaque entrée
échouait à sa propre vérification. L'horodatage est posé explicitement.

**R10 — injection de prompt (atténuation).** Le code scanné est des données, pas des
instructions : l'échantillon est encadré par un délimiteur explicite et le prompt dit au
modèle de *signaler* une tentative d'injection plutôt que de lui obéir. Atténuation, pas
correctif : un LLM n'offre pas de frontière de confiance, ce qui est la raison de fond
pour laquelle un verdict de revue IA ne fait pas échouer le gate par défaut.

### Défaut d'exploitation corrigé au passage

La vraie base s'est retrouvée **à moitié migrée** (colonnes `api_key`/`audit_logs`
créées, `alembic_version` encore à 0004, et la reprise échouant sur « duplicate column »).
Cause : `upgrade_to_head()` s'exécute à l'import, Reflex importe l'application dans
plusieurs processus, et le DDL de SQLite n'est pas transactionnel — deux montées
simultanées se marchent dessus, et l'échec laisse le schéma entre deux états. Deux
mesures : un verrou fichier (`fcntl`) sérialise la migration, et 0005 est idempotente
*par colonne* (inspection avant ajout) pour pouvoir reprendre une migration partielle.
La base réelle a été réparée à 0005.

### Reste ouvert après cette vague

Pas de cloisonnement par équipe au niveau des *comptes* (seules les clés API sont
restreignables à une cible). Quota et anti-bourrage en mémoire, donc par processus :
correct pour ce déploiement mono-processus, à repenser si l'application est répliquée.
Le journal d'audit reste dans la même base que les données qu'il surveille.

## 9nonies. Vague 4 — de la détection à l'action (2026-08-06)

Revue de produit plutôt que de sécurité : la détection couvre déjà dépendances,
secrets, IaC, licences et revue IA, et le manque n'est plus là. Il est dans ce qui
se passe *après* la détection. Trois points retenus, ceux dont le rapport
valeur/effort est le plus élevé.

**F1 — export SARIF.** Un problème ne vivait que dans Zanshin. SARIF est le seul
format que GitHub code scanning, GitLab et Azure DevOps ingèrent nativement : c'est
ce qui met un finding sur la pull request qui l'a introduit, annoté sur la ligne,
devant la personne qui peut le corriger — au lieu d'un tableau de bord qu'elle n'a
aucune raison d'ouvrir. Un sérialiseur de plus à côté d'OpenVEX et du CSV.

Décisions qui séparent un document SARIF *valide* d'un document *utile* :

- **Les problèmes triés partent en `suppressions`, pas à la corbeille.** Les
  retirer ferait qu'à l'envoi suivant la plateforme les redéclare comme nouveaux,
  annulant le travail de triage ; et la suppression transporte la justification VEX,
  donc le relecteur voit *pourquoi* c'était écarté. `affected` n'est pas supprimé :
  décider qu'un problème est réel ne doit pas le cacher.
- **`partialFingerprints` porte l'empreinte Zanshin.** Sans elle, la plateforme
  réidentifie par fichier et ligne, donc un fichier déplacé devient un problème neuf
  *et* un problème résolu. C'est la même identité qui garde le triage attaché d'un
  scan à l'autre.
- **Chaque résultat a une localisation**, avec repli sur la racine du dépôt. GitHub
  écarte silencieusement les résultats sans localisation, et les problèmes de
  dépendances — la majorité — n'ont pas de fichier : une localisation « honnêtement
  vide » aurait signifié qu'ils n'apparaissent jamais.
- **`security-severity` en plus de `level`.** SARIF n'a pas de « critique » ;
  GitHub classe sur cette propriété, pas sur `level`. Sans elle, critique et élevé
  se confondent en « error ».

Effet de bord assumé : `line` ajouté sur `finding` et `issue`. Sans numéro de ligne,
chaque annotation atterrit ligne 1 du fichier, ce qui dans une revue est du bruit.
Volontairement hors empreinte : un secret qui descend de trois lignes reste le même
secret, et re-fingerprinter à chaque reformatage remettrait son triage à zéro.

**F2 — dépendance directe ou transitive.** Toutes les vulnérabilités arrivaient avec
la même quantité d'information sur *quoi faire* : aucune. Un CVE critique dans un
paquet déclaré dans `pyproject.toml` se corrige en changeant une ligne ; le même
quatre niveaux plus bas attend une publication amont, un pin, ou une décision
d'accepter le risque. Classés à l'identique, ils produisent un backlog que personne
ne termine — et les transitifs, largement majoritaires, enterrent la poignée qui est
actionnable aujourd'hui.

Syft répondait déjà et la réponse était jetée. Dans son JSON, une relation
`dependency-of` nomme la dépendance en `parent` et le dépendant en `child` : un
paquet qui n'est jamais `parent` est une racine du graphe, c'est-à-dire quelque chose
que le projet a demandé. Vérifié sur un scan réel de ce dépôt — 545 artefacts,
43 racines, et les racines sont bien les dépendances déclarées (`fastapi`,
`gitpython`, `@radix-ui/themes`, `esbuild`) tandis que les 392 paquets de `bun.lock`
tombent de l'autre côté.

Le point important est le cas où le graphe manque : certains catalogueurs n'émettent
aucune arête, et alors *tout* paraît racine. Étiqueter une image entière
« dépendances directes » serait pire que se taire — une réponse fausse et assurée sur
le champ censé décider quoi corriger en premier. Donc graphe absent ⇒ `NULL` partout,
et l'UI n'affiche rien plutôt qu'une supposition. Même logique pour un paquet absent
du SBOM : inconnu, pas « transitif ».

Vérifié de bout en bout sur un scan réel de conteneur : 53 directes / 368
transitives, avec `openssl` et `openjdk` d'un côté, `openssl-libs` et
`libcurl-minimal` de l'autre. Sur une image, « direct » se lit « paquet installé
volontairement » plutôt que « déclaré dans un manifeste » — c'est le même fait de
graphe, et il reste informatif, mais il est moins actionnable que sur un dépôt (la
correction passe par l'image de base, cf. l'attribution par couche, non faite).

**F3 — expiration des décisions de triage.** `not_affected` n'expirait jamais. C'est
exactement comment les suppressions VEX pourrissent : quelqu'un écarte un problème en
connaissance de cause en janvier, le contexte change en mars, et personne ne le revoit
— ni dans le tableau de bord, ni dans le document VEX remis à un client, ni dans le
gate qu'un pipeline appelle à 3h du matin.

- **Offert, pas imposé.** « Composant absent du produit » n'a pas besoin d'être
  revu ; « pas atteignable dans notre configuration » si. Seule la personne qui
  décide sait laquelle des deux elle vient d'enregistrer. Un délai par défaut aurait
  été une décision de politique déguisée en champ de formulaire.
- **La justification et le commentaire sont conservés** à l'échéance. Les effacer
  transformerait une réexamination programmée en enquête à partir de rien, ce qui est
  la façon la plus sûre de faire cesser de renseigner des dates. `triaged_by` et
  `triaged_at` restent aussi : c'est la trace de qui a dit quoi.
- **Sur le tick de l'ordonnanceur**, pas au chargement de page : une suppression qui
  expire pendant la nuit doit cesser de supprimer même si personne n'ouvre l'écran.
- **Colonne nullable, pas de backfill.** NULL veut dire « jusqu'à nouvel ordre »,
  exactement ce que voulaient dire toutes les décisions existantes. Poser une échéance
  rétroactivement aurait réouvert un backlog du jour au lendemain.

Un défaut trouvé par un test : `expires_in_days=0` était silencieusement traité comme
« sans échéance », parce que `0` est falsy. `None` signifie sans échéance ; `0` ou un
négatif est une erreur d'arithmétique de l'appelant, et l'avaler l'aurait masquée.

### Reste ouvert après cette vague

Atteignabilité réelle (le code vulnérable est-il appelé ?) — F2 en capture une part
pour une fraction du coût, mais pas plus. Attribution par couche pour les conteneurs
(« passer à cette image de base supprime 43 des 61 problèmes »), SAST déterministe
(Semgrep) pour retirer à la revue IA une responsabilité qu'elle ne peut pas porter,
politique de gate stockée et versionnée au lieu d'arriver dans le corps de la requête,
et correction automatique (branche + PR à partir de `extract_remediation`).

## 9decies. La base de données devient réellement configurable (2026-08-06)

`ZANSHIN_DATABASE_URL` existait et était documentée comme *le* moyen de pointer
Zanshin vers une autre base. Le moteur était construit avec
`connect_args={"check_same_thread": False}` sans condition — un argument propre à
SQLite — donc tout autre dialecte échouait à l'import dans le pilote. Le réglage était
réel pour un dialecte et un piège pour les autres : la pire des deux situations, parce
qu'il se présentait comme pris en charge.

**Deux boutons, par ordre de priorité.** `ZANSHIN_DATABASE_URL` pour une URL
SQLAlchemy complète ; `ZANSHIN_DB_PATH` pour un simple chemin de fichier. Le cas
courant mérite le bouton simple : garder les données hors de l'arborescence source ne
devrait pas exiger de connaître la syntaxe des URL SQLAlchemy, et un chemin nu est ce
qu'on écrit correctement du premier coup dans une unité systemd. Le chemin est rendu
**absolu** : un chemin relatif se résout par rapport au répertoire courant, qui n'est
pas le même pour `reflex run`, `alembic` et un service — un réglage, trois bases, et
le symptôme est un tableau de bord vide plutôt qu'une erreur.

**Options de moteur par dialecte**, parce que les deux cas veulent l'inverse l'un de
l'autre : SQLite veut son contrôle inter-threads désactivé (le pool de scan et la
boucle d'événements Reflex touchent le même pool) et un délai d'attente sur verrou ;
une base serveur veut un pool de connexions et `pool_pre_ping`, notions vides pour un
fichier. Le délai d'attente est un ajout : sans lui, deux écritures simultanées
donnent « database is locked » immédiatement, alors que la contention est le régime
normal ici.

**Échouer utilement.** Dialecte inconnu, URL illisible, pilote absent : trois erreurs
distinctes avec un message qui nomme le problème et, pour le pilote, la commande à
lancer. À l'import, pas à la première requête — une faute de frappe dans une variable
doit arrêter l'application, pas ressortir plus tard en requête échouée avec une pile
d'appels interne à SQLAlchemy.

**PostgreSQL et MySQL vérifiés, pas supposés.** Six obstacles réels ont été trouvés
en les faisant tourner, pas en les lisant — et aucun n'était visible depuis SQLite :

1. `GUID` déclarait `impl = BINARY`, rendu littéralement en DDL comme `BINARY` — que
   PostgreSQL refuse (`type "binary" does not exist`), dès la première table de la
   première migration. Le type était donc ce qui séparait « URL configurable » de
   « base configurable ». Il choisit maintenant son implémentation par dialecte :
   `uuid` natif sur PostgreSQL, 16 octets bruts ailleurs — représentation stockée
   inchangée sur SQLite, aucune ligne existante touchée.
2. Les migrations 0003 et 0004 interrogeaient `FROM user` en SQL brut. `user` est un
   mot réservé PostgreSQL, où un `FROM user` non quoté désigne la fonction
   `current_user` : la requête échouait sur « column username does not exist ».
   Reconstruites avec les constructions SQLAlchemy, qui quotent selon le dialecte.
3. `SafeDateTime` déclarait `impl = String` sans longueur. MySQL refuse un `VARCHAR`
   sans longueur — `CompileError` sur la première table. Longueur déclarée à 40, la
   valeur la plus large que la classe puisse produire faisant 32 caractères. SQLite
   ignore la longueur, donc rien ne change pour un déploiement existant.
4. **Toutes** les colonnes de clé étrangère étaient `BigInteger` alors que les clés
   primaires visées sont `Integer`. SQLite ne s'en soucie pas, PostgreSQL le tolère,
   MySQL le refuse net (« Referencing column … are incompatible »). Le défaut a
   traversé six migrations depuis le schéma antérieur à Alembic. Corrigé en
   *rétrécissant* les clés étrangères, pas en élargissant les clés primaires : sur
   SQLite, seule une colonne déclarée exactement `INTEGER PRIMARY KEY` est un alias du
   rowid, donc `BIGINT PRIMARY KEY` cesserait silencieusement de s'auto-incrémenter.
   Migration 0007 pour les bases existantes ; les migrations 0001, 0002 et 0003 ont
   été amendées pour qu'une base *neuve* soit correcte d'emblée — éditer une baseline
   est sans risque justement parce qu'elle ne s'exécute que sur une base neuve.
5. 0003 supprimait `finding.vex_decision_id` sans supprimer d'abord la contrainte de
   clé étrangère. MySQL refuse. Le nom de la contrainte est celui que le serveur a
   choisi (`finding_ibfk_2` ici, `finding_vex_decision_id_fkey` là, rien sur SQLite),
   donc il est cherché par inspection plutôt que deviné.
6. `DROP INDEX IF EXISTS` n'existe pas sur MySQL, et `NULLS LAST` non plus — cette
   dernière dans le *tri applicatif* de la liste des problèmes, pas dans une
   migration. Remplacés par une inspection préalable et par un tri sur
   `colonne IS NULL` (faux avant vrai, donc les valeurs avant les absences).

**Les tests qui l'établissent.** `pytest -m backends` démarre de vrais serveurs
PostgreSQL 16 et MySQL 8.4 avec testcontainers, applique les sept migrations, vérifie
`alembic check` sur chacun, puis fait passer une ligne par chaque type de colonne
maison (GUID, SafeDateTime, JSON) et chaque service qui en possède un — clé SSH
chiffrée liée à son identifiant, clé API avec portées et expiration, chaîne d'audit et
sa détection de falsification, cycle de vie des problèmes, expiration de triage, filtre
de directivité, tri par sévérité, les trois exports, les agrégats du tableau de bord.
36 tests, deux backends. Exclus de l'exécution par défaut : un téléchargement d'image
n'a rien à faire dans la boucle lancée à chaque modification.

Ce que ces tests changent par rapport à une lecture attentive : les six défauts
ci-dessus étaient tous invisibles pour SQLite, dont les types sont dynamiques et qui
ignore les clés étrangères. Aucun n'aurait été trouvé par un mock, une vérification de
chaîne de dialecte ou une relecture. Le seul moyen était d'exécuter.

L'application a aussi été démarrée pour de vrai sur PostgreSQL : elle migre, crée son
compte de bootstrap avec le changement de mot de passe forcé, et sert l'UI comme l'API.

**Deux limites énoncées plutôt que masquées.** Les clés étrangères sont appliquées sur
PostgreSQL et ignorées par SQLite sauf `PRAGMA` explicite ; les cascades de ce schéma
sont côté ORM et `Issue.findings` n'en a aucune, donc une suppression qui laisse
aujourd'hui des orphelins en silence lèverait une erreur là-bas. Activer le `PRAGMA`
aurait été un aller simple vers ce même échec sur SQLite : cela demande des règles
`ondelete`, une migration et ses tests, pas un effet de bord. Et `SafeDateTime` stockait
des chaînes ISO-8601, donc pas d'arithmétique de dates en SQL sur ces colonnes — *levée
depuis*, par la migration `0013` : les horodatages sont de vrais types date sur les trois
moteurs, et les cinq endroits qui chargeaient une table entière pour la filtrer en Python
sont devenus des requêtes.

**`ZANSHIN_AUTO_MIGRATE=false`** pour les déploiements qui migrent comme étape propre
— ce que devrait faire une base serveur répartie sur plusieurs hôtes, puisque le
verrou fichier ne sérialise que les processus d'un hôte. Sauter n'est pas ignorer : le
schéma reste vérifié, et une base en retard sur le code arrête l'application là.

Le verrou de migration a aussi déménagé à côté de la base et non dans l'arborescence
source : ce qui est sérialisé est l'accès à *cette base*, donc deux déploiements
partageant un checkout mais tenant deux bases ne doivent pas se bloquer, et un
checkout en lecture seule ne doit pas empêcher le démarrage.

### Défaut de vérification à signaler

Les vérifications de migration annoncées en 9octies et 9nonies (« base neuve », « base
héritée », « aller-retour ») utilisaient `ZANSHIN_DB_PATH`, qui **n'existait pas
encore** : les commandes `alembic` retombaient donc silencieusement sur la base réelle.
Aucune base neuve n'a été testée à ce moment-là, et l'aller-retour
`downgrade`/`upgrade` a tourné sur la base de développement — il a réussi, et le scan
suivant a repeuplé les colonnes, mais ce n'était pas ce qui était affirmé. C'est
exactement le mode de défaillance que cette section corrige : un réglage qui a l'air
d'avoir pris effet. Les vérifications ont été refaites, avec la variable qui existe
désormais.

## 9undecies. Vague 5 — fermer la boucle côté organisation (2026-08-06)

Trois points de la liste de la vague 4, choisis pour leur rapport valeur/effort.

**G1 — politique de gate stockée et versionnée.** Les règles arrivaient dans le corps
de la requête : elles vivaient donc dans le fichier CI de chaque projet, où celui qui
les trouve trop strictes les assouplit lui-même, et l'équipe sécurité l'apprend jamais.
Le verdict était par ailleurs inauditable — deux appels identiques à un mois d'écart
pouvaient différer, sans trace de pourquoi.

Trois options se présentaient pour la politique encore envoyée par les pipelines
existants : l'ignorer (honnête, casse tout le monde au prochain appel), la laisser
gagner (le trou actuel), ou **la laisser durcir sans jamais assouplir**. La troisième
est implémentée : une équipe peut se tenir à un standard plus élevé que le défaut de
l'organisation, pas à un plus bas. Le champ refusé revient dans
`policy.ignored_relaxations` avec la `source` et la `version` réellement appliquées —
une politique différente de ce qui a été demandé doit se déclarer, pas se substituer en
silence.

Le sens de « plus strict » est défini champ par champ, et c'est là qu'un test a attrapé
une inversion complète : `SEVERITY_ORDER` étant classé du pire au moins grave, un rang
*plus élevé* est un seuil *plus bas*, donc plus strict. Ma première comparaison faisait
l'inverse — elle aurait livré exactement le contraire de la fonctionnalité, un pipeline
libre de relever son seuil à `critical`. `fixable_only` est l'autre piège : à `true` il
échoue sur *moins* de choses, donc `false` est le strict, et c'est le champ le plus
tentant à assouplir puisqu'il tolère silencieusement une faille exploitée sans
correctif.

*Deuxième défaut trouvé par un test :* la contrainte d'unicité sur
`(target_kind, target_id, is_active)` ne protégeait pas la portée globale, stockée en
NULL — SQL considère les NULL comme distincts, donc deux politiques globales actives
passaient, et le verdict aurait dépendu de l'ordre des lignes. La portée globale est
maintenant un sentinelle (`"*"`/`0`), traduit à la frontière du dépôt : moins joli dans
un SELECT, et la seule écriture sous laquelle l'invariant tient réellement, sur les
trois backends.

Pas de notion de *dérogation* au niveau de la politique (« ignorer CVE-X jusqu'en
juin ») : ça existe déjà, dans le bon vocabulaire et avec une date de révision — le
triage `not_affected` de la vague 4. Un second mécanisme de suppression signifierait
deux endroits à consulter quand un finding n'arrive pas à faire échouer un build.

**G2 — création de tickets (GitLab, Jira).** SARIF a fermé la boucle vers le
développeur ; ceci la ferme vers l'organisation. Deux décisions ont façonné le code :

- **Piloté par la politique de gate, pas par un second seuil.** « Ouvrir un ticket pour
  ce qui ferait échouer un build » se raisonne, et il n'existe alors qu'un seul endroit
  où « assez grave pour agir » est défini. Un `ticket_min_severity` aurait créé deux
  vocabulaires qui divergent, et le premier rapport de bug serait « pourquoi ça a fait
  un ticket mais pas échouer le build ».
- **Un balayage, pas un événement.** Les notifications partent en ligne après un scan ;
  les tickets non. Un balayage sur « problèmes actionnables sans ticket » est idempotent
  par construction — la référence posée sur le problème *est* la clé de déduplication —
  donc un gestionnaire en maintenance est simplement réessayé au tick suivant. C'est
  aussi pourquoi aucun outbox n'est nécessaire ici : l'état à réconcilier est déjà une
  colonne. Un ticket par problème, posé une fois pour toute sa vie : un ticket qui
  ressuscite à chaque rescan est la façon la plus sûre de faire couper les notifications
  d'un projet.

Le jeton passe par `EncryptionService` comme une clé SSH : il donne un droit d'écriture
sur le gestionnaire, ce qui n'est pas la même classe de secret qu'une URL de webhook.
Un champ vide au formulaire conserve le jeton stocké, sinon changer le nom du projet
désactiverait silencieusement les tickets.

**G3 — détection de fin de vie (endoflife.date).** Une classe de risque entière sans
CVE : une exécution hors support ne recevra pas de correctif pour la *prochaine*
vulnérabilité, quelle qu'elle soit. Deux chemins d'appariement, parce que la réponse est
à deux endroits dans un SBOM Syft :

1. **La distribution**, depuis le bloc `distro` (`id`, `versionID`). C'est la réponse la
   plus utile pour une image et celle qu'aucune recherche par paquet ne trouverait :
   c'est le système de l'image de base, pas un paquet dedans.
2. **Les paquets**, appariés par purl contre l'index d'identifiants d'endoflife.date —
   une requête rend environ 940 correspondances purl → produit, donc aucune table de
   correspondance à maintenir et aucune à pourrir.

La couverture est volontairement partielle, et le dire compte : le catalogue suit des
*produits* (langages, exécutions, frameworks, bases, distributions), pas chaque
bibliothèque. Une image de 131 paquets en appariera une poignée. C'est le bon périmètre,
parce que « fin de vie » est une propriété de plateforme ; le risque d'une bibliothèque
donnée est ce que les scanners de vulnérabilités répondent déjà.

*Deux détails qui auraient été des bugs silencieux :* l'appariement de cycle se fait
composante par composante et non par préfixe de chaîne — « 3.14 » commence par « 3.1 »,
donc un préfixe aurait classé Python 3.14 dans le cycle 3.1, fin de vie 2012, et déclaré
morte une exécution supportée. Et la déduplication porte sur le *cycle*, pas sur la
version : une image liste la même exécution comme distribution et comme paquet, en
« 3.9 » et « 3.9.1 », et la fin de vie était rapportée deux fois.

### Vérifications

704 tests sur SQLite (85 % de couverture), 36 sur PostgreSQL 16 et MySQL 8.4. Migration
0008 vérifiée sur base neuve, base héritée et aller-retour. En conditions réelles sur
l'application lancée : le gate répond avec la politique intégrée sur une table vide,
puis la politique de la cible prime sur la globale, puis une requête tentant
`fail_on_severity: critical` et `fail_on_kev: false` se voit appliquer `low` avec les
deux champs listés en refus. Un faux GitLab local a reçu six tickets avec le bon jeton
et le bon titre, et un balayage de 50 derrière a laissé les 6 références intactes — 56
problèmes ticketés, 56 références distinctes. La détection de fin de vie a été passée
contre l'API réelle : `rhel 7.9`, `python 3.9.18` et `django 3.2.1` sont signalés avec
la version recommandée, `rhel 9.7` ne l'est pas.

Les données de ce test de bout en bout (56 références, 2 politiques, 5 réglages) ont été
retirées de la base de développement : elles pointaient vers un GitLab local et le jeton
avait été chiffré avec une clé jetable.

## 9. Prochaines étapes immédiates

1. ~~Valider le schéma de la table `Finding` et son articulation avec `VexDecision`.~~ Fait en vague 2 : `Issue` supersède `VexDecision` (voir 9quater).
2. ~~Choisir un vrai outil de migration (Alembic recommandé).~~ Fait en vague 2.
3. Vérifier de bout en bout le service `scan-api/` (Dockerfile, versions d'outils) sur une infrastructure disposant de Docker/réseau externe.
4. Valider en conditions réelles la revue de code par IA (temps de réponse Ollama sur un vrai dépôt, qualité perçue des retours, fiabilité du modèle à respecter le format JSON demandé).
5. ~~Dérive de schéma héritée~~ — traitée en vague 3 (migration 0004) pour `user`, `repository`, `container` et `scan`. Restent `api_key` et `audit_logs`, dont seuls les types d'horodatage divergent (sans effet sur SQLite) : les tables créées par l'implémentation précédente n'ont pas les index et contraintes d'unicité que déclarent les modèles, et leurs colonnes d'horodatage sont typées `TIMESTAMP` au lieu de `SafeDateTime` (sans effet sur SQLite). Détecté en écrivant la migration `0002`, délibérément non corrigé là : réécrire des tables peuplées pour ajouter des contraintes est une opération à décider en tant que telle, pas un effet de bord. Une migration dédiée à prévoir — notamment l'unicité de `user.username`, qui n'est aujourd'hui garantie que par le code applicatif.
6. ~~Exporter les décisions de triage en document VEX.~~ Fait en vague 3.
7. ~~API HTTP et *policy gate*.~~ Fait en vague 3.
8. Traiter les secrets présents dans l'historique git (cf. 9ter, point 4) : les bases retirées de l'index y figurent toujours. Considérer les mots de passe et clés SSH concernés comme compromis (rotation), puis décider si l'historique doit être réécrit (`git filter-repo`) ou si le dépôt reste privé et l'on s'en tient à la rotation.
