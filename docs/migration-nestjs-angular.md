# Migration de Zanshin vers NestJS + Angular

**Statut : en cours.** Branche `claude/migration-nestjs-angular`. Le plan ci-dessous reste
la référence ; cette section dit où l'on en est.

## Avancement

| Lot | État | Ce qui est fait |
|---|---|---|
| 0 — Socle | **terminé** | Monorepo npm, NestJS 11 + Angular 21 (Sakai converti vers Optimus UI), trois jobs CI, vérification des ressources tierces |
| 1 — Socle NestJS | en cours | Chaîne d'intégrité du journal d'audit, format d'horodatage Python, correctif du pilote PostgreSQL, harnais de parité de schéma, entités `user` / `audit_logs` / `setting` |
| 2 — Cœur métier | en cours | Empreinte des problèmes, verdict du gate et durcissement de politique, exports SARIF / OpenVEX / CSV |
| 3 — API d'administration | à faire | |
| 4 — File de scans et agents | à faire | |
| 5 — Interface Angular | à faire | Seule la coquille existe |
| 6 — Bascule | à faire | |

**Prochaines étapes, dans l'ordre :** les treize entités restantes (le harnais rend
l'exercice mécanique et sûr), puis `sync_from_scan`, qui est le premier morceau à
*écrire* dans la base, puis l'authentification.

Reste entièrement à faire, et c'est l'essentiel du coût : les 9 150 lignes de services,
l'API d'administration, et le portage des 17 970 lignes de tests.

## Le banc différentiel, tel qu'il existe aujourd'hui

C'est la pièce qui rend la réécriture vérifiable, et elle est en place.

`scripts/generate_parity_vectors.py` produit, **depuis le code Python réel**, les
valeurs que la pile TypeScript doit reproduire. Les fichiers atterrissent dans
`backend/test/vectors/` et sont commités, la CI TypeScript n'ayant pas d'interpréteur
Python. Deux garde-fous encadrent ce dispositif :

* `tests/test_parity_vectors.py` vérifie que les fichiers commités correspondent
  encore à ce que produit le code Python d'aujourd'hui, et que les fonctions recopiées
  dans le générateur n'ont pas dérivé de leurs originales ;
* les suites Jest les rejouent.

Le jour où quelqu'un modifie une formule côté Python, c'est la suite TypeScript qui le
dit. Recopier les valeurs à la main aurait figé un instantané.

| Vecteurs | Contenu | Généré par |
|---|---|---|
| `audit-hash.json` | 5 entrées de journal et leur empreinte | copie vérifiée de `compute_entry_hash` |
| `python-timestamp.json` | 7 horodatages, isoformat et rendu PostgreSQL | `datetime.isoformat()` |
| `issue-fingerprint.json` | 8 empreintes de problèmes | copie vérifiée de `build_fingerprint` |
| `policy-gate.json` | 20 verdicts, 14 durcissements | **le vrai `policy_gate.evaluate`**, importé |

Quand le code Python s'importe sans ouvrir de connexion — c'est le cas de
`policy_gate` — le générateur importe l'original plutôt que d'en recopier la logique.
Quarante lignes de règles imbriquées se recopient mal ; cinq lignes de hachage se
recopient bien, et la copie est alors confrontée à l'originale par un test.

## Ce que le chantier a déjà appris

Quatre choses trouvées en construisant, dont trois n'auraient pas été trouvées en
lisant :

1. **`node-postgres` casse les horodatages deux fois.** Il rend un `Date`, qui perd la
   microseconde, et applique le fuseau de la machine à une colonne sans fuseau
   contenant de l'UTC. La chaîne d'audit se serait déclarée falsifiée sur tout
   l'historique. Correctif dans `backend/src/database/pg-types.ts`, vérifié contre un
   PostgreSQL réel.
2. **`datetime.isoformat()` n'a aucun équivalent JavaScript** — trois écarts avec
   `toISOString()`, chacun suffisant à casser un hachage.
3. **`primeicons@8` n'est plus MIT.** Épinglé en `7.0.0` exact.
4. **Sakai chargeait une police depuis un CDN**, ce que la CSP de Zanshin refuse — le
   piège qui avait déjà tué la typographie côté Reflex. `frontend/scripts/check-assets.mjs`
   le refuse désormais.

Et deux défauts du code Python, corrigés au passage : `ScanRepository.count_by_queue_state`
levait un `NameError` à chaque appel, et `AgentJobService.build_task` omettait `run_sast`,
si bien qu'aucun agent distant n'exécutait jamais Semgrep.

---

## 1. Contexte

Zanshin est aujourd'hui une application Python : interface Reflex, API FastAPI montée sur
la même ASGI, SQLAlchemy + Alembic, et une couche d'exécution de scans qui pilote des
conteneurs Docker. Elle fonctionne.

Ce qui motive le déplacement n'est pas un défaut de Python — l'analyse de la pile menée
en amont a conclu que Python est le bon langage pour ce domaine — mais **Reflex** :

* l'état d'un client vit sur l'instance qui a accepté sa socket, donc une deuxième
  instance web exige Redis (`state_manager_mode`), et `startup_guard.py` existe pour
  refuser au démarrage les déploiements que cela casse ;
* quatre pannes CSS silencieuses en un après-midi, dont une typographie morte deux fois
  (refus CSP *et* variable Radix écrasée) ;
* le typage ne traverse pas la frontière Python/JS : `.get("critical", 0)` sur une
  dataclass, `r["findings"] == "0"` comparé à une chaîne.

Le choix retenu est un front Angular (Sakai + Optimus UI) et un back NestJS, pour n'avoir
qu'un seul langage de bout en bout et une API qui existe vraiment.

### Ce que cela coûte, mesuré

| Couche | Lignes Python | Sort |
|---|---:|---|
| `tests/` | **17 970** (1 015 tests) | à réécrire |
| `zanshin/services/` | 9 150 | à porter |
| `zanshin/ui/` | 8 380 | à remplacer |
| `migrations/` | 2 105 (15 révisions) | **conservé** |
| `zanshin/models/` + `repositories/` | 2 498 | à porter |
| `zanshin/api/` | 1 511 | à porter |
| `zanshin/agent/` | 666 | **conservé, en Python** |
| Racine `zanshin/*.py` | 1 275 | à porter |
| `scan-api/` | 229 | à supprimer (déjà redondant) |
| **Total** | **44 008** | |

Le chiffre qui commande le calendrier : **les tests sont 41 % du projet**, soit 1,72 ligne
de test par ligne de service. Ils n'encodent pas des trivialités — ils encodent le cycle
de vie du triage, l'empreinte des problèmes, la réclamation transactionnelle, et six
défauts de portabilité qui étaient invisibles à la lecture comme sur SQLite. Une migration
qui les abandonne repart sans filet précisément là où le code est subtil.

**Estimation honnête : environ six mois à une personne à plein temps**, hors imprévu. La
majeure partie n'est pas l'interface — c'est le portage du métier et la reconstruction du
harnais de tests.

---

## 2. La décision structurante : ce qu'on ne réécrit pas

> **L'exécution des scans reste en Python. Le protocole d'agent est la couture.**

C'est le cœur de ce plan, et ce qui le rend faisable.

`zanshin/scan_contract.py` n'importe **rien** de Zanshin — deux modèles Pydantic et une
version :

```python
CONTRACT_VERSION = "1"
class ScanTask(BaseModel):    # scan_id, kind, repo_url, branch, sub_path,
    ...                       # ssh_private_key?, image?, collect_code_sample, run_sast
class ScanArtifacts(BaseModel):  # sbom, cves, secrets, iac?, sast?, code_sample,
    ...                          # duration_ms, log
```

Et `zanshin/agent/` parle déjà à un plan de contrôle par **quatre routes HTTP** :

| Route | Rôle |
|---|---|
| `POST /api/v1/agent/hello` | enregistrement, vérification de `CONTRACT_VERSION` |
| `GET /api/v1/agent/jobs` | long-polling : réclame une `ScanTask` |
| `POST /api/v1/agent/jobs/{id}/heartbeat` | renouvelle le bail |
| `POST /api/v1/agent/jobs/{id}/result` | rend les `ScanArtifacts` |

`Dockerfile.agent` prouve l'indépendance : l'image n'installe que `httpx`, `pydantic`,
`docker`, `gitpython` — ni Reflex, ni SQLAlchemy, ni Alembic — et un test vérifie
l'invariant d'import.

**Conséquence :** NestJS n'a qu'à implémenter ces quatre routes pour que l'agent Python
existant continue de fonctionner sans être modifié. On ne réécrit donc **ni** `docker_engine.py`
(498 lignes de durcissement de conteneurs, images épinglées par digest, réseau coupé,
limites mémoire/pids), **ni** `scan_runner.py`, **ni** les règles Semgrep, **ni** l'intégration
Syft/Grype/gitleaks/checkov.

C'est aussi le morceau où TypeScript n'apporterait rien : le SDK Docker Node est moins
mûr que son homologue Python, et la valeur de ces 1 500 lignes est dans des réglages
durement acquis, pas dans leur langage.

**Ce qu'on perd :** le déploiement mono-processus. Aujourd'hui le serveur web scanne
lui-même via un « agent intégré ». Demain il faut au moins un conteneur agent à côté.
C'est un vrai changement d'exploitation, à documenter — et c'est aussi ce qui débarrasse
enfin le processus exposé aux utilisateurs du socket Docker.

---

## 3. Architecture cible

```
┌─────────────────────┐     HTTPS      ┌──────────────────────────────┐
│  Angular 22         │ ─────────────▶ │  NestJS  (plan de contrôle)  │
│  Sakai + Optimus UI │  OpenAPI       │  ─ REST + OpenAPI            │
└─────────────────────┘  généré        │  ─ TypeORM (schéma Alembic)  │
                                       │  ─ file de scans, baux       │
                                       │  ─ cycle de vie des problèmes│
                                       │  ─ gate, exports SARIF/VEX   │
                                       └──────┬───────────────────────┘
                                              │ 4 routes /api/v1/agent
                                              │ (contrat inchangé, v1)
                                       ┌──────▼───────────────────────┐
                                       │  Agent Python  (inchangé)    │
                                       │  ScanRunner + docker_engine  │
                                       │  syft grype gitleaks checkov │
                                       │  semgrep                     │
                                       └──────────────────────────────┘
```

* **PostgreSQL seul.** Abandonner SQLite au passage supprime `supports_skip_locked`,
  `_claim_conditional`, une partie de `startup_guard.py`, et les types maison `GUID`
  (→ `uuid` natif) et `SafeDateTime` (→ `timestamp` natif). C'est la simplification la
  plus rentable du chantier. Elle a un prix : le démarrage « un fichier, zéro
  dépendance » disparaît.
* **Le schéma ne bouge pas.** TypeORM en `synchronize: false` lit les tables telles que
  les 15 révisions Alembic les ont faites. Alembic reste propriétaire du schéma pendant
  toute la migration ; on ne bascule vers les migrations TypeORM qu'à la toute fin, si on
  le fait.
* **Sessions.** Le code Python distingue déjà deux familles : services dont la session est
  portée par leurs repositories, et services recevant `db` en paramètre (`issue_service`,
  `scan_queue`, `scheduler`, `scan_ingestor`…). Cette frontière se transpose directement :
  providers NestJS singletons, `EntityManager` passé explicitement pour la seconde famille.

---

## 4. Le harnais qui rend la réécriture survivable

Avant d'écrire une ligne de NestJS, construire un **banc de comparaison différentielle**.
C'est la seule chose qui transforme « on a réécrit 44 000 lignes » en « on a vérifié qu'on
a réécrit 44 000 lignes ».

Zanshin s'y prête exceptionnellement bien : ses sorties les plus critiques sont
**déterministes et sérialisables**.

| Sortie | Comment on la compare |
|---|---|
| `build_fingerprint` | même entrée → même SHA-256, octet pour octet |
| Verdict du gate | `POST /api/v1/gate` sur les mêmes cibles → même verdict, même règle en cause |
| Export SARIF | document JSON normalisé puis diffé |
| Export OpenVEX | idem |
| Export CSV | idem, 25 colonnes |
| `sync_from_scan` | même scan rejoué → mêmes `new_issues_count`/`resolved_issues_count`, mêmes états |

Mécanique : une base PostgreSQL peuplée d'un jeu de données réaliste, les deux plans de
contrôle branchés dessus en lecture, un script qui appelle les deux et diffe. Il tourne en
CI à chaque lot. Un écart est un défaut, pas une interprétation.

C'est aussi ce qui permet de **ne pas porter les 1 015 tests d'un bloc** : les tests qui
décrivent un comportement observable sont remplacés par le diff ; seuls ceux qui décrivent
une mécanique interne (concurrence de la réclamation, migrations, portabilité) doivent
être réécrits pour de bon.

---

## 5. Les lots

Chaque lot se termine sur un point d'arrêt : quelque chose de vérifiable, et la possibilité
d'abandonner sans avoir rien cassé.

### Lot 0 — Préparation (≈ 1 semaine)

* **Bloquant immédiat :** Node 25.2.1 est refusé par Angular (`Node.js : 25.2.1
  (Unsupported)`). Passer en Node 22 ou 24 LTS.
* Vérifier que le Nexus Civadis proxifie tout (déjà confirmé : `@openng/optimus-ui@1.0.1`,
  `@openng/optimus-ui-themes@1.0.1`, `@angular/core@22.1.1`).
* Créer `frontend/` (Angular) et `backend/` (NestJS) à la racine, en monorepo npm workspaces.
* Brancher Zanshin sur son propre `package-lock.json` dès le premier commit — c'est
  l'outil, autant qu'il se surveille lui-même. npm produit un arbre transitif d'un ordre
  de grandeur supérieur à `uv.lock` ; c'est le vrai coût du choix TypeScript.
* Décider PostgreSQL-seul, et l'écrire dans une décision d'architecture.

**Point d'arrêt :** deux squelettes qui démarrent, CI verte, rien de métier.

### Lot 1 — Socle NestJS (≈ 3–4 semaines)

* Entités TypeORM calquées sur `zanshin/models/`, `synchronize: false`, pointées sur une
  base construite par `alembic upgrade head`. Un test qui échoue si une entité et le
  schéma divergent — l'équivalent d'`alembic check`.
* Authentification : sessions, rôles (`SUPERUSER`/`ADMIN`/`USER`), gardes NestJS reprenant
  la sémantique de `requires_login`/`requires_admin`. **À poser sur les endpoints**, comme
  aujourd'hui ils sont posés sur les handlers et non sur le rendu.
* `bcrypt` (paquet Node du même nom, compatible avec les empreintes existantes → les mots
  de passe survivent).
* Anti-bourrage (`login_throttle`, 5/utilisateur et 20/client sur 15 min) et `counter_store`
  mémoire/Redis.
* Journal d'audit **chaîné par hash** : `compute_entry_hash` doit produire exactement les
  mêmes empreintes, sinon `verify_chain()` déclare l'historique falsifié.
* Anti-SSRF (`url_guard`) : à porter tel quel, y compris la résolution DNS et les plages
  privées.

**Point d'arrêt :** on peut se connecter à NestJS avec un compte existant, et le journal
d'audit se vérifie bout à bout, y compris sur les lignes écrites par Python.

### Lot 2 — Le cœur métier (≈ 4–5 semaines)

Le plus délicat, et celui qui bénéficie le plus du banc de comparaison.

* `build_fingerprint` — SHA-256 de `repo:{id}|type|identifier|purl-ou-nom|file_path`.
  Trivial à écrire, **contractuel** à respecter (§6).
* `sync_from_scan` — regroupement par empreinte, une seule requête `IN`, création /
  réouverture / rafraîchissement partiel (ne jamais écraser une valeur acquise par un
  `None`), résolution des disparus **limitée aux types réellement scannés**, hook
  `before_commit` dans la même transaction que l'outbox.
* `policy_gate.evaluate` — fonctions pures, portage direct. Attention à `unknown` classé
  **sous** `low`, et à l'exclusion inconditionnelle des types `quality`.
* `gate_policy_service.resolve` — cible > global > built-in, avec `harden`.
* `exports.py` — SARIF (suppressions plutôt qu'omissions, `partialFingerprints`, une
  location obligatoire par résultat, `security-severity` numérique), OpenVEX, CSV.
* `issue_service.triage` + `expire_stale_triages`.

**Point d'arrêt :** le banc différentiel est vert sur empreintes, verdicts et trois
formats d'export, sur un jeu de données réel.

### Lot 3 — API d'administration (≈ 4–6 semaines)

C'est le lot qui n'existe pas aujourd'hui : l'API actuelle est une API de CI (18 routes,
lecture seule + gate + exports + protocole d'agent). L'interface, elle, appelle les
services directement — **59 `get_container()`** dans `zanshin/ui/pages/`, dont 20 pour la
seule page Paramètres.

Il faut donc écrire les endpoints de : dépôts, conteneurs, clés SSH, utilisateurs, clés
API, agents, triage, politiques de gate, tickets, journal d'audit, et les treize
sous-domaines de réglages.

**Ce travail a de la valeur même si la migration s'arrête là** : il donne enfin un
consommateur aux clés API, permet le provisionnement et les tests de bout en bout.

* `@nestjs/swagger` produit l'OpenAPI ; le client Angular s'en génère.
* Conserver les 18 routes existantes **à l'identique** — elles ont des consommateurs
  externes (barrières CI, `issues.sarif` téléversé dans GitHub code scanning).

**Point d'arrêt :** OpenAPI complet, client TypeScript généré, tests d'API sur chaque
route.

### Lot 4 — File de scans et protocole d'agent (≈ 3–4 semaines)

* Réclamation transactionnelle : `SELECT … ORDER BY created_at, id LIMIT n FOR UPDATE
  SKIP LOCKED` puis passage à `scanning` **dans la même transaction**. PostgreSQL-seul
  supprime la variante conditionnelle SQLite.
* Baux (1 200 s), renouvellement filtré sur `claimed_by`, `still_owned` vérifié avant
  ingestion, `reclaim_expired_leases`, `MAX_ATTEMPTS=3` avant échec définitif.
* Les quatre routes `/api/v1/agent/*`, à l'identique, contrat v1.
* Inbox d'idempotence (`processed_message`) — sans elle, un renvoi d'agent gonfle
  `times_seen`.
* Ordonnanceur : bail de leader (`leader_lease`, une ligne par job), tick, cron des cibles,
  relais outbox avec backoff exponentiel, balayage des tickets, rétention.

**Point d'arrêt :** l'agent Python **existant, non modifié** réclame un scan auprès de
NestJS, l'exécute et rend ses artefacts ; le problème apparaît dans la base avec la bonne
empreinte. C'est le jalon le plus important du chantier.

### Lot 5 — Interface Angular (≈ 6–8 semaines)

Quinze écrans, inventoriés page par page (routes, état, handlers, dialogues) dans
l'analyse préparatoire.

* Base Sakai (MIT, Angular 21) + `ng generate @openng/optimus-ui:migrate-from-primeng`,
  puis montée en Angular 22.
* Design system partagé d'abord, car il porte tout le reste : `stat-card`, `severity-bar`
  (la barre segmentée proportionnelle), `status-badge`, `severity-donut`, `empty-state`,
  `count-badge`, `delta-badges`, `severity-summary`.
* Les `view_models.py` (`IssueRow`, `PostureRow`, `ScanRow`, `TallyRow`…) sont déjà la
  spécification des DTO : ce sont eux qui deviennent les interfaces TypeScript, générées
  depuis l'OpenAPI.
* Ordre conseillé, du plus simple au plus lourd : Connexion → Journal d'audit →
  Utilisateurs → Clés SSH → Clés API → Qualité → Sécurité → Tableau de bord → Conteneurs →
  Agents → Problèmes → Dépôts → Paramètres.
* **Découper Paramètres.** C'est aujourd'hui 1 720 lignes et une seule classe d'état pour
  treize sous-domaines indépendants. Le porter tel quel serait reproduire le défaut.
* **Corriger au passage un défaut connu :** les liens `/issues?repo_id=`, `?container_id=`
  et `?type=quality` sont générés par les pages Sécurité et Qualité mais **aucune page ne
  les lit** — la couche UI actuelle n'utilise nulle part les paramètres d'URL. En Angular
  c'est le comportement naturel du routeur ; autant que le filtre marche enfin.

**Point d'arrêt :** parité fonctionnelle écran par écran, vérifiée contre l'application
Reflex encore en service.

### Lot 6 — Bascule et retrait (≈ 2 semaines)

* Les deux plans de contrôle tournent en parallèle sur la même base, NestJS en lecture
  seule d'abord.
* Bascule des écritures, puis arrêt de Reflex.
* Suppression de `zanshin/ui/`, `zanshin/api/`, `zanshin/services/` — en gardant
  `zanshin/agent/`, `zanshin/scan_contract.py`, `zanshin/services/scan_runner.py`,
  `zanshin/services/scanners/`, `zanshin/services/git_url.py` : exactement ce que
  `Dockerfile.agent` copie déjà.
* Décision à prendre alors seulement : garder Alembic (il marche, il est testé) ou
  basculer sur les migrations TypeORM.

---

## 6. Les cinq pièges qui détruisent des données

À traiter comme des invariants, pas comme des détails d'implémentation.

1. **L'empreinte est un contrat de données.** SHA-256 de
   `repo:{id}|{type}|{identifier}|{purl ou nom}|{file_path}`. Elle exclut délibérément la
   **version** du paquet, `is_direct_dependency` et la **ligne**. Une divergence d'un seul
   octet — un séparateur, un ordre, une casse — relance **tout** le backlog comme
   « nouveau » et détruit chaque décision de triage. À verrouiller par un test à vecteurs
   fixes avant d'écrire quoi que ce soit d'autre.

2. **`_derive()` du chiffrement doit être reproduit octet pour octet.** `encryption_service.py`
   ne dérive pas la clé par KDF : il **tronque à 32 octets ou complète avec des NUL**.
   C'est délibéré — changer la dérivation rendrait indéchiffrable tout l'existant. Il faut
   aussi reproduire AES-GCM **et l'AAD contextuelle** (`private_key_context(key_id)`), qui
   est ce qui empêche de recopier le blob chiffré de la clé SSH A dans la ligne B pour
   cloner le dépôt A avec la clé de B. Et le repli sans AAD pour les valeurs antérieures,
   et la rotation multi-clés (`ZANSHIN_PREVIOUS_ENCRYPTION_KEYS`).

3. **`None` n'est pas `[]`.** Dans `ScanArtifacts`, `[]` signifie « l'analyse a tourné et
   n'a rien trouvé » — ce qui **résout** les problèmes correspondants ; `None` signifie
   « elle n'a pas tourné » — le backlog reste intact. La même distinction gouverne
   `scanned_types_for`. Un portage qui normalise les `None` en listes vides résout
   silencieusement des centaines de problèmes de sécurité, sans erreur nulle part.
   Le typage TypeScript aide ici, à condition de ne pas activer une désérialisation qui
   remplit les défauts.

4. **La chaîne du journal d'audit.** `compute_entry_hash` doit produire les mêmes valeurs,
   sinon `verify_chain()` déclare falsifié tout l'historique écrit par Python. C'est
   exactement le mode de panne qui avait fait retirer MySQL (troncature `DATETIME` à la
   seconde). Vérifier la chaîne complète après bascule fait partie de la définition de
   « terminé ».

5. **L'outbox et les problèmes partagent une transaction.** Le hook `before_commit` de
   `sync_from_scan` n'est pas une commodité : la notification doit devenir durable au même
   instant que ce qu'elle décrit. En TypeORM, cela veut dire une transaction interactive
   explicite, pas deux appels successifs.

---

## 7. Vérification

Un lot n'est fini que si :

1. `npm test` (backend et frontend) est vert ;
2. le **banc différentiel** est vert sur son périmètre — empreintes, verdicts de gate,
   SARIF/VEX/CSV, compteurs de `sync_from_scan` ;
3. les tests multi-backends conservent leur équivalent : PostgreSQL réel via
   testcontainers, réclamation concurrente sous charge (c'est le test qui prouve que
   `SKIP LOCKED` fait ce qu'on croit) ;
4. un vrai scan Docker de bout en bout passe : l'agent Python réclame, exécute, rend ; les
   problèmes créés ont les bonnes empreintes ; relancer le même scan incrémente
   `times_seen` sans créer de doublon **ni perdre un triage** ;
5. `verify_chain()` du journal d'audit passe sur l'historique complet, Python inclus.

---

## 8. Risques, énoncés

* **Optimus UI est en 1.0.1**, fork communautaire de PrimeNG v21 né du passage de PrimeTek
  en licence commerciale. Le choix de licence est le bon — MIT, redistribuable, cohérent
  avec un projet open source — mais l'interface s'adosse à un projet jeune. Repli
  raisonnable si le fork s'essouffle : Angular Material, au prix d'un retour sur Sakai.
* **Sakai est un template PrimeNG**, converti vers Optimus par schematic. La conversion
  est mécanique mais n'est pas garantie sans reprise.
* **L'arbre de dépendances npm** est d'un ordre de grandeur supérieur à `uv.lock`. Pour un
  outil de sécurité, c'est un point à assumer explicitement — et à instrumenter dès le
  lot 0.
* **Six mois sans nouvelle fonctionnalité.** C'est le vrai coût. Un plan qui l'ignore n'est
  pas un plan.
* **Le point de non-retour est le lot 4**, pas le lot 6 : dès que NestJS distribue le
  travail aux agents, revenir en arrière demande de resynchroniser les états de scan.

---

## 9. Ce qu'on peut décider de ne pas faire

Deux sorties honorables, à garder en tête :

* **S'arrêter après le lot 3.** On obtient une API d'administration complète, testée, avec
  son OpenAPI — utile en soi, consommable par des scripts — et l'interface Reflex continue
  de tourner devant. C'est le meilleur rapport valeur/risque du document.
* **Ne faire que le lot 5, contre l'API du lot 3.** Angular devant, Python derrière. On
  règle le problème réellement diagnostiqué (Reflex), sans réécrire 20 000 lignes de métier
  qui, elles, ne posent pas de problème.

La migration complète vers NestJS ne se justifie que par l'unification du langage. C'est un
argument réel — un seul écosystème, un seul profil de développeur pour reprendre le projet —
mais il faut le peser contre six mois et 1 015 tests.
