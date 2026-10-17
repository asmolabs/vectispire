# Plan : porter le plan de contrôle en Rust

**Date :** 2026-10-16 · **Statut :** proposition, aucun code · **Périmètre :** `vectispire-core` et la
partie de `vectispire-common` que le portage de l'agent ne couvre pas déjà · **Schéma et contrat visés :**
la ligne 0.11.1 (`release/0.11.1-merge` b8bd7e8d0 : Flyway V1–V91, `openapi.json` à 245 chemins)

Ce plan est l'étape d'avant le code. Il mesure ce qu'il y a à porter, fixe ce qui ne doit pas changer,
choisit les bibliothèques, retient une stratégie de migration et un oracle de test, et finit par les listes
de tâches des phases 0, 1 et 2 que des agents en parallèle peuvent exécuter. Il s'appuie sur l'étude
de l'agent (« Étude : porter l'agent distant en Rust », 2026-10-16, branche `docs/rust-agent-study`) et
sur le portage de l'agent en cours dans `vectispire-rust/` (branche `feat/rust-agent` : crates `agent`,
`protocol`, `crypto`, `git`, `container`, `scanners`, `domain`, `tls`, `testkit`). Le plan de contrôle
rejoint cet espace de travail.

## 0. Ce qui avait été décidé, et pourquoi c'est différent

Le 2026-09-10, un portage de ce backend en NestJS a été chiffré à **53 à 69 semaines-développeur** et
abandonné le jour même. Deux propriétés de sécurité sont tenues ici par le compilateur : l'isolement de
l'agent vis-à-vis de la base par le graphe de build
([0003](../../architecture/fr/decisions/0003-long-polling-for-agents.md)), et les couches vérifiées sur
le graphe d'imports. En Node, toutes deux se dégradent en conventions. Le code Java est lui-même le
portage d'une implémentation NestJS antérieure, dont le registre des décisions consigne les défauts.

Rust lève cette objection. Les frontières de crate et `pub(crate)` tiennent ce que les modules Gradle,
ArchUnit et Spring Modulith tiennent aujourd'hui, au moins aussi strictement, et à la compilation plutôt
que dans un test. **Ce qui ne change pas, c'est le coût.** Le backend est gros, sa valeur est dans ses
tests et son registre des décisions, et chaque défaut qu'ils consignent doit être reporté plutôt que
redécouvert. L'estimation ci-dessous est plus élevée que celle de NestJS, pas plus basse.

## 1. Inventaire (mesuré sur b8bd7e8d0)

Les lignes sont les lignes Java non vides et hors commentaires. Ce code est volontairement très
commenté ; les commentaires portent un raisonnement que le portage doit garder.

### 1.1 Taille

| | Fichiers principaux | Lignes principales | Fichiers de test |
|---|---|---|---|
| `vectispire-core` | 778 | 66 236 | 383 (+49 d'intégration) |
| `vectispire-common` | 336 | 26 749 | 192 |
| `vectispire-agent` (en cours de portage) | 7 | 1 006 | 9 |
| `vectispire-report-demo` (un plugin, non porté) | 5 | 590 | 3 |

Environ 6 400 lignes de `vectispire-common` sont déjà atteintes par le portage de l'agent (clone,
lanceur de conteneurs, cinq scanners et leurs analyseurs, cryptographie). **Le portage du plan de
contrôle fait donc environ 86 000 lignes.**

Les tests, tels que Gradle les compte sur la ligne 0.11.1 : core 2 338, common 2 093, agent 80, et
`integrationTestAll` 171 sur MySQL comme sur PostgreSQL. 172 des fichiers de test de core utilisent
**MockMvc** : ils tournent dans le processus et ne sont pas neutres vis-à-vis du langage (voir §4.3).
Seuls 2 démarrent un vrai serveur.

### 1.2 Modules de `core`

| Module | Fichiers | Lignes | | Module | Fichiers | Lignes |
|---|---|---|---|---|---|---|
| access | 101 | 7 010 | | posture | 19 | 2 454 |
| checklists | 77 | 6 882 | | threatintel | 25 | 1 852 |
| forges | 50 | 5 306 | | agents | 17 | 1 929 |
| issues | 46 | 5 191 | | gate | 18 | 1 612 |
| compliance | 51 | 4 615 | | tickets | 18 | 1 589 |
| scanning | 52 | 4 443 | | exports | 12 | 1 400 |
| targets | 46 | 3 947 | | platform | 13 | 1 140 |
| reportplugins | 48 | 3 593 | | rules | 14 | 992 |
| inventory | 39 | 3 557 | | siem | 10 | 936 |
| plugins | 48 | 3 039 | | outbound | 7 | 864 |
| notifications | 13 | 824 | | audit | 13 | 751 |
| crypto | 7 | 600 | | outbox | 9 | 416 |
| ai | 4 | 375 | | reporting | 2 | 284 |
| settings | 8 | 234 | | config | 4 | 218 |
| maintenance | 6 | 170 | | | | |

Les dépendances entre modules (`@ApplicationModule(allowedDependencies)`), qui fixent l'ordre du
portage :

- **Aucune dépendance de module :** access, audit, outbound, settings, platform, maintenance, reporting ; outbox → maintenance ; crypto → outbound, settings ; siem → access.
- **targets** → access · **scanning** → access, targets · **issues** → access, scanning, targets · **inventory** → access, scanning, targets.
- **rules** → access, inventory, issues, scanning · **gate** → access, issues, rules, scanning, targets · **notifications**, **threatintel**, **tickets**, **plugins**, **agents** → des sous-ensembles des précédents.
- **checklists** → access, inventory, issues, notifications, plugins, scanning, targets · **exports**, **posture**, **ai** → gate, inventory, issues…
- **forges** → access, checklists, targets · **compliance** → ai, exports, gate, posture, rules… · **reportplugins** → checklists, compliance, gate…

### 1.3 Surface HTTP

- **245 chemins, 311 opérations, 422 schémas**, dans un `openapi.json` de 657 Ko.
- Les plus gros groupes : projets (43 opérations), dépôts (20), connexions aux forges (14), modèles de checklist, conformité et réglages (12 chacun), authentification (10), administration, jeux de règles et équipes (9 chacun), le protocole des agents (8), et SCIM (12, hors `/api/v1`).
- **71 contrôleurs.** Actuator expose `health` (avec les sondes Kubernetes `liveness`/`readiness`), `info` et `metrics`.

### 1.4 Persistance

- **77 entités, 77 dépôts** : 319 méthodes `@Query` (4 natives), 4 classes qui utilisent `Specification`/`CriteriaBuilder` de JPA pour des filtres dynamiques, 1 qui passe directement par JDBC.
- **415 sites `@Transactional`** ; 27 écouteurs d'événements (événements applicatifs de Spring Modulith et écouteurs transactionnels).
- **Flyway 12.4.0** (BOM de Spring Boot 4.1.1) : 46 fichiers sous `db/migration/common` et 44 sous `mysql` comme sous `postgresql`, V1–V91, environ 78 tables. Emplacements `common` puis `{vendor}` ; par défaut `outOfOrder=false`, `validateOnMigrate=true`, clean désactivé, pas de baseline.
- Substitutions par moteur (`MigrationDialect`, positionnelles, les huit obligatoires) :

| Substitution | MySQL | PostgreSQL |
|---|---|---|
| `${ts}` | `datetime(6)` | `timestamp with time zone` |
| `${id}` | `bigint auto_increment primary key` | `bigint generated always as identity primary key` |
| `${bool}` | `bit(1)` | `boolean` |
| `${true}` / `${false}` | `b'1'` / `b'0'` | `true` / `false` |
| `${text}` | `longtext` | `text` |
| `${double}` | `double` | `double precision` |
| `${bytes}` | `longblob` | `bytea` |

  Un `spring.flyway.placeholders.*` qui tente d'en remplacer une est refusé au démarrage.

### 1.5 Travail planifié et asynchrone

- **28 implémentations de `MaintenanceTask`** sur trois tours à délai fixe (relais 60 s, planification 60 s, horaire), plus 8 autres méthodes `@Scheduled`.
- Les tours n'ont pas d'élection de leader : chaque tâche doit supporter de tourner sur chaque instance. `MaintenanceJobsTest` vérifie la composition. Le planificateur des analyses fait exception : son tic ne tourne que sur le leader, au moyen d'une ligne de bail (phase 2, §7).
- Une **boîte d'envoi** (outbox) porte les notifications, les événements SIEM et la synchronisation des tickets.

### 1.6 Mécanique de sécurité

- **Chaîne de filtres :** adresse du client, limite de taille du corps, authentification par jeton, limites de débit (jeton, connexion, webhook), confinement des clés, intercepteur de changement de mot de passe, accès actuator, réponses en problem document.
- **Sessions :** jetons opaques de 32 octets ; **le magasin n'en garde que le SHA-256**. Les sessions sont sans état du point de vue de Spring (`SessionCreationPolicy.STATELESS`) et voyagent en jeton porteur, d'où **le CSRF désactivé à dessein**. La CSP est posée dans la chaîne.
- **Mots de passe :** **Argon2id**, chaîne PHC, m = 19 Mio, t = 2, p = 1, sel de 16 octets, BouncyCastle. Des paramètres stockés plus faibles sont rehachés à la connexion ; les anciens hachages bcrypt sont reconnus.
- **Clés d'API :** `zsk_` suivi de 43 caractères, un préfixe de 12 caractères en clair pour réduire les candidats, le reste haché. **Clés d'agent :** une sorte à part. **SCIM :** son propre jeton.
- **TOTP :** HMAC-SHA1 (RFC 6238). **OIDC :** client OAuth2 de Spring Security (authentification unique, règles de rattachement des comptes).
- **Verrouillage et limites :** Bucket4j. **Double validation**, **modèle de rôles** (drapeaux de `Role`), et **`Visibility`** résolue par compte et par clé, appliquée dans les requêtes (404, jamais 403).
- **Sortant :** chaque appel passe par `PinnedHttpSender` et sa garde (adresse résolue épinglée, plages privées et de métadonnées refusées, redirections refusées).
- **Cryptographie :**
  - chiffrement au repos AES-256-GCM (BouncyCastle) sous `ENCRYPTION_KEY`, avec un contexte lié en donnée associée, et des enveloppes scellées vers les agents ;
  - signatures ECDSA P-256/SHA-256 (compatibles cosign), clé de signature des documents, DSSE ;
  - chaîne de hachage SHA-256 du journal d'audit ;
  - webhooks HMAC-SHA256.

### 1.7 Sorties et intégrations

- **PDF :** Apache **PDFBox 3.0.8** à cinq endroits : rapport de conformité, rapport OWASP, rapport de posture, historique de triage, curseur de rapport.
- **Autres formats :**
  - CSV ;
  - SARIF ;
  - OpenVEX et CSAF ;
  - lecture de CycloneDX et SPDX ;
  - le xlsx des checklists **rendu octet par octet** depuis le modèle stocké (`Workbook` de vectispire-common, un zip de parties XML).
- **Notifications et SIEM :** e-mail par Spring Mail (texte brut) ; SIEM en CEF sur syslog (`SyslogSender`) ; tickets Jira, GitLab et GitHub ; connexions aux forges (API GitLab et GitHub).
- **Conteneurs :** le worker intégré et les plugins de rapport utilisent docker-java à travers le proxy socket, ce que la crate `container` du portage de l'agent couvre déjà.
- **Configuration :** environ **70 variables d'environnement `VECTISPIRE_*`** dans `application.yaml` (303 lignes), plus `/run/secrets` lu comme arbre de configuration.

## 2. Ce qui ne doit pas changer

1. **Le document OpenAPI, octet par octet.** `ClientContractSpecTest` le fige ; le client Angular en est
   généré ; agents et intégrations en dépendent ; `published-operation-ids.txt` liste les operationId
   qu'aucune version ne peut renommer ; `api-compat` le compare au dernier tag. Le plan de contrôle Rust
   **sert les mêmes octets** et il est vérifié contre eux, pas contre une approximation régénérée (§3.4).
2. **Le schéma de la base, exactement.** Aucune migration n'est écrite pour le portage. Les mêmes
   fichiers, la même `flyway_schema_history`, pour qu'une installation migrée par Java continue sous Rust
   et, pendant la transition, revienne sous Java (§3.3). `ddl-auto: validate` devient un contrôle de
   parité du schéma sur les deux moteurs.
3. **MySQL et PostgreSQL**, les deux, dès la première phase.
4. **Les frontières, à la compilation.**
   - Chaque module de core devient une crate (`vectispire-cp-<module>`) dont la surface publique est son `lib.rs`. L'équivalent du paquet racine d'un module et de ses interfaces nommées est `pub` ; `web`, `internal` et `persistence` sont des modules `pub(crate)`.
   - `allowedDependencies` devient les `[dependencies]` de la crate, et un test lit `cargo metadata` et échoue sur un lien absent d'une liste versionnée. Cette liste est la décision de revue que Modulith demande aujourd'hui.
   - Les couches à l'intérieur d'une crate (`domain ← scanning ← persistence ← services ← web`) sont tenues par la visibilité des modules, plus un petit test fondé sur `syn` pour ce que la visibilité ne sait pas dire, comme « aucun type SQL dans un module web ».
   - `CrossModuleQueriesTest` devient un test qui lit chaque chaîne SQL et échoue sur la table d'un autre module hors d'une liste qui ne fait que rétrécir.
5. **Les invariants de sécurité d'`AGENTS.md`.**
   - La visibilité est appliquée dans la requête, et un refus est un 404.
   - Les empreintes sont un contrat de données.
   - Absent n'est jamais vide.
   - La porte sortante est le seul client HTTP.
   - L'agent ne lie jamais de crate de base de données : le test d'isolement de l'agent existe déjà dans l'espace de travail, et les crates du plan de contrôle ne doivent jamais devenir une dépendance de `vectispire-agent`.
6. **Tout ce qui est stocké reste vérifiable.**
   - Chaînes PHC Argon2id avec les mêmes paramètres (et le repli bcrypt).
   - Hachages et préfixes des clés d'API, secrets TOTP.
   - Enveloppes AES-256-GCM avec la même disposition du nonce et les mêmes données associées.
   - Signatures par la même clé de documents, chaîne d'audit continuée depuis la tête stockée.

   La crate `crypto` du portage de l'agent prouve déjà l'interopérabilité octet par octet des enveloppes et des signatures ; le plan de contrôle la réutilise.
7. **Les sessions survivent à la bascule.** Ce sont des jetons opaques dont le SHA-256 est stocké : un
   plan de contrôle Rust qui lit la même table accepte les mêmes sessions. Aucune déconnexion à la
   bascule n'est nécessaire. Cela ne tient que si la recherche de session et les durées d'inactivité et
   absolue de Rust correspondent exactement à `Sessions`, ce qui est l'un des cas de conformité.

## 3. Bibliothèques

### 3.1 Choix

| Besoin | Choix | Écarté, et pourquoi |
|---|---|---|
| Exécution | **tokio** | le seul runtime que le reste de la pile suppose |
| Serveur HTTP | **axum** + **tower** + **tower-http** | actix-web : son propre runtime d'acteurs et son modèle de middlewares ; axum se compose de couches tower, qui correspondent une à une à la chaîne de filtres (§1.6) |
| Base de données | **sqlx** (pilotes MySQL et PostgreSQL, rustls) pour les requêtes fixes, **sea-query** pour les 4 sites à filtres dynamiques | SeaORM : un ORM sur le même schéma réintroduit le risque des « deux autorités » que `ddl-auto: validate` évite ; diesel-async : un schéma compilé par moteur, donc deux modules de schéma à garder égaux, et l'asynchrone est une couche ajoutée |
| Vérification des requêtes | `sqlx::query!` vérifié hors ligne contre **les deux** moteurs (deux caches `.sqlx` générés en CI depuis des conteneurs) | des chaînes vérifiées seulement à l'exécution perdraient ce que les 319 `@Query` reçoivent de la validation de Hibernate au démarrage |
| Migrations | **une crate à nous, `vectispire-migrate`** (§3.3) | refinery, sqlx-migrate : leurs propres tables d'historique et sommes de contrôle |
| OpenAPI | **le `openapi.json` versionné fait foi** ; un test de conformité vérifie les types de requête et de réponse de chaque route contre lui (§3.4) ; utoipa seulement comme aide pour générer les schémas à comparer | utoipa ou aide comme source : régénérer le document ne reproduirait jamais 657 Ko de sortie springdoc octet par octet |
| Sérialisation | **serde** + **serde_json** avec `preserve_order`, et le module `jackson` du portage de l'agent pour une sortie compatible Jackson (échappements `\uXXXX` en majuscules, nombres de `Double.toString`, textes d'`Instant`/`Duration`) | la sortie brute de serde_json : diffère de Jackson sur les échappements et les nombres, ce que les réponses de référence montreraient aussitôt |
| Validation | **garde** | validator : modèle de dérivation plus ancien, plus faible sur les règles imbriquées et conditionnelles |
| Sessions et authentification | middleware à nous sur la table des sessions (§2.7) ; **argon2** + **password-hash** (PHC) ; **bcrypt** en vérification seulement ; **totp-rs** (SHA-1, 30 s, 6 chiffres) ; **openidconnect** pour l'authentification unique | tower-sessions : un modèle de session par cookie ; l'API utilise des jetons porteurs |
| Limites de débit | **governor**, clés exactement comme Bucket4j (adresse, compte, préfixe du jeton) | tower-governor seul : ses clés ne couvrent pas le compte ni le préfixe |
| Configuration | **figment** avec les mêmes noms `VECTISPIRE_*`, la syntaxe des durées de Spring (déjà portée dans l'agent), et `/run/secrets` comme arbre de configuration | config-rs : messages d'erreur moins précis sur la provenance |
| Journalisation | **tracing** + tracing-subscriber, texte ou JSON ; le **miroir fichier du journal d'audit** gardé comme écrivain à part | log + env_logger : pas de spans |
| Métriques et santé | **metrics** + **metrics-exporter-prometheus** sous `/actuator/metrics` ; `/actuator/health`, `/liveness`, `/readiness` avec le même JSON | le SDK OpenTelemetry maintenant : inutile pour la parité |
| Planification | intervalles tokio, une tâche par `MaintenanceTask`, les trois mêmes cadences, chacune tolérant plusieurs instances | une crate de cron : aucune tâche n'est pilotée par le calendrier |
| E-mail | **lettre** (rustls, STARTTLS, les mêmes réglages `vectispire.mail.*`) | — |
| Client HTTP | **reqwest** avec rustls, enveloppé par la porte sortante portée depuis `PinnedHttpSender` : résoudre une fois, épingler, refuser le privé, les métadonnées et les redirections | hyper directement : plus de code pour la même garantie |
| Cryptographie | la crate **`vectispire-crypto`** de l'espace de travail (RustCrypto `aes-gcm`, `p256`/`ecdsa`, `sha2`, `hmac`) | ring seul : pas d'import PKCS#8 P-256 tel que Java l'écrit ; aws-lc-rs : une chaîne de compilation C dans le build |
| XML | **quick-xml** (parties du xlsx, CycloneDX/SPDX en XML), entités externes coupées | roxmltree : lecture seule |
| xlsx | le modèle stocké réécrit partie par partie avec **zip** (ordre des entrées et horodatages déterministes), comme le fait le `Workbook` Java | rust_xlsxwriter ou calamine : ils génèrent ou lisent, ils ne préservent pas un modèle octet par octet |
| **PDF** | **le principal risque de bibliothèque.** Candidats : **printpdf** (bas niveau, comme les flux de contenu de PDFBox) ou **krilla** (plus haut niveau, utilisé par typst). Les PDF sont produits par du code, pas par des gabarits ; une bibliothèque de bas niveau correspond le mieux au code Java | typst comme moteur de documents : un second langage pour cinq rapports ; Chromium sans tête : un navigateur dans le plan de contrôle |
| Tests | **testcontainers** (MySQL 9.4 et PostgreSQL 17 par digest, comme `Engine.java` les épingle), **insta** pour les fichiers de référence, **proptest** pour les analyseurs et les empreintes, **wiremock** pour les bouchons sortants | — |
| Analyse statique | clippy avec `-D warnings` et une sélection pédante ; `unsafe_code = "forbid"` dans chaque crate du plan de contrôle | — |

### 3.2 Servir l'interface

Le build Angular est servi depuis la même origine par `ServeDir` de tower-http, avec la même CSP, les
mêmes en-têtes de cache et le même repli vers l'application que la configuration Java pose.
`connect-src 'self'` reste vrai.

### 3.3 `vectispire-migrate` : un exécuteur compatible Flyway

C'est une crate à part entière de la phase 0, parce que la table d'historique décide de tout : un
exécuteur qui tient sa propre table ne peut pas continuer une installation que Java a migrée.

**Ce qu'il lit.** Les fichiers existants, inchangés :

- `db/migration/common` et `db/migration/{mysql,postgresql}`, embarqués à la compilation ;
- la version, et la description tirée du nom du fichier (`V91__checklist_contacts.sql` → `91`, « checklist contacts ») ;
- les huit substitutions du §1.4, portage direct de `MigrationDialect`, avec le même refus d'un remplacement.

**Ce qu'il écrit.** Des lignes de `flyway_schema_history` que Flyway 12.4 écrirait :

- `installed_rank`, `version`, `description`, `type = SQL`, `script` ;
- la **somme de contrôle**, `installed_by`, `installed_on`, `execution_time` et `success`.

**La somme de contrôle doit être celle de Flyway.** Flyway calcule un CRC32 sur le script lu ligne par
ligne, sans les fins de ligne et sans un éventuel BOM UTF-8 en tête. On la croit calculée sur la ressource
brute, avant le remplacement des substitutions. Cette croyance est la première chose que les tests de la
crate tranchent contre le vrai Flyway ; ce plan ne l'affirme pas. Le test :

1. Java migre une base vide jusqu'à V91 sur chaque moteur.
2. L'exécuteur Rust recalcule chaque somme depuis les fichiers embarqués ; elle doit égaler chaque somme stockée.
3. L'exécuteur Rust migre une autre base vide.
4. Le vrai Flyway, avec la configuration de Java, la valide sans erreur, et `SchemaParityIntegrationTest` passe dessus.

**Validation avant de servir.** Comme Flyway avec `validateOnMigrate` et les réglages par défaut de
Spring :

- chaque somme appliquée correspond à son fichier ;
- aucune version appliquée ne manque dans les fichiers, et aucune version de fichier n'est plus ancienne que la dernière appliquée (`outOfOrder=false`) ;
- aucune ligne n'a `success = false` ;
- puis les migrations en attente sont appliquées, dans l'ordre.

Le plan de contrôle ne répond pas en HTTP avant que ce contrôle ait réussi.

**Transactions et verrou.**

- Chaque migration tourne dans une transaction sur PostgreSQL, dont le DDL est transactionnel. Sur MySQL, le DDL valide implicitement ; le comportement de Flyway (une migration en échec laisse une ligne `success = false` et refuse le démarrage suivant) est reproduit, pas amélioré.
- Deux instances qui démarrent ensemble ne doivent pas migrer toutes les deux. L'exécuteur prend `pg_advisory_lock` sur PostgreSQL et `GET_LOCK` sur MySQL, sous la clé qu'utilise Flyway, pour qu'une instance Java et une instance Rust s'excluent aussi. La clé est à lire dans le source de Flyway 12.4 et à figer par un test.
- `clean` et `baseline` ne sont pas implémentés du tout.

**Disposition et parité.**

- `MigrationLayoutTest` est porté : une version vit dans un seul des deux endroits, `common` ou le dossier du moteur, et V1–V39 ne bougent jamais.
- Le **contrôle de parité du schéma** remplace `ddl-auto: validate`. Chaque module de persistance déclare ses tables et colonnes (nom, famille de type, nullabilité) à côté de ses requêtes. Un contrôle au démarrage, et un test d'intégration sur les deux moteurs, les comparent avec `information_schema`.

**Pourquoi pas une crate existante.**

- **refinery :** sa propre `refinery_schema_history` et sa propre somme (SipHash).
- **sqlx::migrate :** `_sqlx_migrations` et SHA-384.
- **barrel :** un DSL, pas un exécuteur.

Aucune ne sait lire ni écrire `flyway_schema_history` comme Flyway 12.4. L'exécuteur est petit, de l'ordre de 600 à 900 lignes avec ses tests, et le posséder coûte moins cher que de modifier une crate dont la conception centrale est sa propre table.

**Plan de test.** Avec testcontainers, sur les deux moteurs :

- migrée par Java → Rust valide, sommes et parité ;
- migrée par Rust → Java et Flyway valident, et `integrationTestAll` passe dessus ;
- un fichier modifié est refusé ;
- une version appliquée manquante est refusée ;
- une ligne `success = false` est refusée ;
- le désordre est refusé ;
- deux instances Rust, puis une Rust et une Java, démarrent ensemble : l'une migre, l'autre attend.

### 3.4 Le contrat, gardé identique

Le document servi est le `openapi.json` versionné, embarqué. Une suite de conformité vérifie, route par
route :

- que le routeur répond à chaque chemin et méthode du document, et à rien d'autre ;
- que les types de requête et de réponse de chaque gestionnaire se sérialisent en JSON valide contre le schéma du document ;
- que les **réponses de référence** du §4.3 valident contre lui.

Une route ajoutée sans que le document change échoue. Un document modifié à la main sans le code échoue
au rejeu des réponses de référence.

## 4. Stratégie de migration

### 4.1 Options

- **(a) Construction en parallèle, puis bascule.** Le plan de contrôle Rust est construit jusqu'au bout,
  à côté du Java, et n'est pas déployé avant d'avoir passé tout l'oracle (§4.3). Une installation bascule
  alors en remplaçant l'image. La base, les sessions, les clés et la chaîne d'audit suivent (§2). Le
  retour à Java reste possible tant qu'aucune migration plus récente que la dernière version Java n'a
  tourné.
- **(b) Étrangleur.** Un routeur envoie certains chemins à Rust et le reste à Java, sur une seule base.
  Les risques sont concrets ici :
  - deux écrivains de la **chaîne d'audit**, dont la tête est prise sous verrou ;
  - deux relais de la **boîte d'envoi** ;
  - deux planificateurs qui lancent les mêmes tâches de maintenance — toléré aujourd'hui seulement dans la sémantique d'une seule implémentation ;
  - deux caches des réglages et de la visibilité ;
  - des durées de session prolongées par l'un et expirées par l'autre ;
  - chaque transaction entre modules coupée entre deux processus.

### 4.2 Recommandation

**(a), avec des barrières par module.** Chaque phase se termine quand ses routes passent l'oracle alors
que le reste de l'application manque encore, et l'avancement se mesure donc en continu. Aucune
installation ne fait jamais tourner les deux. Un étrangleur ferait de chacun des risques ci-dessus un état
de production à concevoir, puis à retirer.

### 4.3 L'oracle

Ces éléments sont neutres vis-à-vis du langage, ou le deviennent :

1. **L'identité du contrat** (§3.4).
2. **Le trafic enregistré.**
   - La suite HTTP Java (172 fichiers de test MockMvc) reçoit un `ResultHandler` commun qui écrit chaque requête, le statut, les en-têtes et le corps de la réponse, et un vidage des lignes que le test a touchées, dans des fichiers de référence.
   - Identifiants, horodatages et jetons sont normalisés.
   - La suite Rust charge les mêmes lignes, rejoue les mêmes requêtes en vrai HTTP et compare. Les tests Java existants deviennent ainsi l'oracle sans qu'on porte d'abord leurs assertions une à une.
   - Une différence est soit un défaut de Rust, soit un comportement Java à écrire comme voulu, puis à reproduire.
3. **La suite e2e Playwright,** lancée contre le plan de contrôle Rust.
4. **Les exercices,** avec l'image Rust à la place de « l'image de ce commit » :
   - `scripts/upgrade-drill.sh` : des données écrites par la dernière version Java, relues inchangées par Rust ;
   - l'exercice de restauration ;
   - `scripts/composition-scan-check.sh` avec les deux agents.
5. **La comparaison de l'état de la base :** après le même scénario, les bases Java et Rust comparées table par table, normalisées.
6. **Les gardes, portées en tests :**
   - `AuthorizationCoverageTest` et `RouteAuthorizationTest` (chaque route déclare son rôle et sa visibilité, sinon le build échoue) ;
   - `ServicesRefuseHiddenTargetsTest`, `MaintenanceJobsTest`, `TableEmptyingTest`, `RefusalTypesTest` ;
   - `ResponseNullabilityTest`, qui découle côté Rust de la conformité au schéma ;
   - les jeux de référence des empreintes.

## 5. Phases

Les estimations sont en semaines-développeur, pour une équipe à l'aise en Rust / une équipe qui
l'apprend. Elles comptent le portage, les tests, le travail d'oracle et la revue. L'ordre suit les
dépendances du §1.2.

| Phase | Contenu | Critères de sortie | Semaines |
|---|---|---|---|
| 0. Fondations | crates de l'espace de travail, `vectispire-migrate`, couche base et parité du schéma, pile HTTP avec la chaîne de filtres, configuration, erreurs en problem documents, JSON compatible Jackson, porte sortante, outillage de test, enregistreur de trafic dans la suite Java, conformité au contrat, contrôles de sécurité en CI (§6) | test aller-retour de migrate vert sur les deux moteurs ; une application Rust vide sert `/actuator/health` et le contrat embarqué ; l'enregistreur produit les fichiers de référence depuis toute la suite Java | 10–14 / 14–20 |
| 1. Accès | utilisateurs, sessions, mots de passe, clés d'API, d'agent et SCIM, TOTP et verrouillage, OIDC, rôles, `Visibility`, réglages de double validation, chaîne d'audit, réglages, plateforme | toutes les réponses de référence de `auth`, `users`, `api-keys`, `admin`, `security` et SCIM passent ; des sessions d'une base migrée par Java acceptées ; gardes d'autorisation portées ; revue de sécurité de la phase sans rien au-dessus de bas | 12–16 / 17–24 |
| **Point de décision 1** | débit mesuré face à ce plan ; revue des deux parties les plus dures faite | | |
| 2. Cibles et scans | cibles, solutions, projets, scans, ingestion (empreintes), côté serveur du protocole des agents, boîte d'envoi | jeux de référence de l'ingestion identiques octet par octet ; réponses de référence du protocole ; exercice de mise à niveau vert pour ces tables | 14–20 / 20–28 |
| 3. Anomalies et décisions | anomalies, triage, double validation, exceptions, VEX/CSAF, inventaire, règles, barrière | réponses de référence ; exercices des empreintes et de l'historique de triage | 14–19 / 20–27 |
| 4. Intégrations | notifications, e-mail, SIEM, tickets, forges, renseignement sur les menaces, plugins, conseiller IA | réponses de référence avec bouchons sortants ; format SIEM identique octet par octet | 12–17 / 17–24 |
| 5. Documents | checklists (xlsx octet par octet), exports, conformité, posture, rapports (PDF), plugins de rapport | xlsx et chaque PDF comparés à ceux de Java sur les mêmes données : PDF égaux en texte et en structure, pas octet par octet sauf si c'est prouvé faisable | 13–19 / 19–27 |
| 6. Bascule | oracle complet, deux moteurs, deux semaines côte à côte sur une copie de préproduction, chaîne de publication (image, SBOM, signature à identité inchangée) | chaque élément de l'oracle vert ; nightly verte 14 jours | 6–9 / 8–12 |
| **Total** | | | **81–114 / 115–162** |

**À propos du débit assisté par IA.** Les fondations du portage de l'agent sont allées plus vite que ce
que l'étude de l'agent estimait. Le code a été produit en heures, pas en semaines, et les contrôles
étaient réels. Mais la production de code n'est pas le goulot de ce portage. Le goulot est :

- décider ce que signifie chaque comportement Java ;
- relire le code qui touche à la sécurité ;
- rendre l'oracle digne de confiance.

Cela ne se comprime pas de la même façon. Le plan ne compte sur aucun multiplicateur. Si la phase 1 en confirme un, les phases suivantes sont réestimées au point de décision 1, pas avant.

**Les parties les plus dures, dans l'ordre :**

1. **Accès :** le modèle de rôles, `Visibility` dans chaque requête, la double validation, un verrouillage aux mêmes clés, les règles de rattachement OIDC.
2. **Ingestion et empreintes :** le contrat de données de chaque anomalie.
3. **Anomalies et triage :** machine à états, approbations, expiration, sémantique VEX/CSAF.
4. **Checklists :** le xlsx rendu octet par octet, les mesures, l'approbation.
5. **PDF :** aucune bibliothèque équivalente à PDFBox.
6. **SIEM :** CEF sur syslog, au cadrage exact.

**Risques et parades.**

| Risque | Parade |
|---|---|
| Un comportement perdu que seul un test Java figeait | l'enregistreur de trafic en fait des réponses de référence avant que la moindre phase commence |
| Une incompatibilité de somme ou de verrou avec Flyway | tranchée par les premiers tests de `vectispire-migrate` contre le vrai Flyway ; rien d'autre ne touche la base avant qu'ils soient verts |
| Le manque de bibliothèque PDF | la phase 5 commence par un essai de deux semaines sur les cinq rapports ; repli : un petit écrivain PDF à nous au-dessus de `printpdf` |
| Les différences de sortie avec Jackson | le module `jackson` du portage de l'agent ; les réponses de référence attrapent le reste |
| Deux bases de code pendant la construction | Java reste le produit ; Rust ne livre rien avant la bascule ; chaque changement Java pendant la construction arrive avec sa réponse de référence, et l'oracle suit |
| Les compétences de l'équipe | le point de décision 1 les mesure, pas ce plan |

**Registres de décision.** Un ADR au départ (« le plan de contrôle est porté en Rust derrière un oracle
de conformité ; Java reste le produit jusqu'à la bascule »), qui amende 0028–0030 (les modules deviennent
des crates), 0013 et 0027 (l'exécuteur de migrations), et qui consigne le choix PDF après son essai. Un
second ADR à la bascule.

## 6. Contrôles de sécurité

Le plan de contrôle Rust doit porter au moins ce que porte le Java. La partie CI de l'espace de travail
`vectispire-rust` existant est construite à part, sur sa propre branche ; cette section dit ce dont le
plan de contrôle a besoin et ce qu'il y ajoute, elle ne la reconçoit pas.

### 6.1 Dans le code

- **`unsafe_code = "forbid"`** dans chaque crate du plan de contrôle. Le seul `unsafe` de l'espace de travail reste les deux appels globaux de libgit2 dans la crate `git` de l'agent.
- **Limites d'entrée :**
  - la limite de taille du corps par classe de route, portée depuis `RequestBodyLimitFilter` ;
  - des limites de profondeur et de taille du JSON ;
  - des limites multipart ;
  - des limites de taille décompressée (bombe zip) pour les envois de xlsx, de SBOM et d'archives ;
  - le XML avec entités externes et DTD coupées.
- **L'autorisation comme garantie à la compilation ou au test.** Chaque gestionnaire est enregistré par un seul constructeur qui exige son exigence de rôle et son mode de visibilité ; une route sans eux ne compile pas. `AuthorizationCoverageTest` et `RouteAuthorizationTest` sont portés en tests qui parcourent le routeur et le contrat : chaque route déclarée, chaque route nommant une cible résolvant une `Visibility`, les refus répondant 404.
- **La visibilité dans la requête :** chaque requête qui prend un identifiant de cible prend un argument `Visibility` par son type. Les aides `sea-query`/`sqlx` font d'une requête sans lui une erreur de compilation dans les modules de persistance.
- **Sortant :** le seul client HTTP est la porte ; un test de l'espace de travail échoue sur une construction de `reqwest::Client` hors d'elle, portage de `onlyTheOutboundDoorSpeaksHttpOutwards`.
- **En-têtes :** les mêmes CSP, `X-Content-Type-Options`, `Referrer-Policy`, refus d'encadrement et HSTS, posés une fois dans une couche tower et vérifiés par un test sur chaque classe de route.
- **Cookies et CSRF :** l'API utilise des jetons porteurs et garde le CSRF coupé comme aujourd'hui. Le cookie de passage de l'authentification unique garde `Secure`, `HttpOnly` et `SameSite`, et `Secure` dépend de la règle des mandataires de confiance de 0038.
- **Comparaisons à temps constant** (`subtle`) pour les jetons, les hachages de clés, les HMAC et les codes TOTP. Le temps de connexion est égalisé pour les comptes inconnus, comme le fait Java.
- **Des types secrets qui ne s'impriment jamais :** le type `Secret` de l'agent (`***` en `Debug`, pas de `Display`) pour les mots de passe, jetons, clés et la clé de chiffrement ; `zeroize` à la libération pour le matériel de clé.
- **Cryptographie à temps constant :** uniquement des primitives RustCrypto ; pas de RSA avec un avis de fuite temporelle connu (le portage de l'agent a déjà coupé `rsa` pour RUSTSEC-2023-0071).
- **Limites de débit :** limites de connexion, de jeton et de webhook aux mêmes clés qu'aujourd'hui, avec leurs tests portés.
- **Absent, jamais vide :** les analyseurs rendent `Option`/`Result`, jamais une valeur par défaut ; les cas du correctif 0.11.1 sont des cas de référence dès le départ.

### 6.2 En CI

Le job de l'espace de travail fournit l'essentiel ; le plan de contrôle y ajoute ses crates :

- **Dépendances :**
  - `cargo deny` pour les avis, licences, interdictions (aucune crate de base dans l'agent ; pas d'`openssl-sys` sauf décision) et sources (crates.io seulement) ;
  - `cargo audit` ;
  - une politique de confiance pour les nouvelles crates : **cargo-vet** avec des audits importés, ou, si c'est trop coûteux, une liste autorisée relue qui produit le même effet, pour qu'une nouvelle crate soit une décision de revue comme l'est aujourd'hui une ligne `allowedDependencies`.
- **Analyse statique :**
  - clippy avec `-D warnings` plus des lints utiles à la sécurité, dont `unwrap_used` et `expect_used` hors tests, `indexing_slicing` dans les analyseurs, `arithmetic_side_effects` dans les calculs de taille, `mem_forget` et `undocumented_unsafe_blocks` ;
  - **semgrep** avec les règles Rust à côté des règles existantes.
- **Fuzzing** avec `cargo fuzz` dans la nightly : chaque analyseur et désérialiseur qui lit une entrée non fiable. Cela couvre SARIF, CycloneDX, SPDX, OpenVEX, CSAF, xlsx, les corps du protocole des agents, les corps SCIM et les problem documents.
- **Chaîne d'approvisionnement :**
  - un **SBOM** par `cargo auditable` (embarqué) et CycloneDX (publié) ;
  - **Grype** sur l'image, au digest que `ScannerImages` épingle ;
  - **checkov** sur le Dockerfile ;
  - **gitleaks** comme aujourd'hui ;
  - des **builds reproductibles :** l'image construite deux fois au même digest.
- **Publication :** **signature cosign inchangée.** L'identité nomme `release.yml`, pas le langage, et les consommateurs continuent de vérifier la même identité.
- **Revues :** la **compétence `security-audit`**, les quatre domaines en parallèle, lancée à la fin de chaque phase. Une phase ne sort pas avec un constat au-dessus de bas.

## 7. Tâches des phases 0, 1 et 2

Chaque tâche possède ses fichiers, pour que des agents en parallèle ne se marchent pas dessus. Les crates
sont sous `vectispire-rust/crates/`.

### Phase 0, en parallèle

| # | Tâche | Possède | Interfaces fournies |
|---|---|---|---|
| 0.1 | **`vectispire-migrate`** : fichiers embarqués, substitutions, somme Flyway, lecture/écriture de l'historique, validation, verrou par moteur, test de disposition, tests aller-retour sur les deux moteurs | `crates/migrate/`, une aide de test Java qui migre avec le vrai Flyway | `migrate::run(&Pool, Engine) -> Result<Report>` et `migrate::validate(...)` |
| 0.2 | **Couche base** : pool par moteur, `Engine`, transactions, caches hors ligne `sqlx` pour les deux moteurs en CI, aides sea-query qui exigent `Visibility`, déclarations et contrôle de parité du schéma | `crates/cp-db/` | `Db`, `Tx`, constructeurs de requêtes typés par `Visibility`, `parity::check` |
| 0.3 | **Pile HTTP** : application axum, la chaîne de filtres en couches tower (adresse, limite de corps, jeton, limites de débit, confinement, changement de mot de passe, problem documents, en-têtes), constructeur de routes qui exige rôle et visibilité | `crates/cp-http/` | `RouteBuilder`, `Problem`, extracteur `Caller` |
| 0.4 | **Conformité au contrat** : `openapi.json` embarqué, contrôle routeur contre document, validation des types des gestionnaires, exécuteur de rejeu des réponses de référence | `crates/cp-contract/` | `contract::assert_router(&Router)`, `golden::replay(dir)` |
| 0.5 | **Enregistreur de trafic côté Java** : un `ResultHandler` MockMvc commun et une aide de vidage des lignes qui écrivent des fichiers de référence normalisés ; lancé sur toute la suite Java | `vectispire-java/vectispire-core/src/test/.../golden/`, `vectispire-rust/golden/` | le format des fichiers de référence |
| 0.6 | **Configuration et exécution** : figment avec chaque nom `VECTISPIRE_*` et `/run/secrets`, tracing, écrivain du miroir d'audit, métriques et points actuator, arrêt propre | `crates/cp-runtime/`, `crates/cp-app/` (le binaire) | `Settings`, `Telemetry`, `App::serve` |
| 0.7 | **Porte sortante** : portage de `PinnedHttpSender` et de sa garde sur reqwest, avec ses tests | `crates/cp-outbound/` | `Outbound::send` |
| 0.8 | **Frontières** : test `cargo metadata` avec la liste versionnée des liens, test des couches par `syn`, test du SQL entre modules, contrôle de `unsafe_code` interdit | `crates/cp-arch-tests/` | — |
| 0.9 | **CI des crates du plan de contrôle** : les ajouter au job de sécurité de l'espace de travail (§6.2), caches sqlx pour les deux moteurs, squelette des cibles de fuzzing | les fichiers CI de l'espace de travail que la tâche CI séparée possède : se coordonner avec elle | — |

Dépendances : 0.2 a besoin de l'`Engine` de 0.1 ; 0.3 n'a besoin de rien ; 0.4 a besoin du type de
routeur de 0.3 ; 0.5 est purement Java. Toutes démarrent ensemble ; 0.2 et 0.4 se rebasent une fois sur
0.1 et 0.3.

### Phase 1, en parallèle après la sortie de la phase 0

| # | Tâche | Possède |
|---|---|---|
| 1.1 | **Comptes et mots de passe** : utilisateurs, PHC Argon2id + vérification bcrypt + rehachage, règles de changement, changement obligatoire | `crates/cp-access/src/accounts/` |
| 1.2 | **Sessions et jetons** : magasin des sessions (SHA-256), durées, extraction du jeton, clés d'API (préfixe + hachage), clés d'agent, jeton SCIM | `crates/cp-access/src/credentials/` |
| 1.3 | **MFA et limites** : TOTP, récupération, verrouillage, limites de connexion, de jeton et de webhook aux clés de Bucket4j | `crates/cp-access/src/mfa/`, `crates/cp-http/src/limits.rs` |
| 1.4 | **OIDC** : client openidconnect, règles de rattachement (adresse vérifiée, pas de rattachement privilégié), cookie de passage | `crates/cp-access/src/sso/` |
| 1.5 | **Rôles, visibilité, double validation** : drapeaux de `Role`, `VisibilityService`, droits d'équipe et directs, restriction de la clé, réglages de double validation | `crates/cp-access/src/` à la racine de la crate (`roles.rs`, `visibility.rs`, `rows.rs`, `four_eyes.rs`, `approvers.rs`), leurs requêtes dans `persistence/`. Pas `src/authz/` : `cp-arch-tests` n'admet comme places d'un module que sa racine, `web`, `internal`, `persistence` et ses interfaces nommées, et refuse tout autre répertoire |
| 1.6 | **Audit et réglages** : journal d'audit avec la chaîne continuée depuis la tête stockée, miroir fichier, magasin et types des réglages, plateforme. **L'enregistrement des réglages écrit toutes ses modifications en une transaction**, là où Java valide chacune séparément et où un échec à mi-chemin laisse les précédentes écrites. C'est un écart délibéré par rapport à Java, décidé par l'utilisateur à la fusion de la phase 1 le 2026-10-17 et consigné dans le README de `cp-platform` | `crates/cp-audit/`, `crates/cp-settings/`, `crates/cp-platform/` |
| 1.7 | **Routes d'accès** : `auth`, `users`, `teams`, `api-keys`, `admin`, `security`, SCIM, contre les réponses de référence | `crates/cp-access/src/web/` |
| 1.8 | **Revue de sécurité de la phase 1** : la compétence `security-audit` sur le diff de la phase | — |

La colonne *Possède* nomme des répertoires pour la lisibilité. La même règle de disposition que pour
1.5 range les fichiers de chaque tâche à la racine de sa crate, dans `internal` et dans `persistence`,
comme l'ont fait 1.1 et 1.2.

### Phase 2, en parallèle après la sortie de la phase 1

La phase 2 couvre les cibles et l'analyse : le parc qu'un compte déclare, la file qui l'examine, les
agents qui y puisent, et l'ingestion qui transforme leurs rapports en constats. C'est là que se trouve la
deuxième des parties les plus difficiles (§5). Le côté Java est mesuré sur **b8bd7e8d0**, la tête de
`release/0.11.1-merge` et le commit que le §1 a mesuré. La base de cette branche (312b7cc8b) a 102
commits de retard sur lui : la ligne 0.11.1 est donc la plus à jour. Le côté Rust est lu sur
`rust/p1-merge` (44f36aff3).

#### Ce que la phase 2 porte

| Module | Fichiers principaux | Lignes | Fichiers de test (unitaires + intégration) | Tables |
|---|---|---|---|---|
| targets | 46 | 3 947 | 5 + 3 | `t_solution`, `t_project`, `t_repository`, `t_container`, `t_git_token`, `t_ssh_key` |
| scanning | 52 | 4 443 | 21 + 6 | `t_scan`, `t_finding`, `t_leader_lease` |
| agents | 17 | 1 929 | 5 + 2 | `t_agent` |
| outbox | 9 | 416 | 2 + 1 | `t_outbox_message` |
| maintenance | 6 | 170 | 2 + 0 | `t_one_shot_job` |
| crypto | 7 | 600 | 5 + 0 | aucune (la clé de signature est une ligne de `t_setting`) |
| **Total** | **137** | **11 505** | **40 + 12** | **12 sur 78** |

`crypto` et `maintenance` ne figurent pas dans le titre de la phase. Ils appartiennent au socle partagé
de Java, que la phase 1 n'a pas porté, et la phase 2 ne peut pas s'en passer :

- `targets` stocke chiffrés les jetons git et les clés SSH ;
- le répartiteur scelle les secrets pour les agents ;
- sept des tâches planifiées de la phase sont des `MaintenanceTask`.

Le reste de l'inventaire :

- **`vectispire-common`, environ 2 600 lignes de plus :**
  - `domain.targets`, `scans`, `agents`, `dependencies` (`DependencyGraph`), `sbom`, `scheduling`, `licenses`, `retention` ;
  - de `domain.issues`, l'empreinte et son vocabulaire (`IssueFingerprint`, `FindingType`, `ToolKeys`) ;
  - `Digests.sha256Fields`, `BoundedText` ;
  - `ScanArtifacts`, `PluginStep`, `ScanTask`.

  Le portage de l'agent tient déjà `FailureReason`, `RepositoryUrl`, `Severity`, la règle des
  sous-chemins, l'écriture de `ScanArtifacts`, et les primitives Ed25519 et X25519.
- **Tests :** 240 fichiers de test de `core` importent l'un des six modules. **69 fichiers MockMvc appellent une route de la phase 2**, et leurs enregistrements sont les réponses de référence de la phase.
- **HTTP : 49 opérations sur 35 chemins**, soit 16 % des 311 :
  - cibles : 29 (solutions 5, projets 7, dépôts 6, conteneurs 5, jetons git 3, clés SSH 3) ;
  - analyses : 3 ;
  - protocole des agents : 8 ;
  - administration des agents : 9.

  Les neuf autres chemins sous `/repositories` et `/solutions` relèvent de l'inventaire, de la
  conformité et des greffons, et attendent leurs phases.
- **Migrations :** 35 des 91 versions touchent ces douze tables (V1 à V86).
- **Travail planifié :**
  - sept `MaintenanceTask` : le tic de planification et l'arriéré à secrets délégués sur le tour de planification ; le relais des notifications sur le tour de relais ; la rétention des analyses, les lignes orphelines de cibles, les identités de dépôt et les messages envoyés sur le tour horaire ;
  - la boucle propre du travailleur intégré ;
  - deux réparations au démarrage : les revendications retenues, et les suppressions de cibles qu'un arrêt a interrompues.

  L'ordre dans un tour est une seule `Sequence` à travers tous les modules : les tours Rust gardent donc
  une liste ordonnée unique, et non une par crate. **Le « pas d'élection de leader » du §1.5 vaut pour les
  tours, pas pour le planificateur.** Le tic de planification ne tourne que sur le leader, au moyen de
  `t_leader_lease` : un `UPDATE` conditionnel dont le nombre de lignes désigne le gagnant. Deux instances
  qui battraient ensemble analyseraient chaque cible due une fois par instance.

#### Les contrats de données qu'elle porte

1. **L'empreinte.** C'est le SHA-256 en hexadécimal minuscule des octets UTF-8 de cinq champs joints par NUL, un champ nul étant joint comme vide :
   - la clé de cible, `repo:<id>` ou `container:<id>` ;
   - le nom de fil du type ;
   - l'identifiant ;
   - le purl, ou le nom du paquet quand le purl est nul **ou vide** ;
   - le chemin.

   Un type rattaché à un outil (greffon, import) met sa clé d'outil à la place du paquet. La fonction est
   appelée par `issues` (`IssueSyncService.fingerprintOf`) sur l'`Observation` que l'ingesteur lui remet,
   **avant** que le constat soit tronqué à ses colonnes. La phase 2 possède donc la fonction et chacune de
   ses entrées ; la phase 3 possède l'arriéré qui stocke le résultat. Trois comportements de Java sont à
   reproduire, pas à corriger :
   - `getBytes(UTF_8)` écrit une demi-paire de substitution isolée comme `?` ;
   - `ToolKeys` rogne avec `String.strip()`, dont `Character.isWhitespace` exclut l'espace insécable, que `char::is_whitespace` de Rust inclut ;
   - les noms d'outil passent en minuscules avec `Locale.ROOT`.
2. **Absent n'est jamais vide** ([0007](../../architecture/fr/decisions/0007-none-is-not-an-empty-list.md)). L'`Optional` d'une étape décide si son type est examiné :
   - SAST et qualité entrent ensemble ;
   - la fin de vie n'entre que si la détection est active, qu'un SBOM existe et que la recherche a réussi ;
   - les licences entrent dès qu'un catalogue existe ;
   - le périmètre d'un greffon n'entre que s'il a produit.

   L'ensemble est conservé sur l'analyse (`examined_types`,
   [0032](../../architecture/fr/decisions/0032-security-checklists.md)). Les deux `Optional` des API
   arrivent intacts à l'inventaire : Java les a aplatis une fois, et cela a vidé les contrats d'un dépôt.
3. **La règle de statut d'une analyse.** Toutes les étapes absentes avec un échec enregistré donnent `failed` : la cible n'a jamais été examinée, et `completed` dirait qu'elle est saine. Rien d'observé et rien d'échoué reste `completed`, car une tâche à qui l'on n'a demandé aucune étape est une configuration à regarder, pas une erreur. Un type de projet absent d'un résultat laisse le précédent en place. Les langages détectés sont écrits même nuls, et nul se lit « inconnu ».
4. **La troncature vient après l'empreinte.** `BoundedText.clip` compte en unités UTF-16 et ne coupe jamais une paire de substitution. La colonne stockée est une copie d'affichage ; la clé est la valeur entière de l'analyseur.
5. **Le fil.**
   - `ScanArtifacts` est lu comme le lit le mapper de l'agent Java : les champs inconnus sont ignorés, et `null` veut dire absent.
   - Le numéro de contrat est comparé strictement au hello, et un écart répond 409.
   - Les résultats et les rapports d'échec sont signés sur le corps brut.
   - Une clé de scellement n'est crue que sur la clé de signature épinglée ([0031](../../architecture/fr/decisions/0031-a-sealing-key-is-believed-only-on-the-pinned-key.md)).
6. **La boîte d'envoi.**
   - Un message est mis en file dans la transaction de l'appelant, jamais dans une transaction à lui ([0033](../../architecture/fr/decisions/0033-internal-reactions-leave-through-the-outbox.md)).
   - Son identifiant est estampillé dans la charge utile, car la livraison est « au moins une fois ».
   - Chaque message est réglé dans sa propre transaction.
   - Un type que personne ne traite est réessayé puis abandonné avec sa raison, jamais sauté.

#### Ce qu'elle attend de la phase 1

| Pièce | Sert à | Sur `rust/p1-merge` |
|---|---|---|
| visibilité de `cp-access` : `VisibilityService`, `rows::NotFound`, `CallerScope` | chaque route qui nomme une cible, chaque lecture d'analyse ; 404, jamais 403 | fusionnée (1.5) |
| `GrantableTargets`, `IssuerSees` : ports que déclare `access` | `cp-targets` les implémente | déclarés, en attente de `cp-targets` |
| `AgentDirectory` (identifiants) | une clé d'agent désigne son agent ; `cp-agents` l'implémente | déclaré (1.2) |
| `cp-audit` | chaque service d'administration écrit son enregistrement (cibles : 14 imports, agents : 7) | fusionné (1.6) |
| `cp-settings` | rétention, liste de licences bloquées, planification par défaut | fusionné (1.6) |
| `cp-http` : constructeur de routes, `Caller`, limites de corps (résultat d'agent : 256 Mo) | les routes | phase 0 |
| `cp-outbound` | le fournisseur de clé Vault | phase 0 |

La MFA (1.3), l'authentification unique (1.4) et les routes d'accès (1.7) ne sont pas sur
`rust/p1-merge`, et la phase 2 n'en a pas besoin : le rejeu des réponses de référence sème les sessions
comme des lignes, que 1.2 lit déjà. Le point de décision 1 reste entre les phases. La phase 2 n'attend
pas que ces tâches soient **prêtes**, seulement qu'elles soient **décidées**.

**Une règle de la phase 0 doit bouger d'abord.** Java déclare partagés sur `VectispireApplication` sept
modules du socle : `settings`, `outbound`, `crypto`, `audit`, `outbox`, `reporting` et `maintenance`.
Modulith les autorise à tout module sans ligne dans `allowedDependencies`.
`cp-arch-tests/data/edges.toml` n'a pas cette notion : `targets` ne peut utiliser que `access`, et
`cp-targets` dépendant de `cp-audit` échoue aujourd'hui. La correction est la liste partagée sous forme
de règle, prouvée cassée d'une façon comme les autres. Ce ne sont pas sept lignes par module, qui
passeraient chacune pour une décision de revue que personne n'a prise.

#### Ce qu'elle attend des phases suivantes, et la découpe

Chacun de ces points est déjà un port en Java depuis la décision
[0029](../../architecture/fr/decisions/0029-core-domains-become-modules.md). Chacun devient un trait dans
la crate qui le déclare. Le binaire compose un remplaçant nommé d'après le module qui le remplacera. Un
test de composition liste les implémentations Java et échoue à la bascule tant qu'un remplaçant reste :
c'est la leçon de `MaintenanceJobsTest`, un appelant manquant ne se voit qu'au niveau de la composition.

| Port (déclaré par) | Implémentation Java | Phase | Remplaçant de la phase 2 |
|---|---|---|---|
| `ScanIngestor.Backlog` (scanning) | `issues` `IssueBacklog` | 3 | enregistre l'`Observation`, répond la `Reconciliation` enregistrée côté Java |
| `ScanIngestor.InventorySink` (scanning) | `inventory` `ScanInventory` | 3 | enregistre les appels |
| `Enricher`, `EndOfLifeSource` (scanning) | `threatintel` | 4 | absents : le chemin « enrichissement désactivé » de Java lui-même ; la fin de vie n'est alors pas examinée |
| `ScanRuleSets` (scanning) | `rules` | 3 | aucun jeu actif : les règles embarquées |
| `ScanPlugins` (scanning) | `plugins` | 4 | aucun greffon |
| `TargetBacklog` (targets) | `issues` | 3 | chiffres à zéro |
| écouteurs de `TargetPurge` (targets) | access, issues, inventory, compliance, forges, gate, plugins, tickets, checklists, greffons de rapport | 1, 3–5 | ceux de targets, de scanning et d'access |
| `OutboxHandler`, `NotificationChannel` (outbox) | notifications, SIEM, checklists, compliance | 4–5 | la seule livraison d'audit des agents |
| réactions à `RepositoryScanned` | checklists, compliance | 5 | aucune |

Le remplaçant de la boîte d'envoi a une contrainte. Un relais dont le registre est incomplet abandonne,
après ses essais, tout message d'un type qu'il ne connaît pas, et les lignes de Java seraient détruites
lors d'un exercice sur une copie de la base. Le binaire Rust ne démarre donc pas le tour de relais tant
que son registre de gestionnaires n'égale pas celui de Java. Le relais est exercé en test avec les
gestionnaires qui existent.

#### Phase 2, tâches

| # | Tâche | Possède | Interfaces fournies | Oracle |
|---|---|---|---|---|
| 2.1 | **Socle et frontières** : la règle des modules partagés ; les lignes de la phase 2 ; `cp-maintenance` avec ses trois tours (30 s de délai initial, un verrou par cadence, une tâche en échec termine son exécution et non le tour), la `Sequence` globale avec les places des modules suivants réservées, les tâches ponctuelles | `crates/cp-maintenance/`, `crates/cp-arch-tests/` (la seule tâche qui modifie `edges.toml`) | `MaintenanceTask`, `Cadence`, `Sequence`, `Turns`, `OneShotJobs` | `MaintenanceJobsTest` et `MaintenanceCompositionTest` portés ; `t_one_shot_job` sur les deux moteurs ; la règle partagée cassée d'une façon sur l'espace de travail synthétique |
| 2.2 | **Boîte d'envoi** : mise en file dans le `Tx` de l'appelant, prise par mise à jour conditionnelle, attente croissante, abandon avec sa raison, purge, comptes | `crates/cp-outbox/` | `Outbox::enqueue(&mut Tx, …) -> Uuid`, `relay`, `prune_sent`, `counts` ; `OutboxHandler`, `NotificationChannel` | `OutboxServiceTest`, `OutboxDatabaseTest` ; `OutboxClaimIntegrationTest` avec deux relais en course sur MySQL et PostgreSQL ; vidages des lignes comparés à ceux de Java |
| 2.3 | **Chiffrement au repos et scellement** : `EncryptionService` (AES-256-GCM, contexte en données associées), les sources de la clé (variable, fichier, `/run/secrets`, Vault par `cp-outbound`), la clé de signature ; le côté scellement ajouté à la crate partagée `crypto` | `crates/cp-crypto/` ; un `seal` additif dans `crates/crypto/`, revu par le flux de l'agent | `Encryption::{encrypt, inspect}(text, context)`, `SigningKeys`, `crypto::seal` | un jeu de référence dans les deux sens : Java déchiffre et ouvre ce que Rust écrit, et l'inverse, par contexte ; `EncryptionServiceTest`, `EncryptionKeyFile*`, `VaultKmsProviderTest` contre un Vault wiremock |
| 2.4 | **L'empreinte et le vocabulaire des cibles**, purs : `FindingType`, `ToolKeys`, l'empreinte, `ScanTarget`, `BoundedText`, `DependencyGraph`, `Sbom::is_catalogue`, `ScanStatus`, l'analyseur cron de Spring, liste de licences bloquées, rétention | de nouveaux fichiers dans `crates/domain/src/` ; `vectispire-rust/reference/{fingerprints,cron,…}/` ; leurs écrivains Java dans `vectispire-common/src/test/` | `fingerprint::{of, of_tool}`, `ScanTarget::fingerprint_key`, `clip`, `DependencyGraph::of`, `CronSchedule::next` | des jeux de référence écrits par Java, identiques à l'octet : les cas d'`IssueFingerprintTest` et de `ToolFingerprintTest`, plus des demi-paires isolées, des espaces insécables, des purls vides et nuls, des caractères astraux à la troncature ; des corpus proptest hachés des deux côtés ; les prochains déclenchements d'un corpus d'expressions Spring |
| 2.5 | **Le protocole, moitié serveur** : lecture typée de `ScanArtifacts` telle que Jackson la fait, chaque `Option` conservée ; les corps de revendication, de hello, de clé de scellement et d'échec que le serveur écrit ; une fonctionnalité `client` que le plan de contrôle laisse éteinte, pour ne pas lier le client HTTP de l'agent | `crates/protocol/` : additif, revu par le flux de l'agent | `ScanArtifacts::read`, l'écriture d'`AssignedTask`, les corps | `reference/artifacts/` dans les deux sens, plus des corps de revendication écrits par Java ; la suite `against_a_stub` de l'agent Rust ; des cibles de fuzzing sur le corps du résultat |
| 2.6 | **Cibles** : les 29 routes ; planifications, identité et doublons de dépôt, nommage, imports ; la suppression en deux temps, reprise au démarrage ; les tâches des lignes orphelines et des identités | `crates/cp-targets/` | `TargetCatalog` ; les traits `TargetScans`, `TargetBacklog` et `TargetPurge` ; `GrantableTargets` et `IssuerSees` pour `cp-access` | réponses de référence des 29 ; `TargetDeletionTest`, `TargetPurgeOrderTest`, `UnnamedTargetTest`, `CronExpressionsTest` ; `RepositoryDuplicateIntegrationTest` et `TargetDeletionIntegrationTest` sur les deux moteurs ; la règle de couverture d'autorisation sur chaque route qui nomme une cible |
| 2.7 | **File, répartition et planification** : la revendication (lecture, puis une mise à jour conditionnelle par candidat, étiquettes et `notBefore` dans la sélection, exclusion des secrets délégués par pages) ; le répartiteur (revendication, scellement, battement, résultat écrit en une transaction, échec, reprise, tentatives) ; le bail de leader et le planificateur ; rétention, purge, catalogue ; les routes des analyses | `crates/cp-scanning/` sauf les fichiers de 2.8 ; elle crée la crate et y déclare `ingestion` vide dès le premier jour | `ScanQueue::claim_within` ; les traits `AgentClaimLock`, `ScanRuleSets` et `ScanPlugins` ; `ScanDispatcher` ; `TargetScans` pour `cp-targets` | `ScanQueueIntegrationTest`, `ScanLabelsIntegrationTest`, `LeaderElectionIntegrationTest`, `SchedulerDatabaseTest`, `RetentionDatabaseTest` sur MySQL et PostgreSQL ; N revendicateurs en course sur les deux moteurs (chaque analyse prise une fois, personne affamé) ; les cas de `ScanDispatcherTest` ; les 3 réponses de référence |
| 2.8 | **Ingestion** : des étapes aux constats, l'ensemble examiné, l'enrichissement appliqué avant l'écriture, l'arriéré nourri des valeurs entières, la troncature ensuite, la règle de statut, les licences tirées du catalogue | `crates/cp-scanning/src/ingestion.rs`, `src/internal/ingestion/`, `src/persistence/findings.rs` ; un écrivain de référence Java sous `vectispire-core/src/test/…/scanning/` | `ScanIngestor::{prepare, ingest}` ; `Backlog`, `InventorySink`, `Enricher`, `EndOfLifeSource`, `LicenseSource` ; `Observation`, `Reconciliation` | **le jeu de référence de l'ingestion** (plus bas) ; `ScanIngestorTest`, `ExaminedTypes*`, `SecretsReportFateTest`, `NoOutboundDuringIngestionTest`, `EnrichmentOutsideTransactionTest` ; `LongFindingIntegrationTest` sur les deux moteurs |
| 2.9 | **Agents, côté serveur** : les 8 routes du protocole avec l'attente longue et son en-tête de concurrence, et les 9 routes d'administration ; le contrôle du contrat au hello ; l'épinglage de la clé de scellement ; les signatures vérifiées sur le corps brut avant toute lecture ; l'arriéré à secrets délégués et sa tâche ; la réparation des revendications retenues ; le travailleur intégré comme exécutant que la file compte ; le gestionnaire de livraison d'audit | `crates/cp-agents/` | les implémentations d'`AgentClaimLock` et d'`AgentDirectory` ; `AgentResultAuditDelivery` | réponses de référence de 15 des 17 (deux différées, plus bas) ; `AgentSealingKeyIntegrationTest`, `WithheldClaimRepairIntegrationTest` sur les deux moteurs ; `AgentJobPollerTest`, `UnroutableWorkerTest`, `CredentialedBacklog*` |
| 2.10 | **Le travailleur intégré** : la chaîne d'analyse de l'agent sortie de son binaire (`agent/src/scan.rs`) vers une bibliothèque que les deux programmes utilisent, et la boucle de revendication du travailleur par-dessus | `crates/runner/`, déplacée avec le flux de l'agent ; `crates/cp-scanning/src/internal/worker/` | `Runner::run(task) -> ScanArtifacts` | **une application démarrée, travailleur actif, fait passer une analyse en file à terminée sur les deux moteurs** : le défaut de câblage d'`AGENTS.md`, qu'aucun test unitaire ne voit ; `ScanWorkerOffloadTest`, `CloneFailureFateTest` ; les suites de l'agent inchangées |
| 2.11 | **Composition et oracle** : la phase 2 câblée dans le binaire avec ses remplaçants nommés ; la liste des différés ; l'exercice de montée de version étendu ; les deux agents contre l'image Rust | `crates/cp-app/` (la composition de la phase 2), `vectispire-rust/golden/deferred.txt`, `scripts/upgrade-drill.sh` | — | les réponses de référence de la phase rejouées ; l'exercice écrit solutions, projets, dépôts, conteneurs, jetons git, clés SSH, agents et une analyse par l'API de la dernière version Java, puis les relit par Rust sur MySQL et PostgreSQL ; `scripts/composition-scan-check.sh` avec les deux agents ; les douze tables comparées à celles de Java après le même scénario ; le test de composition des remplaçants |
| 2.12 | **Revue de sécurité de la phase 2** : la compétence `security-audit` sur le diff de la phase. Accent sur le parc que sert une route de cible ; sur l'appartenance d'une analyse rapportée à l'agent qui l'a prise ; sur la signature avant la lecture ; sur l'épinglage de la clé de scellement ; sur la SSRF par les URL de dépôt et les références d'image ; sur la limite de 256 Mo des résultats ; et sur les jetons et clés de déploiement jamais journalisés | — | — | aucun constat au-dessus de bas |

**Le jeu de référence de l'ingestion.** Java fait tourner `ScanIngestor` sur un corpus avec un
`Backlog` enregistreur, et écrit, pour chaque cas :

- l'`Observation`, avec chaque empreinte ;
- les lignes de constats ;
- l'ensemble examiné ;
- le statut.

L'ingestion Rust doit produire les mêmes octets. Le corpus :

- les sorties de référence des analyseurs du portage de l'agent (dépendances 79, SAST 85, IaC 62, secrets 28) ;
- pour chaque étape, un cas absent et un cas vide ;
- toutes les étapes absentes avec un échec ;
- un greffon qui a produit, un non applicable et un refusé ;
- des valeurs qui dépassent leurs colonnes ;
- des demi-paires isolées ;
- un SBOM proche de la limite du corps.

C'est « jeux de référence d'ingestion identiques à l'octet » rendu exécutable. Il est écrit avant que
2.8 commence, parce qu'une référence écrite après le code tend à donner raison au code.

Dépendances :

- **2.1 arrive en premier, en une journée.** Le `Cargo.toml` de chaque crate est vérifié contre sa règle d'arêtes, et 2.2, 2.6, 2.7 et 2.9 implémentent son `MaintenanceTask`. Seule 2.1 modifie `edges.toml` ; les autres lui demandent une ligne.
- **2.4 livre ses types avant leur comportement.** `FindingType`, `ScanTarget` et `ToolKeys` d'abord, pour que 2.6 à 2.8 compilent contre eux pendant que les jeux de référence s'écrivent.
- **2.3 et 2.5 publient d'abord leurs signatures.** 2.6 a besoin d'`Encryption` ; 2.7 de `seal` et du corps de revendication ; 2.8 des artefacts typés ; 2.9 des corps.
- **2.7 possède le `lib.rs` de `cp-scanning`.** 2.8 ne possède que ses fichiers déclarés.
- **2.10 attend l'accord du flux de l'agent sur l'extraction de la chaîne.** D'ici là, le répartiteur de 2.7 est prouvé avec des agents distants seulement.
- **2.11 démarre le premier jour**, puisque les réponses de référence existent depuis la tâche 0.5, et clôt la phase. 2.12 vient en dernier.

#### Ce qui ne se découpe pas, et ne peut qu'être différé

1. **Les identifiants d'issue des constats, et les comptes de nouvelles et de résolues d'une analyse.** Ce sont les réponses de l'arriéré. La phase 2 les compare à la `Reconciliation` que Java a enregistrée ; les vraies arrivent avec `issues` en phase 3.
2. **`GET /agent/rules/{hash}` et `GET /agent/plugins/{id}/{digest}`.** Leur contenu appartient à `rules` (phase 3) et à `plugins` (phase 4). Ils sont servis par `ScanRuleSets` et `ScanPlugins`, donc leurs réponses de référence sont différées, comme les revendications qui nomment un jeu de règles propre ou un greffon.
3. **Les chiffres d'arriéré des listes de cibles.** Les réponses de référence enregistrées avec des issues ouvertes attendent la phase 3.
4. **La suppression complète d'une cible.** Les lignes des modules suivants attendent leurs purges ; la comparaison d'une suppression en phase 2 couvre ses douze tables.
5. **La livraison du contenu de la boîte d'envoi.** Les notifications de delta d'analyse sont écrites par l'arriéré (phase 3) et livrées par `notifications` (phase 4), comme les événements SIEM.
6. **Les crates du portage de l'agent.** `protocol`, `crypto` et la chaîne d'analyse changent dans les flux de l'agent : de façon additive, et revus là-bas.

Aucun de ces points ne rend fausse une réponse de référence de la phase 2. Ils en rendent certaines plus
tardives. `golden/deferred.txt` porte une raison par réponse et ne fait que rétrécir, comme
`sql-known.toml`.

#### Risques propres à la phase 2

| Risque | Pourquoi ici | Parade |
|---|---|---|
| **Une empreinte dérive** | rien n'échoue : l'arriéré est résolu puis recréé, et tout le tri est perdu (`AGENTS.md`). La différence se cache dans le comportement de Java : `?` pour une demi-paire isolée, `strip()` et l'espace insécable, nul joint comme vide, purl vide qui retombe sur le nom | le jeu de référence de 2.4 écrit par Java, avec ces cas ; des corpus proptest hachés des deux côtés ; toute différence fait échouer la construction, sans tolérance |
| **Un `Optional` est aplati** | il résout en silence tout l'historique d'un type ([0007](../../architecture/fr/decisions/0007-none-is-not-an-empty-list.md)) ; Java l'a corrigé deux fois, pour les contrats d'API et pour la fin de vie | un cas absent et un cas vide par étape dans le jeu de référence de l'ingestion ; dans `cp-scanning`, pas d'`unwrap_or_default` sur l'`Option<Vec<_>>` d'un analyseur, imposé par une règle de lint |
| **Gros SBOM** | un résultat peut atteindre 256 Mo ; un arbre `serde_json::Value` coûte plusieurs fois le corps, qu'il faut aussi garder pour la signature | vérifier sur les octets bruts, puis lire les étapes dans des structures typées et garder le SBOM en JSON brut ; un test de mémoire avec un corps à la limite ; le `max_allowed_packet` de MySQL dans les tests moteurs |
| **Revendications concurrentes** | la revendication est une lecture, puis une mise à jour conditionnelle par candidat, sans verrou de ligne. `SKIP LOCKED` a été abandonné pour ce qu'il faisait sous MySQL, et une fenêtre plus large affamait PostgreSQL. Les deux ne se sont vus que sur de vrais serveurs | des revendicateurs en course sur MySQL et PostgreSQL, à la place d'`integrationTestAll`. Un test contre une base simulée ne compte pas comme test de revendication |
| **Deux relais, au moins une fois** | la prise d'un message est une mise à jour conditionnelle sur `next_attempt_at` ; un relais Rust à qui il manque un gestionnaire abandonne les messages en attente de Java | `OutboxClaimIntegrationTest` sur les deux moteurs ; le relais est retenu tant que le registre est incomplet ; l'exercice vérifie que `t_outbox_message` n'a pas changé |
| **Le cron de Spring** | les planifications sont stockées en texte `CronExpression` de Spring : un champ des secondes, le jour de semaine de 0 à 7, des macros. Aucune crate Rust ne les lit de la même façon | un portage de l'analyseur dans `domain`, tenu aux prochains déclenchements et aux messages de refus de Java |
| **Longueurs UTF-16** | `BoundedText` et les contrôles de longueur comptent en unités UTF-16, là où Rust compte en octets ou en caractères | portés en unités UTF-16 ; des cas de référence avec des caractères astraux |
| **Les crates de l'agent bougent** | `protocol` et `crypto` sont partagées ; un changement fait pour le serveur peut modifier les octets de l'agent | additif seulement ; les jeux de référence de l'agent restent en CI ; le flux de l'agent relit |
| **Câblé mais pas exercé** | le travailleur intégré Java n'a rien revendiqué tant qu'il a existé | 2.10 est acceptée sur une application démarrée, pas sur un test unitaire |

## 8. Recommandation

- **La phase 0 peut commencer maintenant.** C'est surtout ce dont toute décision ultérieure a besoin de toute façon : un exécuteur compatible Flyway, l'oracle, les frontières.
- **Le reste attend le point de décision 1.**
- **Pendant toute la construction, Java reste le produit.** Versions, correctifs et fonctionnalités arrivent d'abord en Java, chacun avec sa réponse de référence, pour que l'oracle suive le produit au lieu de le figer.
