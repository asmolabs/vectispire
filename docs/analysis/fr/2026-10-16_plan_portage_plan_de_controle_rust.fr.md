# Plan : porter le plan de contrôle en Rust

**Date :** 2026-10-16 · **Statut :** proposition, aucun code · **Périmètre :** `vectispire-core` et la
partie de `vectispire-common` que le portage de l'agent ne couvre pas déjà · **Schéma et contrat visés :**
la ligne 0.11.1 (`release/0.11.1-merge` b8bd7e8d0 : Flyway V1–V91, `openapi.json` à 245 chemins)

Ce plan est l'étape d'avant le code. Il mesure ce qu'il y a à porter, fixe ce qui ne doit pas changer,
choisit les bibliothèques, retient une stratégie de migration et un oracle de test, et finit par une liste
de tâches de phase 0 et de phase 1 que des agents en parallèle peuvent exécuter. Il s'appuie sur l'étude
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
- Pas d'élection de leader : chaque tâche doit supporter de tourner sur chaque instance. `MaintenanceJobsTest` vérifie la composition.
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

## 7. Tâches des phases 0 et 1

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
| 1.5 | **Rôles, visibilité, double validation** : drapeaux de `Role`, `VisibilityService`, droits d'équipe et directs, restriction de la clé, réglages de double validation | `crates/cp-access/src/authz/` |
| 1.6 | **Audit et réglages** : journal d'audit avec la chaîne continuée depuis la tête stockée, miroir fichier, magasin et types des réglages, plateforme | `crates/cp-audit/`, `crates/cp-settings/` |
| 1.7 | **Routes d'accès** : `auth`, `users`, `teams`, `api-keys`, `admin`, `security`, SCIM, contre les réponses de référence | `crates/cp-access/src/web/` |
| 1.8 | **Revue de sécurité de la phase 1** : la compétence `security-audit` sur le diff de la phase | — |

## 8. Recommandation

- **La phase 0 peut commencer maintenant.** C'est surtout ce dont toute décision ultérieure a besoin de toute façon : un exécuteur compatible Flyway, l'oracle, les frontières.
- **Le reste attend le point de décision 1.**
- **Pendant toute la construction, Java reste le produit.** Versions, correctifs et fonctionnalités arrivent d'abord en Java, chacun avec sa réponse de référence, pour que l'oracle suive le produit au lieu de le figer.
