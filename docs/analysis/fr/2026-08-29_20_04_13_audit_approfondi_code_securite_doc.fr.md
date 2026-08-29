# Audit approfondi — code, sécurité, documentation

**29 août 2026, 20:04** · *English version: [`2026-08-29_20_04_13_in_depth_code_security_doc_audit.en.md`](../en/2026-08-29_20_04_13_in_depth_code_security_doc_audit.en.md)*

## Note globale : **8,1 / 10** — en hausse depuis 8,0

Deux mouvements de sens contraire, et ce ne sont pas deux informations de même nature.

**La vérification est revenue.** L'audit du 28 août notait la vérification 5,0 parce que `main`
avait 75 commits de retard et ne portait pas `nightly.yml` : GitHub ne pouvait donc pas déclencher
la planification. `main` a désormais **3 commits de retard** et porte `nightly.yml` avec son
`cron:`. Le mécanisme est en place. C'est du terrain réellement regagné.

**Le chiffrement au repos des secrets est facultatif, et il l'a toujours été.** Trois réglages
disposent d'une route dédiée qui les chiffre avant stockage — le jeton du tracker, le secret du
webhook de ticket, et (dans l'arbre de travail) la clé d'API du fournisseur d'IA. **La route
générique `PUT /api/v1/settings` accepte les trois par leur nom et les écrit en clair**, 200 OK,
sans avertissement. Je ne l'ai pas déduit : j'ai écrit la requête et relu la colonne. Quinze audits
ont porté au crédit du produit un jeton de tracker chiffré au repos sans jamais l'écrire par
l'autre porte.

Ce second point relève surtout de « *un audit précédent avait noté ce qu'il n'avait pas mesuré* »,
et non de « *le terrain s'est dégradé* » : le contournement précède le travail en cours. Ce que le
travail en cours ajoute, c'est un troisième secret qui l'emprunte.

| Domaine | Note | Mouvement |
|---|---|---|
| Documentation & Architecture | **8,5** | ↓ |
| Sécurité & Cryptographie | **8,0** | ↓ |
| Qualité du code | **8,5** | = |
| Conformité & Standards | **8,5** | = |
| **Vérification réellement exécutée** | **7,0** | ↑↑ |

**Note de périmètre.** L'arbre de travail porte 19 fichiers modifiés et un fichier nouveau — une
fonctionnalité inachevée ajoutant un **fournisseur OpenAI à la revue par modèle**. Elle est auditée
ici parce qu'elle est ce qu'il y a de plus conséquent dans le dépôt en cet instant : elle ouvre un
chemin par lequel le code source de chaque dépôt scanné quitte le patrimoine. Les constats la
concernant sont marqués *(arbre de travail)* et ne sont l'erreur commise de personne.

---

## 1. Ce que j'ai exécuté

Tout ce tableau a été lancé. Rien n'y a été déduit de la lecture d'un fichier.

| Contrôle | Commande | Résultat |
|---|---|---|
| Suites JVM | `./gradlew build` | **1292 tests, 0 échec, 0 erreur, 0 ignoré** (255 fichiers de suite) |
| Suites Angular | `npm test` | **146 tests, 23 fichiers, 0 échec** |
| Liens relatifs | `python3 scripts/check-doc-links.py` | **712 liens, 0 cassé** |
| Dérive C4 | `shasum -a 256 workspace.dsl` vs `.workspace.sha256` | **identiques — en phase** |
| Parité documentaire | `find docs/{fr,en} -name '*.md'` | **12 / 12** |
| Registre ADR | `ls docs/architecture/{en,fr}/decisions/` | **0001 → 0017**, deux langues |
| Dossier bflorat | `ls bflorat/{en,fr}` | **5 vues + README**, deux langues |
| Isolation de l'agent | `./gradlew :vectispire-agent:dependencies --configuration runtimeClasspath` | **180 dépendances, zéro JDBC / JPA / Hikari / pilote** |
| Forme de la conformité | comptage des constantes et des littéraux de contrôle | **7 catégories, 6 référentiels, 24 contrôles** |
| Paramètres cryptographiques | constantes de `SecretCipher` / `PasswordHasher` | AES-256-GCM, **nonce 12 o, tag 128 bits, AAD, `v2:`** ; Argon2id **19 Mio, t=2, p=1** |
| Contournement du chiffrement | `PUT /api/v1/settings` via MockMvc, relecture de la colonne | **en clair — §3.1** |
| Acquittement IA | quatre enregistrements via MockMvc | **fonctionne, et ne peut être annulé — §3.2** |
| Route de la clé | `PUT`/`GET /ai-openai-key` en lecteur et en admin | **403 / 200 / 200 — §3.3** |
| Écart de branches | `git rev-list --count origin/main..develop` | **3** |
| Exercice de restauration | `bash scripts/restore-drill.sh` | **non exécuté** — exige `vectispire:latest`, non construit ici |
| Historique des exécutions GitHub | — | **non exécuté** — pas de CLI `gh` sur cette machine ; voir §5 |

### Le compte est 1292, et l'audit précédent annonçait 1371

Ce n'est pas une régression. `find vectispire-java -name '*Test.java'` renvoie **201** fichiers, et
`git ls-tree -r 73fbae5 | grep -c 'Test\.java$'` en renvoie **201** également — le même inventaire
qu'au commit de l'audit précédent, sans aucune suppression dans
`git diff --name-status 73fbae5 HEAD -- '*Test.java'`. L'écart de 79 tests est un écart de
périmètre de mesure (le chiffre antérieur comptait des fichiers de résultats laissés par une
exécution `integrationTest` dans le même répertoire de build), pas une couverture perdue. Deux
nombres produits par deux périmètres différents ne font pas une tendance, et les rapporter comme
telle serait exactement l'erreur que ce prompt existe pour empêcher.

---

## 2. Tester mes propres tests

Trois mutations. Chacune casse le code et exige que la suite tombe.

| Mutation appliquée | Attendu | Observé |
|---|---|---|
| `IssueFingerprint` : permuter `target` et `type` dans le condensé | échec | **échoue** — le vecteur littéral épinglé `44c39a41…851d` l'attrape |
| `ContainerRunner` : `withCapDrop(Capability.values())` → `withCapDrop(CHOWN)` | échec | **échoue** — `ContainerHardeningTest` |
| `SettingsController` : supprimer `@RequiresAdministrator` de `PUT /ai-openai-key` | échec | **passe.** `./gradlew :vectispire-core:test --rerun-tasks` — BUILD SUCCESSFUL, 0 échec |

Les deux premières confirment que les deux assertions dont ce projet dépend le plus sont capables
d'échouer. Le vecteur d'empreinte épinglé, ajouté après le constat du 26 août, fait son travail :
réordonner deux champs casse désormais un test au lieu de ré-indexer en silence chaque finding du
parc.

**La troisième est un constat, et c'est le §3.3.**

---

## 3. Constats

### 3.1 🔴 Le chiffrement des secrets stockés est facultatif — une seconde route les écrit en clair

**Exécuté.** Via `MockMvc`, authentifié comme administrateur :

```
PUT /api/v1/settings
{"ai_review_openai_key":"sk-PROBE-openai-key",
 "ticket_token":"PROBE-jira-token",
 "ticket_webhook_secret":"PROBE-webhook-secret"}
→ 200
```

puis relecture de la colonne via `SettingsService` :

```
PROBE stored ai_review_openai_key   = [sk-PROBE-openai-key]    encrypted=false
PROBE stored ticket_token           = [PROBE-jira-token]       encrypted=false
PROBE stored ticket_webhook_secret  = [PROBE-webhook-secret]   encrypted=false
PROBE catalog leaks openai key      = true
PROBE catalog leaks jira token      = true
PROBE reader sees openai key        = false
```

**Ce qui ne va pas.** Trois réglages disposent d'une route dédiée précisément pour que leur valeur
soit chiffrée avant d'atteindre la base — `PUT /settings/ticket-token`,
`PUT /settings/webhook-secret` et (arbre de travail) `PUT /settings/ai-openai-key`. Chacune appelle
`EncryptionService.encrypt` et stocke un blob `v2:`. La route générique du catalogue,
`SettingsController.update`
([`SettingsController.java:157`](../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/api/SettingsController.java)),
valide la clé contre le catalogue puis appelle `settings.set(...)` avec la chaîne brute.
`SettingsService.set` écrit du texte. Il n'existe aucun embranchement sur `Sensitivity.SECRET` dans
le chemin d'écriture : `isSecret()` n'est consulté qu'à un seul endroit de `vectispire-core`, et
c'est le côté *lecture* du catalogue.

`Sensitivity.SECRET` signifie donc « ne pas montrer ceci à un non-administrateur », jamais
« chiffrer ceci ». Le commentaire du nouveau réglage affirme « *Stored encrypted, like a tracker
token, and never returned by any route* ». Les deux moitiés sont fausses par cette porte : il est
stocké en clair, et `GET /api/v1/settings` le renvoie tel quel à tout rôle administratif.

**Pourquoi cela compte.** Le jeton du tracker ouvre Jira en tant que Vectispire. Le secret de
signature du webhook permet à qui le détient de forger des événements de ticket entrants. La clé du
fournisseur permet de dépenser un compte OpenAI. Les trois reposent désormais en clair dans
`t_setting` pour quiconque dispose d'une sauvegarde, d'un réplica de lecture ou d'un compte DBA —
c'est-à-dire exactement l'adversaire pour lequel `SecretCipher` a été écrit, dans une classe dont le
commentaire dit « *quelqu'un capable d'écrire dans la base* ».

**Et la fonctionnalité casse en silence.** `AiReviewService.authentication()` déchiffre la valeur
stockée et, en cas d'échec, n'envoie délibérément aucun en-tête plutôt qu'un chiffré. Une clé en
clair ne se déchiffre pas. L'opérateur saisit une clé valide dans l'écran des réglages, obtient un
200, et le test de connexion déclare l'endpoint injoignable — l'envoyant déboguer un chemin réseau
qui va très bien.

**Recommandation.** Refuser les clés `Sensitivity.SECRET` dans `SettingsController.update` avec un
message nommant la route dédiée, exactement comme les deux lignes d'acquittement le sont déjà huit
lignes plus haut. Puis l'affirmer : un test par réglage secret, écrit par la route générique,
attendant soit un 400, soit une valeur stockée commençant par `v2:`. **Vérification : exécutée** —
la sonde ci-dessus, et les deux lignes d'acquittement qui prouvent que le motif de refus existe déjà
dans cette méthode.

### 3.2 🟠 Le consentement à envoyer le code hors du patrimoine ne peut pas être retiré *(arbre de travail)*

**Exécuté.** Quatre enregistrements successifs, en administrateur :

| Requête | Statut | Corps |
|---|---|---|
| `{"ai_review_provider":"openai"}` | **422** | *« OpenAI URL: the host resolves to a public address (172.66.0.243)… »* |
| `{"ai_review_provider":"openai","ai_review_allow_remote_url":"true"}` | **200** | enregistré `by=admin-… at=2026-08-29T17:59:35Z` |
| `{"ai_review_risk_acknowledged_by":"somebody-else", …_at:"1999-01-01…"}` | **400** | *« …is recorded by the server … and cannot be set here. »* — enregistrement inchangé |
| `{"ai_review_allow_remote_url":"false"}` | **422** | *« OpenAI URL: the host resolves to a public address… »* |

Les trois premières sont le contrôle qui fonctionne, et qui fonctionne bien : la garde résout le nom
au lieu de reconnaître un motif, et un client ne peut pas forger l'identité de l'acceptant.

**La quatrième est à l'envers.** Un opérateur qui veut *cesser* d'envoyer du code source à OpenAI se
voit refuser l'enregistrement. `requireLocalUnlessAcknowledged` est évaluée sur l'état d'après
sauvegarde : le fournisseur restant `openai`, la configuration résultante est jugée illégale et
l'enregistrement entier est rejeté. La seule issue est d'envoyer le changement de fournisseur et
l'interrupteur dans la même requête — et le message ne le dit pas ; il nomme l'URL, à laquelle
l'opérateur n'a pas touché.

**Pourquoi cela compte.** Une garde qui refuse de laisser la configuration devenir *plus sûre* est
une garde tournée du mauvais côté. Et ce refus n'achète rien : `AiReview.validatedUrl()` revalide à
chaque revue, si bien qu'une configuration `provider=openai` avec acquittement éteint n'envoie tout
simplement rien. L'état sûr était déjà traité là où cela compte.

**Recommandation.** Sauter la vérification d'avant-sauvegarde lorsque la transition *retire*
l'acquittement, ou effacer le fournisseur en même temps. Dans les deux cas, garder la trace :
`clearRiskAcknowledgement` fait déjà ce qu'il faut une fois l'enregistrement autorisé.

### 3.3 🟠 La route qui écrit la clé du fournisseur est gardée, mais non testée *(arbre de travail)*

**Exécuté.** Avec le code tel qu'il est écrit, `PUT /api/v1/settings/ai-openai-key` répond **403** à
un simple lecteur et **200** à un administrateur. Le contrôle est correct aujourd'hui.

Ensuite : supprimer `@RequiresAdministrator` de cette méthode et lancer
`./gradlew :vectispire-core:test --rerun-tasks`. **BUILD SUCCESSFUL. Zéro échec.**
`AuthorizationCoverageTest` exempte `SettingsController` par son nom — légitimement, puisqu'il ne
sert rien qui appartienne à une cible — et l'exemption emporte tout le fichier, routes nouvelles
comprises.

**Pourquoi cela compte.** C'est la forme de défaut que ce projet a déjà livrée trois fois : un
contrôle qui fonctionne et une assertion incapable de remarquer qu'il a cessé de fonctionner. La
seule ligne qui sépare un simple lecteur du pouvoir d'écraser ou d'effacer la clé du fournisseur
d'IA n'a rien derrière elle.

**Recommandation.** Un `SettingsControllerTest` — il n'en existe aucun — affirmant le 403 pour un
lecteur sur les deux routes d'écriture. `ApiTestBase` fournit déjà `asReader()` et `asAdmin()` ; la
sonde qui a produit les chiffres ci-dessus fait quatre lignes.

### 3.4 🟠 La revue par modèle est absente du modèle STRIDE, et onze de ses seize flux n'ont pas de ligne

**Exécuté.** `grep -i "ollama\|LLM\|\bAI\b\|model review"` sur
[`STRIDE_THREAT_MODEL.en.md`](../../architecture/security/en/STRIDE_THREAT_MODEL.en.md) et
[`02_security_view.md`](../../architecture/bflorat/en/02_security_view.md) : **zéro correspondance
dans les deux**.

Le modèle énumère six entités externes (E1–E6), cinq processus (P1–P5) et deux magasins de données.
L'endpoint de revue par modèle — une destination externe qui reçoit **la source complète d'un dépôt
scanné**, secrets encore commités inclus — n'est aucun d'eux. C'est le flux de plus grande valeur du
produit et il n'est pas du tout dans le modèle de menaces formel. L'arbre de travail étend ce flux à
un tiers nommé, soumis à sa propre politique de rétention et à sa propre juridiction, ce qui rend
l'omission plus difficile à défendre, pas moins.

Par ailleurs, le tableau des flux est intitulé « *Data Flows in Transit (Data Flows: F1 to F16)* » et
contient **cinq lignes** : F1/F2, F12/F14, F15. Onze flux déclarés ne portent ni menace ni
mitigation. Un registre qui en annonce seize et en analyse cinq se lit, au premier regard, comme
seize analysés.

**Recommandation.** Ajouter l'endpoint de modèle en **E7** avec sa propre ligne (Information
Disclosure — code source vers un tiers ; mitigations : la garde sortante, `INTERNAL_REQUIRED` par
défaut, l'acquittement enregistré), et soit renseigner F3–F11/F13/F16, soit renuméroter l'intitulé
pour refléter ce qui est réellement couvert.

### 3.5 🟡 Le bac à sable des scanners est affirmé là où il est construit, nulle part où il s'exécute

`ContainerRunner` pose `withCapDrop(Capability.values())`, `no-new-privileges`,
`withReadonlyRootfs(true)`, `network=none` sauf demande contraire, des plafonds mémoire / nanoCPU /
PID, et un tmpfs `noexec,nosuid`. `ContainerHardeningTest` affirme chacun d'eux, et le §2 prouve
qu'il échoue quand on en retire un. C'est solide.

Ce qui n'est pas couvert : rien n'affirme que ces drapeaux *survivent jusqu'à un conteneur en cours
d'exécution*. Le seul test qui lance un vrai démon, `ContainerRunnerIntegrationTest`, réside dans
`src/integrationTest` et se trouve hors de `./gradlew build`. L'écart est petit, mais c'est le même
écart que `nightly.yml` sur la mauvaise branche : une assertion qui existe dans un jeu de sources que
personne ne lance par défaut.

### 3.6 🟡 Une chaîne anglaise en dur sur un écran par ailleurs traduit *(arbre de travail)*

[`settings.ts:133`](../../../vectispire-angular/src/app/pages/settings/settings.ts) construit la
liste des fournisseurs à partir de littéraux — `'Ollama — a model on a host you run'`,
`'OpenAI-compatible API'` — alors que chaque autre libellé deux lignes plus haut passe par
`this.i18n.t(…)`. Le bundle français n'a pas de clé pour eux : l'interface française affiche de
l'anglais.

**Pas un constat :** les 52 clés présentes dans `fr.json` et absentes de `en.json` sont *voulues*.
[`settings.ts:379`](../../../vectispire-angular/src/app/pages/settings/settings.ts) lit
`translated !== key ? translated : setting.label` — l'anglais retombe sur le libellé anglais du
serveur, et seul le français a besoin d'une surcharge. Je l'ai vérifié avant de l'écrire, parce que
le seul décompte des clés (609 contre 661) ressemble exactement à une rupture de parité.

---

## 4. Ce qui est vérifié sain

Exécuté, et correct.

- **Cryptographie.** AES-256-GCM via BouncyCastle, **nonce 12 octets, tag 128 bits, AAD de
  contexte, préfixe `v2:`** — `SecretCipher.java:33-36,153-156`. Argon2id à **19 Mio, t=2, p=1**,
  format PHC, les paramètres voyageant avec l'empreinte — `PasswordHasher.java:40-45,72`, et
  `needsRehash` compare au coût courant plutôt que de le supposer.
- **En transit vers un agent.** `SealedEnvelope` est bien X25519 + HKDF + GCM (`X25519Agreement`,
  `HKDFBytesGenerator`), scellé vers une clé publique éphémère que l'agent publie à l'enregistrement
  (`AgentProtocol.java:103`) — le plan de contrôle est hors de la frontière de confiance du secret.
- **Isolation de l'agent.** `./gradlew :vectispire-agent:dependencies --configuration
  runtimeClasspath` liste 180 dépendances et **pas un seul** pilote JDBC, ni JPA, ni Hikari. Le
  `grep` de `jdbc`, `ENCRYPTION_KEY`, `DataSource` sur `vectispire-agent/src/main` ne renvoie rien.
  C'est la forme la plus forte de l'affirmation : non pas « nous ne l'utilisons pas » mais « ce
  n'est pas sur le classpath ».
- **Bac à sable des scanners.** Vérifié plus haut ; aucun socket Docker n'atteint un scanner. Le
  plan de contrôle et l'agent en montent un (`docker-compose.yml:81,125`), ce que le bac à sable
  existe précisément pour contenir.
- **Forme de la conformité.** `ComplianceEngine` commute sur **sept** catégories
  (`ComplianceEngine.java:125-131`) ; `ComplianceFramework` déclare **six** référentiels portant
  **24** littéraux `new ComplianceControl(`. Un évaluateur, six cartographies — la formulation du
  README est exacte. `cappedByPlatform` (`:148-170`) déclasse SECRETS_MANAGEMENT, AUDIT_AND_LOGGING
  et GOVERNANCE quand le mécanisme sous-jacent est éteint : un contrôle ne peut pas être déclaré
  conforme sur la foi de quelque chose de désactivé.
- **Chaîne d'approvisionnement.** CycloneDX, CSAF, OpenVEX, EPSS et la reachability sont tous
  présents dans les sources principales ; SPDX apparaît dans trois fichiers et uniquement comme
  l'absence documentée (ADR 0016).
- **Documentation.** 712 liens relatifs, 0 cassé. Empreinte des diagrammes C4 identique à
  `workspace.dsl`. 12/12 fichiers markdown dans chaque arbre de langue. ADR 0001→0017 dans les deux
  langues — le prompt dit encore « 0001 à 0016 » ; **0017** (les vérifications personnalisées comme
  images de conteneur) a atterri dans `83461b3`.
- **Forge.** `git remote -v` → `git@github.com:asmolabs/vectispire.git`. `.gitlab-ci.yml` a
  **disparu** de `develop` (retiré dans `3668dfe`) tout en subsistant sur `main` ; le modèle livré
  aux clients `ci/gitlab/vectispire-gate.gitlab-ci.yml` demeure, à juste titre. Le paragraphe §5 du
  prompt sur le pipeline archivé à la racine est désormais périmé pour cette branche.

---

## 5. Vérification réellement exécutée — 7,0, et ce que valent les 3,0 manquants

**Regagné.** `origin/main` porte `.github/workflows/nightly.yml` avec `- cron: '30 2 * * *'` et ses
quatre jobs (`databases`, `dockerfiles`, `e2e`, `restore`). `main` a **3 commits de retard** sur
`develop`, non 75. La raison structurelle pour laquelle le nocturne ne pouvait pas se déclencher a
disparu.

**Toujours affirmé plutôt qu'exécuté, et nommé comme tel :**

- **Aucun historique d'exécution n'a été consulté.** Il n'y a pas de CLI `gh` sur cette machine : je
  ne peux pas dire quand le pipeline a été vert pour la dernière fois. Tout ce qui est dit ici de la
  CI porte sur des *fichiers*, pas sur des *exécutions*. Le constat central de l'audit précédent — un
  job déclaré n'est pas un job qui a tourné — n'est donc **pas revérifié**, seulement rendu
  structurellement possible. Cela seul plafonne le domaine sous 8.
- **L'exercice de restauration n'a pas tourné.** `scripts/restore-drill.sh` s'arrête à l'étape 0 :
  `vectispire:latest` n'est pas présente localement. L'exercice est réel et ses assertions le sont ;
  sur cette machine il est inexécuté.
- **Les E2E sont nocturnes seulement.** Les cinq spécifications Playwright tournent dans
  `nightly.yml`, pas dans `ci.yml`. Une pull request fusionne sans qu'aucun navigateur ne s'ouvre.
- **`docs.yml` est sur `develop` et pas sur `main`.** Sans conséquence pour un workflow déclenché
  par `push`, bon à savoir avant que quelqu'un lui ajoute une planification.

**Recommandation, dans l'ordre.** (1) Fusionner `develop` dans `main` pour que le nocturne exécute
l'arbre courant. (2) Consigner l'URL et la date de la première exécution verte dans
`docs/analysis/`, afin que le prochain audit puisse vérifier l'affirmation au lieu d'en hériter.
(3) Faire de `AuthorizationCoverageTest`, `RouteScopingTest` et de la suite de durcissement des
contrôles obligatoires de pull request, s'ils ne le sont pas déjà.

---

## 6. Recommandations, par priorité

| # | Constat | Action | Comment cela a été vérifié |
|---|---|---|---|
| 1 | §3.1 | Refuser `Sensitivity.SECRET` sur `PUT /api/v1/settings` ; un test par réglage secret | **Exécuté** — écriture MockMvc + relecture de la colonne |
| 2 | §3.3 | `SettingsControllerTest` : 403 pour un lecteur sur les deux routes d'écriture | **Exécuté** — garde retirée, suite core entièrement verte |
| 3 | §3.2 | Permettre le retrait de l'acquittement en une requête ; corriger le message | **Exécuté** — quatre enregistrements successifs, statuts et corps ci-dessus |
| 4 | §3.4 | Ajouter l'endpoint de modèle en E7 ; compléter ou renuméroter F1–F16 | **Exécuté** — `grep` sur les deux documents, zéro correspondance |
| 5 | §5 | Fusionner vers `main` ; consigner la première exécution verte | **Affirmé, non exécuté** — historique indisponible ici |
| 6 | §3.5 | Exécuter `integrationTest` dans le nocturne, ou replier le cas conteneur dans `build` | Lecture de l'organisation des jeux de sources ; **non exécuté** |
| 7 | §3.6 | Faire passer les deux libellés de fournisseur par `i18n.t` | **Exécuté** — diff des ensembles de clés et repli à `settings.ts:379` |

---

## 7. Ce que cet audit n'a pas pu mesurer

Dit clairement, parce qu'un audit qui n'énumère que ses trouvailles se lit comme un audit qui a
regardé partout.

- **L'historique des exécutions CI** — pas de CLI `gh`. Rien ici ne dit qu'un pipeline est passé.
- **La campagne multi-moteurs.** PostgreSQL et MySQL n'ont pas été démarrés ;
  `SchemaParityIntegrationTest` et le reste d'`integrationTest` n'ont pas tourné. Le chiffre de 1292
  est celui de la fixture SQLite.
- **L'exercice de restauration**, ci-dessus.
- **Playwright.** Les cinq spécifications n'ont pas été exécutées ; aucun navigateur ne s'est ouvert
  pendant cet audit.
- **`gitleaks`** — non installé sur cette machine. La ligne de base et la configuration ont été
  lues, pas lancées.
- **Le comportement des conteneurs à l'exécution.** Les drapeaux du bac à sable ont été vérifiés
  comme *demandés*, jamais comme *appliqués par un démon*.

---

*État de l'arbre de travail : cet audit a effectué trois mutations temporaires et ajouté un test
sonde, tous annulés. Le `git status` final est identique octet pour octet au `git status` initial —
vérifié par `diff` contre une sauvegarde de chaque fichier muté.*
