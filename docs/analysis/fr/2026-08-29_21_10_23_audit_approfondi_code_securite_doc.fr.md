# Audit approfondi — code, sécurité, documentation

**29 août 2026, 21:10** · *English version: [`2026-08-29_21_10_23_in_depth_code_security_doc_audit.en.md`](../en/2026-08-29_21_10_23_in_depth_code_security_doc_audit.en.md)*

## Note globale : **8,4 / 10** — en hausse depuis 8,1

**C'est le premier audit de la série avec un démon Docker sur la machine.** Tout ce que l'audit de
20:04 listait sous « ce que cet audit n'a pas pu mesurer » — la campagne multi-moteurs, le
comportement des conteneurs à l'exécution, la suite navigateur, l'exercice de restauration — a été
exécuté ici. Trois des cinq domaines bougent en conséquence, et pas dans le même sens.

**La vérification monte parce qu'elle a été faite, pas parce qu'elle s'est améliorée.** 87 tests de
campagne sur PostgreSQL, MySQL et SQLite ; 14 cas conteneur contre un vrai démon ; 13 cas Playwright
dans un vrai navigateur contre un vrai plan de contrôle ; l'exercice de restauration de bout en
bout, mutation intégrée comprise. Rien de tout cela n'avait jamais tourné dans cette série.

**Deux domaines baissent, et ce n'est une dégradation ni pour l'un ni pour l'autre.** Les deux
constats ci-dessous sont du terrain que des audits antérieurs ont noté sans le mesurer :

- **La double validation ne couvre qu'un des deux statuts qui règlent un constat.** Avec
  `triage_four_eyes_required` actif, un simple lecteur marquant `not_affected` tombe correctement en
  `pending_approval` — et le même lecteur marquant `fixed` le règle sur-le-champ, HTTP 200, sans
  seconde personne. `FIXED` cesse de faire échouer les builds exactement comme `NOT_AFFECTED`.
  L'aide du réglage promet les deux.
- **Trois points d'entrée HTTP chargent toute la table des constats.** Mesuré à trois tailles de
  parc : 23 → 223 → **623** chargements d'entités pour 20 → 220 → 620 constats. L'un d'eux est
  `/api/v1/dashboard`, la page sur laquelle chaque compte arrive en se connectant.

| Domaine | Note | Mouvement |
|---|---|---|
| Documentation & Architecture | **9,0** | ↑ |
| Sécurité & Cryptographie | **8,0** | = |
| Qualité du code | **8,0** | ↓ |
| Conformité & Standards | **8,0** | ↓ |
| **Vérification réellement exécutée** | **9,0** | ↑↑ |

---

## 0. État de remédiation — les deux constats sont fermés

*Ajouté après l'audit. Vérification complète après les changements : **1326 tests JVM** (1320 avant,
+6), **0 échec**, et la campagne trois moteurs de nouveau verte — **PostgreSQL 29, MySQL 29,
SQLite 29** — ce qui compte ici, une projection DTO ne générant pas le même SQL sur chaque dialecte.*

| # | Constat | Fermé par | Preuve qu'il peut échouer |
|---|---|---|---|
| §3.1 | Les quatre yeux ne couvraient pas `FIXED` | La file d'approbation s'ouvre sur `status().isSettled()` — la propriété qui signifie déjà « sort du verdict de gate » — au lieu de nommer `NOT_AFFECTED`, dans `IssueTriageService`, et la branche d'approbation d'`apply` est élargie de même. Deux cas ajoutés à `BulkTriageRoutesTest` : un lecteur qui déclare `fixed` est mis en file, et le demandeur ne peut ensuite pas s'accorder son propre correctif. | Les deux nouveaux cas échouent contre l'ancienne condition — écrits avant le correctif, ils ont échoué. |
| §3.2 | Lectures de table entière | Cinq lectures converties en projections de colonnes via `IssueRows` (`Lifespan`, `Resolution`, `Observation`, `Attribution`, `GateRow`). `ReadCostRoutesTest` épingle quatre routes avec le compteur d'entités d'Hibernate. | Un `findAll` remis dans `SlaService` → **1 test échoue**. |

### Le problème d'ordre que le correctif a mis au jour

Élargir la file a cassé une règle voisine, et l'interaction mérite d'être consignée.
`Triage.decide` exige une justification VEX pour `PENDING_APPROVAL` — ce qui était juste tant que la
file ne pouvait contenir que des exemptions, une exemption sans justification s'exportant en
statement VEX invalide. Un **correctif** mis en file n'est pas une exemption et n'a pas de
justification de ce genre à donner : chaque `fixed` d'un lecteur revenait donc en 400.

Le correctif est un ordre, pas une exception : valider la décision que l'opérateur a réellement
demandée, puis mettre le résultat en file. `resolveRequest` (sur la requête, avant validation) est
devenu `queueIfNotApprover` (sur la décision, après). Une exemption ne peut toujours pas entrer en
file sans sa justification ; un correctif ne s'en voit plus réclamer une.

### Et une correction de l'attribution du §3.2

L'audit nommait quatre sites `findAll`. La mesure du correctif en a trouvé **cinq**, et l'un des
quatre était faux : `/api/v1/dashboard` ne lit pas par `DashboardController:237` mais par
`GateService.openIssuesByTarget()`, et le sommaire de conformité est resté linéaire après quatre
conversions à cause d'une cinquième lecture que personne n'avait nommée —
`SlaService.countOverdueByTarget`, qui charge chaque constat en retard du parc pour les grouper par
cible et n'en lit que deux colonnes. C'est la mesure qui l'a trouvée ; relire les quatre sites
nommés ne l'aurait pas fait.

---


## 1. Ce que j'ai exécuté

| Contrôle | Commande | Résultat |
|---|---|---|
| Suites JVM, à froid | `./gradlew build --rerun-tasks` | **1320 tests, 0 échec, 0 erreur, 0 ignoré** (259 suites, 35 tâches exécutées) |
| **Campagne multi-moteurs** | `./gradlew integrationTestAll` | **PostgreSQL 29, MySQL 29, SQLite 29 — 87 tests, 0 échec** |
| **Conteneurs à l'exécution** | `./gradlew :vectispire-common:integrationTest` | **14 cas, 0 échec**, contre un démon vivant |
| **Suite navigateur** | `npx playwright test` | **13 passés** en 2,2 min, vrai plan de contrôle, vrai Chromium |
| **Exercice de restauration** | `bash scripts/restore-drill.sh` | **passé**, sa propre mutation comprise |
| **Image livrée** | `docker build -f Dockerfile -t vectispire:latest .` | **construite, 347 Mo** |
| Suites Angular | `npm test` | **146 tests, 23 fichiers, 0 échec** |
| Liens relatifs | `python3 scripts/check-doc-links.py` | **730 liens, 0 cassé** |
| Dérive C4 | `shasum -a 256` vs `.workspace.sha256` | **identiques — en phase** |
| Parité bilingue | `find docs/{fr,en} -name '*.md'` | **12 / 12** |
| Registre ADR | `ls docs/architecture/{en,fr}/decisions/` | **0001 → 0017**, deux langues |
| Couverture des quatre yeux | MockMvc, les deux statuts réglants | **à moitié couverte — §3.1** |
| Coût des lectures | compteurs Hibernate, 3 tailles de parc | **trois points d'entrée linéaires — §3.2** |
| Écart de branches | `git rev-list --count origin/main..develop` | **9** — c'était 3 ce matin |
| Historique GitHub | — | **non exécuté** — toujours pas de CLI `gh` |
| `gitleaks` | — | **non exécuté** — non installé |

### La campagne, nommée

Sept suites, chacune lancée trois fois — une par moteur : `SingleSignOnIntegrationTest` (un vrai
conteneur Keycloak), `SchemaParityIntegrationTest`, `HistoryQueriesIntegrationTest`,
`ScanQueueIntegrationTest`, `ComplianceSummaryIntegrationTest`, `LeaderElectionIntegrationTest`,
`SecurityDebtIntegrationTest`. Les migrations Flyway s'appliquent et le schéma valide sur les deux
moteurs déployables et sur la fixture SQLite — l'affirmation sur laquelle reposent les ADR 0013/0014,
vérifiée au lieu d'être répétée.

### Le bac à sable, tel qu'un démon l'applique et non tel que le code le demande

L'audit de 20:04 pouvait affirmer que les drapeaux étaient *posés* et marquait l'écart d'exécution
🟡. Les 14 cas tournent désormais : *toutes les capacités sont retirées*, *aucun processus ne peut
gagner de privilèges*, *le système de fichiers de l'image n'est pas modifiable*, *un montage
read-only ne s'écrit pas*, *l'espace de travail est inscriptible et non exécutable*, *le réseau est
coupé sauf si la tâche le demande* — et sa réciproque — *un scanner trop long est arrêté, pas
abandonné*. Cela ferme le §3.5 de l'audit précédent, par la mesure.

---

## 2. Tester mes propres tests

Deux assertions que cette série n'avait jamais mutées, plus une correction de ma propre méthode.

| Mutation appliquée | Attendu | Observé |
|---|---|---|
| `AuditLogService` : `row.setPreviousHash(previousHash)` → `setPreviousHash(null)` | échec | **échoue** — *« the audit log's integrity chain › eachEntryChainsOntoTheOneBefore »* |
| `ContainerRunner.parseJson` : une sortie vide renvoie `Optional.of(tableauVide)` au lieu de `Optional.empty()` | échec | **2 tests échouent** — *« an absent result is not an empty one »* et *« records the failure rather than reporting a completed scan with nothing in it »* (ADR 0007) |

La seconde est la règle ADR 0007 soumise à sa propre mutation pour la première fois : une liste vide
résout tous les constats existants de ce type, un résultat absent ne change rien. La distinction est
affirmée, et elle mord.

### Et une correction de ma part, consignée parce que la méthode l'exige

Ma première exécution Playwright a rapporté **10 échecs sur 13**, dont un cas de sécurité —
*« an MFA challenge cannot be brute-forced with unlimited guesses »*. C'aurait été le titre de ce
rapport. C'était mon erreur : j'avais démarré le plan de contrôle sans
`VECTISPIRE_BOOTSTRAP_PASSWORD`, que le job nocturne fixe, donc aucun compte d'amorçage n'existait
et `signIn` ne pouvait pas s'authentifier. Relancée avec l'environnement complet du job — les cinq
variables de `nightly.yml`, `SPRING_JPA_HIBERNATE_DDL_AUTO=none` et le plafond de tentatives relevé
compris — **13 sur 13 passent**. Un test qui échoue est une affirmation comme une autre, et il doit
être exécuté correctement avant d'être rapporté.

---

## 3. Constats

### 3.1 🔴 La double validation ne couvre pas `FIXED`, et le rapport de conformité compte comme si elle le faisait

**Exécuté.** Avec `triage_four_eyes_required = true`, en simple `USER` (`Role.USER`,
`canApproveTriage = false`), à travers la vraie chaîne de filtres :

```
PROBE four_eyes_required = true
PROBE reader not_affected -> HTTP 200 status=pending_approval settled=false
PROBE reader fixed        -> HTTP 200 status=fixed           settled=true
```

**Ce qui ne va pas.** `IssueTriageService.resolveRequest` bascule une demande en
`PENDING_APPROVAL` à une seule condition :

```java
if (!canApprove && request != null && request.status() == TriageStatus.NOT_AFFECTED) {
```

`TriageStatus` marque **deux** statuts comme réglants — `NOT_AFFECTED(true)` et `FIXED(true)` — et
c'est `isSettled()` qui sort un constat du verdict de gate. Un lecteur ne peut pas écarter un
constat comme inapplicable sans une seconde personne ; le même lecteur peut le déclarer corrigé,
seul, et il cesse de faire échouer les builds tout pareil.

L'aide du réglage, celle que lit l'opérateur avant de l'activer, dit : *« marking an issue as
NOT_AFFECTED **or FIXED** by a user without CISO/Admin approval privileges creates a
PENDING_APPROVAL request. »* La moitié de cette phrase n'est pas implémentée.

**Pourquoi cela dépasse le triage.** `ComplianceService:158` injecte ce réglage dans
`ComplianceEngine.cappedByPlatform`, qui plafonne GOVERNANCE à 75 quand les quatre yeux sont
**éteints**, avec ce motif : *« le compte qui lève une exemption peut aussi l'accorder — le verdict
de gate ci-dessous est consultatif et non appliqué »*. **Allumés**, l'évaluation passe sans
plafond — alors que le compte qui veut écarter un constat peut toujours l'y mettre seul, en
choisissant l'autre mot. `cappedByPlatform` existe précisément pour qu'un contrôle ne soit jamais
déclaré conforme sur la foi d'un mécanisme éteint ; ici il l'est sur la foi d'un mécanisme à moitié
allumé, et la projection atteint les contrôles GOVERNANCE de DORA et de NIS 2.

**Ce qui est juste dans le code alentour**, pour que le correctif ne le défasse pas :
`requireASecondPairOfEyes` est un travail soigné. Il lit le demandeur dans l'**historique des
événements** et non dans la ligne — `triagedBy` est écrasé par chaque décision, donc à l'heure de
l'approbation la ligne nomme déjà l'approbateur —, compare sans tenir compte de la casse, et
documente le seul cas qu'il admet délibérément (une demande antérieure sans acteur enregistré, que
refuser laisserait sans issue). C'est du maker-checker compté en deux personnes et non en deux
rôles, et c'est correct. Simplement, on ne l'atteint jamais pour `FIXED`.

**Recommandation.** Élargir la condition à `request.status().isSettled()` — la propriété qui existe
déjà et signifie déjà « sort du verdict de gate » — plutôt que de renommer les deux statuts. Puis
affirmer les deux chemins : `BulkTriageRoutesTest` couvre `not_affected` et n'a aucun cas pour
`fixed`, ce qui est la raison pour laquelle ceci a survécu. **Vérification : exécutée** — sonde
ci-dessus.

### 3.2 🟠 Trois points d'entrée HTTP chargent toute la table des constats, dont le tableau de bord

**Exécuté.** Compteurs Hibernate `getEntityLoadCount` / `getQueryExecutionCount`, même requête,
trois tailles de parc :

| Route | charg. @20 | charg. @220 | charg. @620 | requêtes @620 |
|---|---|---|---|---|
| `/api/v1/dashboard` | 23 | 223 | **623** | 15 |
| `/api/v1/dashboard/trends` | 22 | 222 | **622** | 1 |
| `/api/v1/compliance/summary` | 23 | 223 | **623** | 19 |
| `/api/v1/issues?page=0&size=20` | 23 | 53 | 53 | 3 |
| `/api/v1/repositories` | 3 | 3 | 3 | 3 |
| `/api/v1/licenses/summary` | 4 | 4 | 4 | 3 |

Exactement `n + 2` et `n + 3`. Le nombre de requêtes reste constant : ce n'est **pas** un N+1, c'est
une requête qui renvoie toutes les lignes. La route paginée des constats plafonne à 53 et les deux
autres sont constantes — ce sont des lectures bornées, et le contraste est ce qui rend les trois
premières sans ambiguïté.

**D'où cela vient.** Quatre appels `findAll` qui matérialisent des `IssueEntity` complètes pour en
lire deux ou trois colonnes :

- [`DashboardController:211`](../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/api/DashboardController.java) — chaque constat, projeté en `BacklogTrend.Lifespan(firstSeenAt, resolvedAt)`
- `DashboardController:237` — la même forme sur la racine du tableau de bord
- [`ComplianceService:250`](../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/services/ComplianceService.java) et `:379` — projetés en `MttrCalculator.ResolvedIssue(severity, firstSeenAt, resolvedAt)`

**Le besoin est légitime ; la lecture ne l'est pas.** Le commentaire de `trends` a raison : la courbe
a besoin de la durée de vie de chaque constat — *« un constat résolu dans la fenêtre doit être compté
comme ouvert les jours précédents, sinon la courbe démarrerait au backlog d'aujourd'hui et
prétendrait que l'histoire a toujours été aussi belle »*. Deux horodatages par constat, c'est une
petite réponse. Une entité complète par constat, non : aux 500 000 lignes qu'un audit antérieur
estimait pour un vrai parc, ouvrir le tableau de bord matérialise 500 000 objets, avec leurs
chaînes, sur le thread de la requête.

**Pourquoi aucun audit antérieur ne l'a vu.** La passe du 25 août a trouvé sept points d'entrée
lisant tout `t_finding`, et ils ont été corrigés ; `AttackPathDatabaseTest` et
`BlastRadiusDatabaseTest` affirment désormais un coût de lecture et sont les deux seuls à le faire.
Personne n'a compté `t_issue`. C'est « *un audit précédent avait noté ce qu'il n'avait pas mesuré* »,
et non du terrain qui se dégrade.

**Recommandation.** Une requête de projection renvoyant les deux ou trois colonnes — `select new
BacklogTrend.Lifespan(i.firstSeenAt, i.resolvedAt) …` — donne la même réponse sans matérialiser
d'entités. Puis l'épingler comme les deux autres le sont : une assertion sur le nombre d'entités
chargées, qui ne bouge pas quand la fixture grossit autour de la requête.

### 3.3 🟡 `main` est passé de 3 commits de retard à 9, et le nocturne s'exécute depuis `main`

L'audit de 20:04 enregistrait la reconquête : `main` portait `nightly.yml` avec son `cron:` et avait
3 commits de retard. Il en a désormais **9** — les trois correctifs de cet audit, la fonctionnalité
IA et deux autres sont tous sur `develop` seulement. GitHub n'exécute un workflow planifié que depuis
la branche par défaut : le nocturne de cette nuit exécutera l'arbre *sans* le correctif de
chiffrement des credentials, sans `SettingsRoutesTest` et sans `AiReviewConsentTest`. Le mécanisme
fonctionne ; il est pointé sur un arbre vieux d'une semaine.

**Recommandation.** Fusionner `develop` dans `main`. C'est désormais l'action au meilleur rapport sur
l'axe vérification, et elle coûte une fusion.

### 3.4 🟡 Une chaîne anglaise en dur sur un écran par ailleurs traduit — toujours ouvert

Rapporté à 20:04 comme §3.6, inchangé :
[`settings.ts:143-144`](../../../vectispire-angular/src/app/pages/settings/settings.ts) construit la
liste des fournisseurs à partir de littéraux — `'Ollama — a model on a host you run'`,
`'OpenAI-compatible API'` — alors que chaque autre libellé deux lignes plus haut passe par
`this.i18n.t(…)`. Le bundle français n'a pas de clé pour eux.

*Toujours pas un constat, revérifié :* les 52 clés de `fr.json` absentes de `en.json` sont voulues —
`settings.ts:379` lit `translated !== key ? translated : setting.label`, donc l'anglais retombe sur
le libellé anglais du serveur et seul le français a besoin d'une surcharge.

---

## 4. Ce qui est vérifié sain

Exécuté cette fois, et correct.

- **Portabilité.** 87 tests sur PostgreSQL 16, MySQL 8 et SQLite. `SchemaParityIntegrationTest` vert
  sur les trois : les migrations Flyway multi-dialectes et `ddl-auto: validate` tiennent.
- **Fédération.** `SingleSignOnIntegrationTest` tourne contre un vrai conteneur Keycloak, trois fois.
- **Le bac à sable, à l'exécution.** Voir §1.
- **La chaîne d'audit.** Mutée et attrapée (§2). L'exercice de restauration va plus loin : il vérifie
  que la chaîne **survit à une restauration**, que le miroir signale les 5 entrées perdues par la
  table restaurée, et — dans sa propre mutation intégrée — que restaurer le miroir en même temps que
  la base rend la perte invisible à `intact` alors que `missingFromMirror` en porte encore le signal.
  Un exercice qui teste son propre angle mort est rare et mérite d'être dit.
- **Force brute et MFA.** Exécutés dans un navigateur : *une rafale de connexions déclenche le
  429 Bucket4j*, *un challenge MFA ne se force pas par essais illimités*, tous deux verts contre un
  plan de contrôle vivant.
- **Le registre ADR a de la substance.** 0001 → 0017 dans les deux langues. Les quatre fichiers les
  plus courts — 0004, 0008, 0009, 0011 — le sont parce qu'ils sont **remplacés**, chacun portant son
  statut, sa date, son successeur et ce qu'il remplace : `0004 → 0008 → 0009 → 0014` et
  `0011 → 0013`. C'est un registre de décisions dont les renversements sont consignés, ce que le
  prompt demande précisément de vérifier.
- **Documentation.** 730 liens, 0 cassé. Empreinte C4 identique. 12/12 par arbre de langue. Le modèle
  STRIDE porte désormais **E7** (l'endpoint de revue par modèle) avec six lignes, **TB5** et **F17**,
  dans les deux langues — le constat §3.4 de l'audit de 20:04, vérifié fermé.
- **Constats précédents.** Les cinq de 20:04 tiennent sous une construction à froid : les routes de
  credentials refusent le chemin générique, l'acquittement se retire, `SettingsRoutesTest` et
  `AiReviewConsentTest` sont dans les 1320.
- **Forge.** `git remote -v` → `git@github.com:asmolabs/vectispire.git`.

---

## 5. Vérification réellement exécutée — 9,0, et ce que valent les 1,0 manquants

Presque tout ce que le pipeline revendique est désormais exécuté *ici*. Ce qui reste est l'écart
entre « ça passe sur cette machine » et « ça est passé sur le runner » :

- **Aucun historique d'exécution n'a été lu.** Toujours pas de CLI `gh`. Rien dans ce rapport ne dit
  qu'un job GitHub a jamais été vert. Tout le §1 a été exécuté localement, ce qui est une
  affirmation plus forte que lire un fichier et plus faible qu'un pipeline vert.
- **Le nocturne pointe sur un arbre périmé** — §3.3.
- **`gitleaks` n'a pas tourné** — non installé. Configuration et ligne de base lues, pas exécutées.
- **Jib n'a pas pu construire.** `./gradlew :vectispire-core:jibDockerBuild` échoue localement en
  tirant `eclipse-temurin` depuis Docker Hub (pull non authentifié). La voie `Dockerfile` — celle qui
  est livrée — a construit sans problème. Environnemental ici ; bon à savoir que le job `images`
  dépend d'un pull de registre qui peut être limité.

---

## 6. Recommandations, par priorité

| # | Constat | Action | Comment cela a été vérifié |
|---|---|---|---|
| 1 | §3.1 | `resolveRequest` : conditionner sur `status().isSettled()` et non sur `NOT_AFFECTED` ; ajouter le cas `fixed` à `BulkTriageRoutesTest` | **Exécuté** — les deux statuts poussés dans la vraie chaîne |
| 2 | §3.2 | Requêtes de projection aux quatre sites `findAll` ; épingler le coût par une assertion de chargement d'entités | **Exécuté** — compteurs Hibernate à 20 / 220 / 620 |
| 3 | §3.3 | Fusionner `develop` dans `main` pour que le nocturne exécute l'arbre courant | **Exécuté** — `git rev-list --count` = 9 |
| 4 | §3.1 | Revoir la cartographie GOVERNANCE une fois le correctif posé : l'évaluation est déplafonnée sur la foi de ce contrôle | **Exécuté** — `ComplianceEngine:170` lu face au résultat de la sonde |
| 5 | §3.4 | Faire passer les deux libellés de fournisseur par `i18n.t` | **Exécuté** — diff des ensembles de clés et repli à `settings.ts:379` |
| 6 | §5 | Consigner l'URL et la date de la première exécution GitHub verte dans `docs/analysis/` | **Affirmé, non exécuté** |

---

## 7. Ce que cet audit n'a pas pu mesurer

- **L'historique des exécutions CI** — pas de CLI `gh`.
- **`gitleaks`** — non installé.
- **La construction d'image par Jib** — bloquée sur un pull Docker Hub, §5.
- **L'échelle.** La mesure du coût des lectures plafonne à 620 constats, sur SQLite. La linéarité y
  est sans ambiguïté ; le coût en temps réel à 500 000 sur PostgreSQL en est déduit, pas mesuré.
- **L'agent, de bout en bout.** L'isolation de `vectispire-agent` a été vérifiée par le classpath
  dans l'audit précédent et n'a pas été rejouée ici ; aucun processus agent n'a été démarré.

---

*Arbre de travail : cet audit a ajouté un test sonde puis l'a retiré, et appliqué deux mutations
temporaires, toutes deux annulées. Le `./gradlew build --rerun-tasks` final a exécuté les 35 tâches
à froid et est passé. Le seul travail non commité est la documentation de l'audit de 20:04 et
`AiReviewConsentTest`, qui lui sont antérieurs.*
