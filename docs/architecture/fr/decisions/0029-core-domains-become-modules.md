# 0029 — Les domaines cœur deviennent des modules, et les paquetages par couche disparaissent

**Date :** 2026-09-26 · **Statut :** acceptée · **Décideur :** Laurent Boucher

> Achève la [0028](0028-vertical-modules.md), qu'elle ne remplace pas : la forme d'un module, le socle
> partagé et les règles qui tiennent un module sont ceux de la 0028. Cette décision couvre l'étape 5 de
> la migration vers Spring Modulith — `targets`, `scanning` et `issues` deviennent des modules,
> `platform` et `shared` sont dissous, et `core.api`, `core.services`, `core.repositories` et
> `core.persistence` sont vidés. Ce que Modulith voit avant et après est dans
> [05 — La modularité](../05-modularity.md).
>
> Depuis l'étape 6 ([0030](0030-modulith-verifies-the-module-boundaries.md)), `MAY_USE` et les règles que
> cette décision nomme entre modules — `modulesMeetAtTheirApi`, la règle de cycles — sont à Spring
> Modulith : chaque module déclare ses dépendances autorisées sur son `package-info`, et `verify()` casse
> le build.

## Contexte

Après l'étape 4, dix-neuf domaines étaient des modules et cinq paquetages restaient les couches de
l'ancien découpage. `issues`, `scanning`, `targets`, `platform` et `shared` vivaient dans
`core.services`, leurs contrôleurs dans `core.api`, leurs tables dans `core.persistence` et
`core.repositories`. Pour Modulith, `services` était un seul module : 554 messages, 57 cycles, tous à
travers lui. La 0028 listait ce que l'étape 5 devait trancher : à qui appartiennent les tables que tous
les modules lisaient (issues, scans, findings, dépôts, conteneurs, la ligne d'agent, les politiques de
barrière), comment `targets` pouvait cesser d'appeler `access` et `scanning` alors que tous deux lisaient
les cibles, où vont les routes du socle et la tâche périodique, et deux types qui franchissaient une
frontière sans être vus.

L'étape venait avec un critère d'arrêt : si les trois domaines cœur ne pouvaient être séparés qu'en
publiant l'essentiel de leur persistance comme interfaces de requêtes nommées, ils forment un seul
domaine, et doivent être un seul module.

## Décision

### Chaque table a un propriétaire, et les autres le lui demandent

| Propriétaire | Tables | Ce que les autres modules appellent |
|---|---|---|
| `targets` | dépôts, conteneurs, projets et solutions, jetons git, clés SSH | `TargetCatalog` (vues, par identifiant, listes, les deux colonnes que d'autres modules décident : périmètre certifié, jeton de badge), `TargetNaming`, `CloneCredentials` (toujours chiffrés), `SolutionAdministrationService` |
| `scanning` | scans, findings, le bail de leader, les messages traités | `ScanCatalog` (`ScanView`, `ScanFindingView`, comptages groupés en maps), `ScanIngestor` et ses ports, `PurgedScans`, le dispatcher et le déclencheur ; `LatestScanRow` et `PackageImpact` comme interface nommée `queries` |
| `issues` | issues, événements de triage (SLA et exceptions sont calculés dessus) | `IssueCatalog` (comptages et listes par critères, agrégats, une issue en `IssueView`, les deux écritures que d'autres faisaient : un ticket rattaché, les chiffres d'exploitation du flux de menace), `PurgedIssues`, les services de triage et de décision ; `IssueFilters`, `IssueRows`, `IssueAggregates` comme interface nommée `queries` |
| `agents` | la ligne d'agent | `AgentDirectory` (un port d'`access` : quel agent détient cette clé) et `AgentClaimLock` (un port de `scanning` : le verrou de ligne de la réservation), tous deux implémentés dans `agents.internal` |
| `gate` | politiques enregistrées (avec le registre des verdicts qu'elle possédait déjà) | `ActiveGatePolicies` — la conversion ligne → politique qui vivait dans `IssueViews`, et la map des politiques actives par portée que `GateService` et le balayage des tickets construisaient chacun |

Chaque méthode d'API exécute la requête que le lecteur exécutait sur le repository, avec les mêmes
paramètres et le même ordre, et répond l'enregistrement `…View` que les routes renvoient déjà, dont les
composantes portent les noms des propriétés de l'entité — un lecteur a changé `getStatus()` en
`status()` et rien d'autre. Un tableau de colonnes ne traverse pas : un comptage groupé est une map, une
paire de colonnes de cible un `ScanOfTarget`, un finding et son scan un `FindingOnScan`.

**Les critères traversent, le prédicat non.** `IssueFilters` construisait une spécification que les
modules composaient avec leurs propres prédicats, en nommant l'entité issue pour le faire. Ce sont
désormais des critères purs — visibilité comprise, et les deux conditions que des modules ajoutaient à
la main (`touching`, `onlyCves`) sont des critères aussi. L'unique traduction en prédicat JPA est
`IssueSpecifications`, à côté du repository, dans `persistence`, où une modification déclenche la
campagne des moteurs au push. L'enregistrement des critères est publié avec les lignes
(`issues.persistence.queries`) : il ne nomme aucun type JPA, le publier c'est publier la question, pas
la table.

### Trois modules, pas un — le critère d'arrêt, mesuré

Ce que les trois modules exposent au reste de l'application :

| | classes | à la racine | dans `persistence.queries` | lu par d'autres modules hors racine |
|---|---|---|---|---|
| `targets` | 38 | 18 | 0 | rien |
| `scanning` | 41 | 17 | 2 (`LatestScanRow`, `PackageImpact`) | `LatestScanRow` |
| `issues` | 39 | 20 | 3 (`IssueFilters`, `IssueRows`, `IssueAggregates`) | les trois |

Et ce qui passe entre eux — des types, pas des messages :

- `scanning` → `targets`, dix types : les vues, `TargetCatalog`, `CloneCredentials`, `TargetNaming`,
  `CronExpressions`, l'événement de purge et ses phases, et `TargetScans`, le port qu'il implémente ;
- `issues` → `targets`, sept : les vues, `TargetCatalog`, `TargetNaming`, l'événement de purge,
  `TargetBacklog`, le port qu'il implémente ;
- `issues` → `scanning`, sept : `ScanCatalog`, les deux vues, `ObservedFinding`, `ScanIngestor` (dont il
  implémente le port `Backlog`), `PurgedScans`, et `LatestScanRow` ;
- rien de `targets` vers les deux autres, rien de `scanning` vers `issues`.

Cinq types de requêtes publiés sur 118 classes, et une poignée d'opérations définies entre les trois —
les lectures du dispatch, le port du backlog, les ports des chiffres et du déclenchement, les noms,
l'historique et les observations, la purge. Ce n'est pas « l'essentiel », donc **les trois restent des
modules distincts**. Le seul couplage restant entre leurs tables est le JPQL des balayages d'orphelins
et des jointures de composants de l'inventaire, qui nomment l'entité d'un autre module dans une chaîne
de requête ; aucune règle ne le voit, et il est listé plus bas.

### Comment les cycles ont été rompus

Les 57 cycles comptés par Modulith étaient un seul artefact de découpage — `services` vu comme un
module — posé sur une poignée de vraies dépendances à double sens entre domaines. Chacune a été rompue
dans le sens que donne le métier : un scan et une issue sont *d'une* cible et doivent apprendre sa
suppression, donc `scanning` et `issues` utilisent `targets`, jamais l'inverse.

| Dépendance à double sens | Sens gardé | Comment passe l'autre moitié |
|---|---|---|
| `targets` ↔ `scanning` (les listes lisent les scans, « scanner maintenant » ; le dispatcher lit les cibles) | `scanning` → `targets` | `TargetScans`, un port que `targets` déclare et que `scanning` implémente (`TargetScanFigures`) |
| `targets` ↔ `issues` (chiffres des listes ; les issues appartiennent aux cibles) | `issues` → `targets` | `TargetBacklog`, un port que `targets` déclare et qu'`issues` implémente (`TargetBacklogFigures`) |
| `targets` ↔ `access` (octrois écrits par les solutions ; la visibilité lit les projets) | `targets` → `access` | `access` déclare `GrantableTargets`, implémenté par `targets.internal.TargetsForAccess` ; les octrois sont révoqués par `TargetGrants`, l'API d'`access` |
| `shared.TargetNaming` lu par `access` et `scanning`, utilisés par `targets` | vers `targets` | dès que `targets` n'utilisait plus qu'`access`, les noms sont rentrés ; `shared` a disparu |
| `TargetDeleted`/`TargetPurge` dans `common.domain` pour que des modules inférieurs écoutent | vers `targets` | tous les écouteurs sont au-dessus de `targets` ; le seul propriétaire en dessous, `access`, révoque les octrois par un appel juste avant la première phase, dans la même transaction |
| `scanning` ↔ `issues` (l'ingestion écrivait les issues ; le backlog lisait les scans) | `issues` → `scanning` | `ScanIngestor.Backlog`, implémenté par `issues.internal.IssueBacklog` ; ce qui traverse est `ObservedFinding`, les valeurs entières du finding, jamais une ligne |
| `scanning` ↔ `inventory` | `inventory` → `scanning` | `ScanIngestor.InventorySink`, implémenté par `inventory` |
| `scanning` ↔ `notifications`, `threatintel` (les ports portaient des lignes) | ils utilisent `issues`/`scanning`, pas l'inverse | `ScanDelta.Sink`, un port d'`issues` ; l'enrichisseur répond des scores pour des identifiants |
| `scanning` → `rules` → `inventory` → `scanning` (latent) | `rules` → `scanning` | `ScanRuleSets`, déclaré par `scanning`, implémenté par `rules.internal.RuleSetsForScans` |
| `access`, `scanning` ↔ `agents` (la ligne d'agent) | `agents` → les deux | `AgentDirectory` et `AgentClaimLock` |
| `issues`, `tickets` lisaient les politiques sous `gate` | `tickets` → `gate` ; `issues` ne les lit plus | `ActiveGatePolicies` |
| `platform` utilisait tout et `access` purgeait les preuves de `gate` et `compliance` | rien n'utilise `platform` | le port `maintenance` (plus bas) ; chaque propriétaire purge ses propres preuves |

La purge d'une cible reste synchrone et ordonnée : une transaction, `TargetPurge.Phase` enfants d'abord,
des sondes entre les phases (`TargetDeletionTest`). La phase des findings a deux écouteurs sur une même
table : `scanning` prend les findings d'une cible par scan, `issues` par issue via `PurgedScans`.

### Les constats de la 0028

| Constat | Résolution |
|---|---|
| `AuditLogController`, `CryptoController` dans `core.api` | `platform.web` — `platform` est au-dessus d'`access` |
| `SbomDiffController` dans `core.api` | `inventory.web`, maintenant qu'`inventory` peut utiliser `scanning` |
| `OutboxService.enqueue` renvoyait l'entité du message | renvoie l'`UUID` du message |
| `RuleSetSummary`, une projection sur le fil | un record à la racine de `rules`, mêmes composantes et mêmes noms ; la projection est `RuleSetRow` ; `SchemaNameCollisionTest` refuse tout type d'un paquetage `persistence` sur une route |
| L'écran des paramètres lisait `Users` d'`access` | `TriageApprovers.anyActive` |
| L'administration des solutions écrivait les octrois d'`access` | `TargetGrants.revokeAll`, `MANDATORY` |
| Les métriques de scan comptaient via le repository d'`outbox` | `OutboxService.counts()` ; les jauges des agents sont passées dans `agents` |
| Le dispatcher recevait l'entité de `rules` | le port `ScanRuleSets` |
| `ApiExceptionHandler` associait une exception imbriquée dans la chaîne de filtres | `RequestBodyTooLargeException`, de premier niveau dans l'interface nommée `security` |
| La ligne d'agent, les politiques de barrière enregistrées | possédées par `agents` et `gate` (plus haut) |
| Où va le nettoyage des preuves | la tâche périodique de chaque propriétaire : `VerdictRetentionTask`, `SnapshotRetentionTask`, même réglage (`evidence_retention_days`), même position dans le tour, un échec ne sautant toujours que sa propre table |

### `platform` dissous : un port pour la tâche périodique, une coque pour le reste

**La tâche périodique est un port.** `MaintenanceJobs` nommait dix services de huit domaines, et c'est
pour lui que `platform` devait pouvoir tout utiliser. `maintenance`, un nouveau module du socle, déclare
`MaintenanceTask` (une cadence et un `run`) ; chaque domaine qui a un travail périodique en apporte un
depuis son paquetage `internal` — treize, de la rétention des scans aux lignes orphelines des cibles. Le
tour exécute les tâches d'une cadence dans leur `@Order` (`MaintenanceTask.Sequence`), qui garde l'ordre
d'avant et dit pourquoi deux positions comptent ; une tâche qui lève une exception termine encore son
tour, comme quand le tour était une seule méthode. `MaintenanceJobsTest` exécute le tour sur les tâches
construites sur des mocks et vérifie chaque appel dans l'ordre ; `MaintenanceCompositionTest` vérifie
que l'application en marche apporte exactement ces tâches — le niveau où un appelant manquant se voit
(le défaut `expireStale`). `outbox` → `maintenance` est la seule nouvelle arête du socle.
`RetentionService` est parti dans `scanning`, dont il purge la table.

**`platform` est la coque.** Ce qui reste compose plusieurs domaines pour un écran ou sert toute l'API :
l'écran des paramètres (les secrets et vérifications d'`ai`, `tickets`, `notifications` et `access`),
les routes du journal d'audit et de la cryptographie que le socle ne peut pas garder, le gestionnaire
d'exceptions, le renvoi vers la SPA et la configuration OpenAPI. C'est un module au-dessus de tout — il
peut utiliser n'importe quel domaine, et rien ne peut l'utiliser, ce qu'`ArchitectureTest` impose.

### Ce qui reste hors module

**`core.config`**, et rien d'autre : le mapper Jackson, l'horloge, les ordonnanceurs, les pragmas
SQLite, les placeholders de type de Flyway, l'envoi de courriel, et les politiques auxquelles les règles
pures de `common.domain` sont liées. Il sert tous les modules et ne décide rien qu'un domaine possède ;
Modulith le voit comme un module sans dépendance. Les sources de test gardent `core.api` (la suite HTTP,
qui exerce les routes de tous les modules), `core.persistence` (les tests de migration et de clés
étrangères) et `core.services` (deux tests de relecture inter-modules) comme paquetages de test ;
aucune règle ne lit les classes de test.

### Les règles, réécrites pour un seul découpage

`ArchitectureTest` ne lit plus deux découpages. Les places sont les quatre d'un module ou `core.config`
(`everyClassHasAPlace`), donc une classe remise dans `core.services` échoue ;
`everyServiceLivesInAKnownDomain` est parti avec le paquetage qu'il gardait. La règle des couches a
cinq couches, sans `repositories`. Et la convention d'écriture que portait le package-info de
`core.repositories` — toute écriture, suppressions dérivées comprises, porte `@Transactional` — est
devenue une règle quand son paquetage est parti, `everyRepositoryWriteIsTransactional`. Elle a trouvé
quinze suppressions dérivées dans cinq modules sans l'annotation, chacune ne fonctionnant que parce que
chaque appelant avait une transaction ouverte ; elles la portent désormais.

## Conséquences

- **Modulith ne signale plus aucune violation** : 25 modules (24 domaines, dont 7 partagés, et
  `config`), 0 message au lieu de 554, 0 cycle au lieu de 57. `verify()` passerait aujourd'hui ;
  l'étape 6 y convertit `ModularityObservationTest`.
- Le contrat HTTP n'a pas bougé (`openapi.json` se régénère à l'identique) et l'application démarre
  avec les mêmes 206 méthodes de handler.
- Le nouveau code va dans le module de son domaine ; un nouveau travail périodique est une
  `MaintenanceTask` dans l'`internal` du propriétaire, placée dans `Sequence` et dans
  `MaintenanceJobsTest.COMPOSITION`.
- Le filtre de chemins du job `engines` de la CI lit `core/<module>/persistence/` ; `core/repositories/`
  en a disparu.
- **Reste, et aucune règle ne le voit** : des chaînes JPQL qui nomment l'entité d'un autre module (les
  balayages d'orphelins, les jointures de l'inventaire aux scans, `AiReviewResults`,
  `Scans.findWithSbomButNoComponents`) — une instruction sur deux tables, moins chère que deux requêtes
  et une différence d'ensembles, mais un couplage que Modulith ne peut pas compter.
  `ProcessedMessageEntity` est mappée et jamais lue.
