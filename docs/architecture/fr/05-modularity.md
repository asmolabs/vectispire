# 05 — La modularité vue par Spring Modulith

> **Vérifié depuis le 2026-09-26, étape 6 de la migration vers Spring Modulith**, avec l'observation
> de l'étape 2 gardée comme référence. [`ModularityTest`](../../../vectispire-java/vectispire-core/src/test/java/com/asmolabs/vectispire/core/ModularityTest.java)
> construit le modèle Modulith du plan de contrôle, **casse le build à la première violation** —
> `ApplicationModules.verify()` — et écrit le modèle des modules et les diagrammes générés dans
> `vectispire-java/vectispire-core/build/modulith-docs/` ([décision 0030](decisions/0030-modulith-verifies-the-module-boundaries.md)).
> La production porte les annotations de Modulith et rien d'autre ; `ModulithRuntimeInertTest` échoue
> si davantage atteint le jar ou si l'un de ses beans devient actif. Les couches à l'intérieur d'un
> module restent celles d'[`ArchitectureTest`](../../../vectispire-java/vectispire-core/src/test/java/com/asmolabs/vectispire/core/ArchitectureTest.java).

## Ce que Modulith détecte : vingt-quatre domaines et `config`

Modulith prend pour modules les paquetages situés directement sous la classe de l'application,
`com.asmolabs.vectispire.core`. L'étape 2 en trouvait cinq, les couches d'un code découpé par couche —
`api`, `services`, `repositories`, `persistence`, `config` — et rien des domaines, qui étaient les
entrailles d'un seul module.

Les étapes 3 à 5 ont déplacé chaque domaine dans un paquetage à lui
([0028](decisions/0028-vertical-modules.md), [0029](decisions/0029-core-domains-become-modules.md)) :
`core.<domaine>` pour l'API, `.web` pour les contrôleurs, `.internal` pour l'implémentation,
`.persistence` pour les entités et les repositories. Modulith trouve désormais **25 modules**, et les
paquetages par couche ont disparu :

| Module | Nature | Autres domaines dont il dépend |
|---|---|---|
| `settings`, `outbound`, `crypto`, `audit`, `outbox`, `reporting`, `maintenance` | socle, **partagé** | `crypto` utilise `outbound` et `settings` ; `outbox` utilise `maintenance` |
| `access` | domaine | — |
| `siem` | domaine | `access` |
| `targets` | domaine | `access` |
| `scanning` | domaine | `access`, `targets` |
| `inventory` | domaine | `access`, `scanning`, `targets` |
| `issues` | domaine | `access`, `scanning`, `targets` |
| `ai` | domaine | `access`, `issues` |
| `notifications` | domaine | `access`, `issues`, `targets` |
| `rules` | domaine | `access`, `inventory`, `issues`, `scanning` |
| `threatintel` | domaine | `access`, `issues`, `scanning`, `siem`, `targets` |
| `agents` | domaine | `access`, `rules`, `scanning`, `targets` |
| `gate` | domaine | `access`, `issues`, `rules`, `scanning`, `siem`, `targets` |
| `exports` | domaine | `access`, `gate`, `issues`, `scanning`, `targets` |
| `posture` | domaine | `access`, `gate`, `inventory`, `issues`, `notifications`, `scanning`, `targets` |
| `tickets` | domaine | `access`, `gate`, `issues`, `targets` |
| `compliance` | domaine | `access`, `ai`, `exports`, `gate`, `inventory`, `issues`, `posture`, `rules`, `scanning`, `targets` |
| `platform` | la coque | tous ; utilisé par aucun |
| `config` | infrastructure | — |

Chaque ligne est aussi ce que déclare le `package-info` du module, dans
`@ApplicationModule(allowedDependencies = …)`, avec les interfaces nommées qu'il lit (`access::security`,
`issues::queries`, `scanning::queries`) et la raison de chaque ligne ; `verify()` échoue sur une
dépendance absente d'une liste, et `ModularityTest` sur une ligne qu'aucun usage ne demande. `access`
figure dans la plupart des lignes à travers les contrôleurs : chaque route a besoin de ses
marqueurs et résout une `Visibility`. Le socle est déclaré partagé (`@Modulithic(sharedModules = …)` sur
`VectispireApplication`) et reste fermé : ses paquetages `internal` et `persistence` sont cachés comme
ceux de n'importe quel module. Trois interfaces nommées sont publiées : `security` d'`access` (les
marqueurs de route, le principal et les aides que les contrôleurs de tous les modules utilisent), et les
`queries` de `scanning` et d'`issues` — les enregistrements dans lesquels leurs requêtes sélectionnent
et que d'autres modules lisent tels quels (`LatestScanRow`, `PackageImpact` ; `IssueFilters`,
`IssueRows`, `IssueAggregates`).

`vectispire-common` est hors du paquetage de l'application et se lit comme une bibliothèque : une
dépendance à `common.domain` est invisible pour Modulith. Depuis l'étape 5, aucun événement n'y vit
pour être vu par des modules inférieurs : `TargetDeleted` et `TargetPurge` appartiennent à `targets`,
et tous les écouteurs sont au-dessus de lui.

## Ce que `verify()` rejette

| | Avant l'étape 3 (étape 2) | Après l'étape 4 | Après l'étape 5 | Étape 6 |
|---|---|---|---|---|
| Modules | 5, toutes des couches | 24 : 19 domaines (6 partagés), 5 couches | 25 : 24 domaines (7 partagés), `config` | les mêmes 25 |
| Messages | **1 304** | **554** | **0** | **0 — et le build casse au premier** |
| `api` → types non exposés de `services` (couche → couche) | 1 304 (208 types) | 278 (50 types) | — | — |
| un module → types non exposés de `services` (module → couche) | — | 201 | — | — |
| un paquetage par couche → types non exposés d'un module | — | 18 | — | — |
| un module → types non exposés d'un autre module | — | **0** | **0** | **0** |
| cycles | 0 | 57, tous à travers `services` | **0** | **0** |
| une dépendance que la liste du module ne déclare pas | — | — | — | **0** (listes déclarées à l'étape 6) |

**`verify()` passe, et c'est la barrière.** Tous les messages que l'étape 5 laissait venaient du
découpage par couche, et ce découpage a disparu : les contrôleurs ont suivi leurs domaines, chaque
lecture des tables d'un autre module est devenue un appel à l'API du propriétaire ou un port, et les 57
cycles — un seul artefact, `services` vu comme un module, posé sur une poignée de vraies dépendances à
double sens — ont été rompus un à un, chacun dans le sens que donne le métier (la 0029 en donne le
tableau). L'étape 6 a rendu le contrôle bloquant et lui a donné le tableau : la règle de cycles,
`modulesMeetAtTheirApi` et `MAY_USE` ont quitté `ArchitectureTest` (la 0030 dit règle par règle ce qui
est parti et ce qui est resté).

**Deux choses qu'une liste de module ne sait pas dire** restent hors de `verify()`. Le socle est partagé,
et Modulith autorise tout module partagé à tout module, ceux du socle compris : `ModularityTest` tient la
liste de chaque module du socle à ce qu'il utilise. Et six modules n'utilisent `access` que pour leurs
routes — `siem`, `rules`, `inventory`, `threatintel`, `gate`, `exports` —, ce qu'une liste, une par
module, ne peut exprimer : `ArchitectureTest.accessForRoutesOnly` en tient leurs services à l'écart.

**Les couplages que ni Modulith ni ArchUnit ne peuvent compter sont des chaînes** : des requêtes JPQL qui
nomment l'entité d'un autre module. `CrossModuleQueriesTest` lit chaque requête de dépôt, rattache les
entités, tables et classes qu'elle nomme à leur module, et échoue sur une référence que sa liste ne porte
pas. Il en trouve onze — les balayages d'orphelins d'`Issues` et de `Scans` (les tables de `targets`),
les cinq jointures de l'inventaire aux scans qui ont vu chaque composant,
`AiReviewResults.latestForRepository` (les scans), et `Scans.findWithSbomButNoComponents`, qui lit
`inventory` depuis `scanning`, à contresens des modules, et le dit. Chacune est une instruction sur deux
tables, moins chère que deux requêtes et une différence d'ensembles ; la dernière est celle à déplacer.

## Ce qui a changé avant cette observation (étape 1)

L'observation de l'étape 2 a été faite après avoir défait les nœuds que la décision 0026 avait consignés, pour que
ce que Modulith vérifiera plus tard parte d'un graphe sans exception connue :

- **Les deux cycles consignés ont disparu.** `audit` → `siem` : la vérification de la chaîne publie
  un événement `AuditChainBroken` que le SIEM écoute, au lieu de l'appeler — un écouteur synchrone
  ordinaire, parce que la vérification n'ouvre aucune transaction et qu'un écouteur après commit
  perdrait l'alerte. `issues` → `tickets` : `issues` déclare un port `TicketReferences`, que `tickets`
  implémente. `ArchitectureTest.KNOWN_CYCLES` est vide.
- **La suppression d'une cible est un événement.** `TargetDeletionService` supprimait des lignes dans
  les tables de sept domaines. Il publie maintenant `TargetDeleted` dans la transaction de
  suppression, et chaque domaine propriétaire purge ses propres lignes dans un écouteur synchrone qui
  exige cette transaction — la purge et la suppression sont validées ensemble ou pas du tout. L'ordre
  est explicite, les enfants avant les parents (`TargetPurge.Phase`), pour que la purge ne dépende pas
  d'une cascade que SQLite n'honore que tant qu'un pragma est émis. Écrire le test a révélé qu'un
  dépôt portant le moindre historique de tri ne pouvait pas être supprimé ; c'est corrigé.
- **`ReportCursor` a quitté `shared`** pour un domaine de fondation `reporting` ;
  `ReachabilityAnalyzer`, un service que rien n'appelait, a été supprimé.

## Ce qu'ont changé les étapes 3 et 4

- **Dix-neuf domaines sont devenus des modules**, le socle d'abord ; 262 classes, avec leurs
  contrôleurs, entités, repositories et tests.
- **`core.api.security` est devenu une partie d'`access`** : `core.access.web.security`, l'interface
  nommée, et `.chain` en dessous pour les filtres.
- **Neuf lectures des tables d'un autre module sont devenues des appels d'API ou des ports**, et six
  dépendances que le découpage par couche cachait sont devenues des lignes de `MAY_USE`, chacune avec sa
  raison.

## Ce qu'a changé l'étape 5

- **`targets`, `scanning` et `issues` sont des modules**, et chacun possède ses tables : les autres
  interrogent `TargetCatalog`, `ScanCatalog` et `IssueCatalog`, qui exécutent les mêmes requêtes et
  répondent les vues que les routes renvoient déjà. `agents` possède la ligne d'agent et `gate` les
  politiques enregistrées, chacune lue d'en dessous par un port. Trois modules plutôt qu'un : les
  interfaces de requêtes nommées publient cinq types sur 118 classes, et une poignée d'opérations
  définies passent entre les trois (la 0029 les compte).
- **`platform` est dissous.** La tâche périodique est un port — `maintenance.MaintenanceTask`, apporté
  par treize tâches des modules qui possèdent le travail, dont les purges de preuves qu'`access`
  exécutait pour `gate` et `compliance` — et `platform` est la coque qui reste : l'écran des paramètres,
  les routes du socle, le gestionnaire d'exceptions, le renvoi vers la SPA et la configuration OpenAPI.
  `shared` a disparu : `TargetNaming` est parti dans `targets`.
- **`core.api`, `core.services`, `core.repositories` et `core.persistence` sont vides.** `core.config`
  est le seul paquetage hors module. Le contrat n'a pas bougé (`openapi.json` se régénère à
  l'identique), et l'application démarre avec les mêmes 206 méthodes de routage.
- **Chaque règle lit un seul découpage** : la règle des couches a perdu sa couche `repositories`, les
  places sont les quatre d'un module ou `config`, et la convention d'écriture des repositories est
  devenue une règle, `everyRepositoryWriteIsTransactional` — qui a trouvé quinze suppressions dérivées
  sans `@Transactional`.

## Ce qu'a changé l'étape 6

- **`ModularityObservationTest` est devenu `ModularityTest`**, qui appelle `verify()` et casse le build ;
  il écrit toujours les fiches et les diagrammes de composants C4.
- **Chaque module déclare ce qu'il peut utiliser**, sur son `package-info`, avec les raisons que portait
  `MAY_USE` ; seul `platform` ne déclare rien, ce qui pour Modulith veut dire « tout ». Les interfaces
  nommées se listent par leur nom : les listes disent donc quels modules lisent `issues::queries`,
  `scanning::queries` et `access::security`.
- **`ArchitectureTest` garde l'intérieur d'un module** : les couches, les quatre places, ce qu'un
  contrôleur, une entité ou un dépôt peut toucher. Retirées, chacune remplacée par `verify()` : la règle
  de cycles avec `KNOWN_CYCLES`, `modulesMeetAtTheirApi`, `domainsDependOnlyWhereAllowed` avec `MAY_USE`.
- **Les chaînes de requête sont contrôlées** (`CrossModuleQueriesTest`), avec la liste ci-dessus.
- **La production ne dépend plus que de `spring-modulith-api`** : le starter core, son modèle
  d'exécution, ses moments, son processeur d'annotations, jMolecules et ArchUnit ont quitté le jar
  (de 122 379 585 à 117 310 636 octets), et l'application démarre avec les mêmes 208 routes.
