# 0030 — Spring Modulith vérifie les frontières des modules, et ArchUnit garde les couches

**Date :** 2026-09-26 · **Statut :** acceptée · **Remplace :** [0026](0026-services-are-grouped-by-domain.md) · **Décideur :** Laurent Boucher

> Étape 6 de la migration vers Spring Modulith. La forme d'un module et le socle sont ceux de la
> [0028](0028-vertical-modules.md), les propriétaires et les ports ceux de la
> [0029](0029-core-domains-become-modules.md) ; aucune n'est remplacée. Ce que cette décision remplace,
> c'est la réponse de la 0026 à « qui vérifie les frontières » : la 0026 avait écarté Modulith *pour
> l'instant* et fait d'un tableau ArchUnit la référence. Ce que Modulith voit est dans
> [05 — La modularité](../05-modularity.md).

## Contexte

Après l'étape 5, Spring Modulith voyait vingt-cinq modules — vingt-quatre domaines, dont sept
partagés, et `config` — et `verify()` n'aurait rien signalé. La frontière entre modules était vérifiée
deux fois : par Modulith en observation, qui n'échouait sur rien, et par quatre règles ArchUnit qui,
elles, cassaient le build — une règle de cycles découpée par module avec ses `KNOWN_CYCLES`,
`modulesMeetAtTheirApi` (la racine d'un autre module ou une interface nommée, rien d'autre), et
`domainsDependOnlyWhereAllowed`, qui lisait le tableau `MAY_USE` des décisions 0026, 0028 et 0029.

Deux autorités pour une frontière, c'est la situation que `ddl-auto: validate` évite pour le schéma :
elles s'accordent aujourd'hui, et le jour où elles divergent, celle qui passe en second gagne sans
bruit. La 0026 avait écarté Modulith pour trois raisons. La première — le code était rangé par couche,
Modulith aurait donc vu des couches — a disparu : l'étape 5 a vidé les paquetages par couche, et la
0026 nommait précisément cette condition pour reconsidérer. La deuxième — son registre d'événements
doublerait l'outbox — tient toujours, et ce n'est pas ce qui est pris ici. La troisième — la
vérification était déjà couverte — est le doublon auquel cette décision met fin.

## Décision

**`ModularityTest` appelle `ApplicationModules.verify()` et casse le build à la première violation.**
Il remplace `ModularityObservationTest`, et écrit toujours les fiches de modules et les diagrammes de
composants C4 dans `build/modulith-docs/`.

### Chaque module déclare ce qu'il peut utiliser

Le tableau rejoint ce qu'il contraint : chaque module sauf `platform` porte
`@ApplicationModule(allowedDependencies = …)` sur son `package-info`, et la raison de chaque ligne —
celles que `MAY_USE` portait en commentaire — est écrite dans la javadoc de ce `package-info`. Trois
propriétés de la lecture de Modulith décident de la façon d'écrire les listes :

- **Une liste absente veut dire « tout »**, pas « rien » : le défaut est ouvert. `ModularityTest`
  échoue sur un module dont le `package-info` n'en déclare aucune, sauf `platform` — la coquille peut
  utiliser n'importe quel module (0029), et le dit en ne déclarant rien. Rien ne peut utiliser
  `platform`, ce qui ne demande aucune règle : toutes les autres listes sont fermées, et aucune ne le
  nomme.
- **Une interface nommée se liste par son nom.** `"scanning"` autorise la racine du module, et elle
  seule ; `"scanning::queries"` autorise les enregistrements de requête publiés. Les listes disent donc
  quels modules lisent `issues::queries`, `scanning::queries` et `access::security`, ce que le tableau
  ne disait pas.
- **Les modules partagés sont autorisés à tous les modules sans être listés**, ceux du socle compris.
  Un domaine ne liste pas le socle. Un module du socle liste les modules du socle qu'il utilise
  (`crypto` → `outbound`, `settings` ; `outbox` → `maintenance`), et comme `verify()` laisserait
  `settings` utiliser `audit`, `ModularityTest.eachModuleDeclaresExactlyWhatItUses` tient chaque liste
  au code dans les deux sens : un usage que la liste n'a pas, et une ligne qu'aucun usage ne demande.
  La seconde moitié est aussi ce qui garde les listes « le code tel qu'il est », comme la 0026 le
  disait de son tableau : une ligne oubliée est une dépendance que la modification suivante prend sans
  qu'une revue le remarque.

**Une ligne du tableau ne pouvait pas devenir une liste.** `MAY_USE` laissait le `web` de tout module
utiliser `access` — chaque route a besoin du principal et de son marqueur, et une route qui nomme une
cible résout une `Visibility` — alors que les services de six modules ne l'utilisaient pas : `siem`,
`rules`, `inventory`, `threatintel`, `gate`, `exports`. Une liste vaut pour tout le module. Ceux dont
les routes appellent `VisibilityService` listent `access`, et `ArchitectureTest.accessForRoutesOnly`
en tient à l'écart leur racine, leur `internal` et leur `persistence`. `access::security` n'a pas
besoin d'une telle règle : la règle des couches tient déjà toute couche service à l'écart de tout
paquetage `web`.

### Ce qu'ArchUnit garde, et ce qu'il a cédé

| Règle | Désormais | Remplacée par |
|---|---|---|
| `domainsFormNoCycle`, `knownCyclesAreStillThere`, `KNOWN_CYCLES` | **retirées** | la détection de cycles de `verify()`, sur tous les modules et `config` |
| `modulesMeetAtTheirApi` | **retirée** | le contrôle des types non exposés de `verify()` : paquetage racine ou `@NamedInterface`, rien d'autre |
| `domainsDependOnlyWhereAllowed`, `MAY_USE`, `FOUNDATION`, `EVERY_ROUTE_USES` | **déplacées** dans chaque `package-info` | les dépendances autorisées de `verify()` ; `eachModuleDeclaresExactlyWhatItUses` pour les arêtes du socle et les lignes périmées ; `accessForRoutesOnly` pour la clause des routes |
| `layersOnlyReachDownwards` | gardée | Modulith lit un module d'un bloc ; les couches à l'intérieur ne sont pas son sujet |
| `everyClassHasAPlace` | gardée | les quatre places d'un module ou `config` ; Modulith accepte n'importe quel sous-paquetage |
| `controllersCallTheirModuleApi` | gardée | à l'intérieur d'un module |
| `entitiesReachNoRepository`, `persistenceHasNoWebOrService` | gardées | à l'intérieur d'un module |
| `apiNeverTouchesPersistence` | gardée | couvre la `persistence` du module lui-même et les `queries` publiées, que `verify()` autorise |
| `apiOpensNoTransaction`, `controllersWriteNoAuditEntry` | gardées | règles de couche |
| `domainIsPure`, `onlyRepositoriesReachTheDatabase` | gardées | des bibliothèques, pas des modules |
| `onlyTheOutboundDoorSpeaksHttpOutwards`, `onlySyslogSenderOpensSockets` | gardées | une seule classe autorisée à une bibliothèque |
| `everyRepositoryWriteIsTransactional`, `caseIsFoldedWithoutTheHostLocale` | gardées | conventions sur des méthodes |
| `findsSomethingToCheck`, `MODULES`, `OUTSIDE_MODULES = {config}` | gardées | les règles gardées les lisent ; `ModularityTest.detectsModules` tient la même liste face au modèle de Modulith. La racine d'un module doit contenir une classe en plus de son `package-info`, que toute racine a désormais |
| — | **nouvelle** : `accessForRoutesOnly` | la seule ligne du tableau qu'une liste de module ne sait pas dire |

Chaque règle gardée ou déplacée a été vérifiée par mutation contre une violation construite pour
elle, et la violation de chaque règle retirée — un accès à la `persistence` ou à l'`internal` d'un
autre module, un cycle, un module absent d'une liste, une interface nommée absente d'une liste,
`platform` ou `config` utilisés par un module — fait échouer `verify()`.

### Le couplage qu'aucun des deux ne voit : les chaînes de requête

Modulith et ArchUnit lisent les classes que le compilateur a produites ; une requête JPQL qui nomme
l'entité d'un autre module est une chaîne. `CrossModuleQueriesTest` lit chaque `@Query` et
`@NativeQuery` de chaque dépôt, rattache noms d'entités, noms de tables et noms de classes qualifiés au
module qui les possède, et échoue sur une référence à un autre module que sa liste `KNOWN` ne porte
pas, ainsi que sur une entrée qu'aucune requête ne fait plus. Il a trouvé exactement ce que la 0029
listait :

| Requête | Nomme | Pourquoi une seule instruction |
|---|---|---|
| `Issues.findOrphanedIds`, `Scans.findOrphanedIds` | `RepositoryEntity`, `ContainerEntity` de `targets` | le balayage des orphelins : des lignes dont la cible a disparu sont une absence dans une autre table |
| `Components.search`, `versionsOf`, `distinctRepositoriesWithComponents`, `distinctContainersWithComponents`, `distinctPurlsByTarget` | `ScanEntity` de `scanning` | un composant porte l'identifiant de son scan ; sa cible est celle du scan |
| `AiReviewResults.latestForRepository` | `ScanEntity` de `scanning` | une revue porte l'identifiant de son scan, pas celui de son dépôt |
| `Scans.findWithSbomButNoComponents` | `ComponentEntity` d'`inventory` | **à contresens** : `scanning` ne peut pas utiliser `inventory` |

Une entrée qui pointe vers un module que la liste de son origine ne nomme pas doit le dire, et la
dernière le dit : le rattrapage de l'inventaire choisit des scans par l'absence de lignes de
composants depuis `scanning`. C'est celle à déplacer — dans `inventory`, sur sa propre table, en
demandant à `ScanCatalog` les scans qui portent un SBOM.

### Dépendances

Le code de production n'utilise de Modulith que ses annotations — `@Modulithic`, `@ApplicationModule`,
`@NamedInterface` — : le classpath principal prend donc `spring-modulith-api`, et celui des tests
`spring-modulith-starter-test` (la vérification, le documenteur et ArchUnit). Le starter core, son
modèle d'exécution, ses « moments », son processeur d'annotations, jMolecules et ArchUnit quittent le
jar de production — de 122 379 585 à 117 310 636 octets — ainsi que l'`application-modules.json` que le
processeur générait pour un runtime absent ; les exclusions d'auto-configuration qui tenaient les
moments éteints partent avec eux. Rien n'est ajouté, donc aucune licence ne change
(`spring-modulith-api` est sous Apache-2.0, comme le starter qu'il remplace). L'application démarre
sur SQLite avec les mêmes 208 routes et le même journal de démarrage, horodatages et ordre des routes
mis à part. `ModulithRuntimeInertTest`
démarre toujours le contexte — sur le classpath de test, qui porte le cœur de Modulith — et lit
désormais aussi le `productionRuntimeClasspath` du fichier de verrouillage, celui dont le jar est
construit.

Toujours pas pris : le registre de publication d'événements (l'outbox est le seul, 0025), l'endpoint
actuator, `@ApplicationModuleTest`.

## Conséquences

- Un cycle ne peut plus être consigné et gardé : `verify()` n'a pas de `KNOWN_CYCLES`. La liste était
  vide depuis l'étape 1 ; un cycle trouvé en revue est rompu dans cette revue, par un port ou un
  événement.
- Un nouveau module, c'est un paquetage sous `core`, un `package-info` avec sa liste, et une ligne dans
  `ArchitectureTest.MODULES` et `ModularityTest.MODULES` (et dans `sharedModules` s'il est du socle).
- Une nouvelle dépendance entre modules est une ligne dans le `package-info` de l'origine, avec sa
  raison, dans la revue qui en a besoin — la même discipline qu'une ligne de `MAY_USE`, à côté du code
  qu'elle contraint. Elle peut toujours être ajoutée par le commit qui en a besoin ; ce qui change,
  c'est qu'il n'y a qu'un endroit à lire.
- **Plus rien ne peut nommer `config`** : le tableau l'ignorait comme cible, une liste fermée non.
  Aucun module ne le faisait.
- `ArchitectureTest` parle de l'intérieur d'un module. Une règle qui trouve son sujet par paquetage doit
  toujours lire là où son sujet vit, et se tait toujours quand ce n'est pas le cas ;
  `findsSomethingToCheck` et `ModularityTest.detectsModules` sont ce qui le remarque.
