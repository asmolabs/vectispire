# 0028 — Les domaines deviennent des modules verticaux, et le socle est partagé

**Date :** 2026-09-26 · **Statut :** acceptée · **Décideur :** Laurent Boucher

> Prolonge la [0026](0026-services-are-grouped-by-domain.md), qu'elle ne remplace pas : les domaines,
> le socle et le tableau de qui peut utiliser qui sont ceux de la 0026. Cette décision couvre les étapes
> 3 et 4 de la migration vers Spring Modulith — à quoi ressemble un domaine quand il possède ses
> paquetages, ce qui a migré, ce qui ne le pouvait pas encore, et ce que l'étape 5 doit trancher. Ce que
> Modulith voit avant et après est dans [05 — La modularité](../05-modularity.md).

## Contexte

Après la décision 0026, la couche de services était découpée par domaine, mais le code restait découpé
par couche : `core.api`, `core.services.<domaine>`, `core.repositories`, `core.persistence`. Spring
Modulith, ajouté en mode observation, prenait pour modules les paquetages situés sous la classe de
l'application et y voyait cinq couches — `api`, `services`, `repositories`, `persistence`, `config` —
et 1 304 violations d'une seule sorte, chaque contrôleur atteignant un service dans un sous-paquetage de
`services`. Rien de cela ne parlait des domaines : pour Modulith, les domaines étaient les entrailles
d'un seul module.

Pire qu'invisibles pour Modulith, les dépendances qui comptaient échappaient à `ArchitectureTest` :
`MAY_USE` contraignait les services qui appellent des services, et rien d'autre. Un service qui lisait
le repository d'un autre domaine, un contrôleur qui appelait le service d'un autre domaine,
n'appartenaient à aucun domaine et rien ne les vérifiait. Placer chaque domaine dans un paquetage à lui
rend ces arêtes visibles, et c'est ce qui, selon la 0026, rendrait Modulith utile à interroger.

## Décision

**Un domaine devient un module : `com.asmolabs.vectispire.core.<domaine>`, d'une forme fixe.**

```
core.<domaine>               son API — les services qu'appellent les autres modules et ses contrôleurs,
                             leurs vues, ses événements et les ports qu'il déclare
core.<domaine>.web           ses contrôleurs (et les records qu'eux seuls utilisent)
core.<domaine>.internal      ce dont l'API est faite : utilitaires, implémentations de ports, configuration
core.<domaine>.persistence   ses entités, ses repositories, et les projections dans lesquelles leurs requêtes sélectionnent
```

La place d'une classe dépend de qui l'appelle, pas de son nom : ce qu'appelle un autre module ou un
contrôleur du module est à la racine ; une classe publique que seuls les services du module utilisent
est dans `internal` ; une classe de paquetage reste à la racine, à côté des classes qui l'utilisent —
Java la cache déjà, et la déplacer obligerait à l'élargir. Les noms de classes ne changent pas : un
schéma OpenAPI porte le nom de son record, et le contrat (`vectispire-angular/openapi.json`) n'a pas
bougé d'un octet.

**Les couches tiennent à l'intérieur de chaque module**, et `ArchitectureTest` définit chaque couche sur
les deux découpages : `web` est la couche `api`, la racine et `internal` sont la couche `services`,
`persistence` porte les entités et les repositories — une seule couche, `entitiesReachNoRepository`
gardant l'ordre que `core.persistence` → `core.repositories` donnait gratuitement. Un contrôleur appelle
l'API de son module, jamais son `internal` (`controllersCallTheirModuleApi`) ni aucun paquetage
`persistence` (`apiNeverTouchesPersistence`, étendue au `web` de chaque module). Les emplacements sont
fermés : une classe dans `core.audit.helpers` ou dans un nouveau paquetage de premier niveau fait
échouer `everyClassHasAPlace`, pour qu'aucune classe n'échappe à la règle des couches en se plaçant là
où elle ne nomme rien.

**Un module n'en atteint un autre que par la racine de celui-ci ou par une interface nommée**
(`modulesMeetAtTheirApi`, qui lit les annotations `@NamedInterface` elles-mêmes pour ne pas pouvoir
contredire le `verify()` de l'étape 6). `MAY_USE` lit désormais un module entier — contrôleurs et
entités compris — et les tranches de la règle de cycles sont attribuées par domaine, modules et
`core.services` confondus.

### Partagé, pas ouvert

Le socle — `settings`, `outbound`, `crypto`, `audit`, `outbox`, `reporting` — est déclaré sur
`VectispireApplication` par `@Modulithic(sharedModules = …)`. Un module partagé, c'est ce que le socle
était déjà dans la 0026 : une dépendance permise pour tout module, toujours amorcée avec un module sous
test. Il reste **fermé**. Un module ouvert (`@ApplicationModule(type = OPEN)`) expose tous ses types et
sort de la vérification des cycles : déclaré ouvert, le journal d'audit aurait publié son repository à
tous les domaines, soit exactement le couplage que ce déplacement supprime — deux lecteurs de
`t_audit_log` ont dû recevoir des méthodes d'API pour cette raison.

### La seule interface nommée : la couche web de sécurité d'`access`

`core.api.security` — les marqueurs de route, le principal, la chaîne de filtres — a rejoint `access`,
et non un module à lui. Tout ce qu'il contient répond à « qui appelle, et que peut-il voir » : le
principal porte les vues d'`access` et les filtres appellent ses services. Un module de sécurité séparé
aurait dépendu d'`access` pendant que les contrôleurs d'`access` dépendaient de lui — un cycle. Il est
coupé en deux :

- `core.access.web.security`, publié comme `@NamedInterface("security")` : les marqueurs, le principal,
  `TrustedProxies`, `Visibilities`, `RequestActors` et les exceptions que le gestionnaire d'erreurs
  traduit. Les contrôleurs de tous les modules en ont besoin, et c'est du vocabulaire web — à la racine
  d'un module, sa couche de services, le principal deviendrait un paramètre qu'un service pourrait
  prendre, et l'auteur d'une entrée d'audit quelque chose qu'un service pourrait lire dans une requête.
- `core.access.web.security.chain` : les filtres, les intercepteurs, `SecurityConfiguration`,
  `OidcConfiguration`. Aucun autre module n'a de raison de nommer un filtre.

`MAY_USE` permet au `web` de tout module d'utiliser `access` : chaque route a besoin du principal et de
son marqueur, et chaque route qui nomme une cible résout une `Visibility`. Cela ne peut pas fermer de
cycle, puisqu'`access` n'utilise rien au-dessus du socle — sauf par un contrôleur d'un module du socle,
et c'est pourquoi `AuditLogController` et `CryptoController` sont retournés dans `core.api` (plus bas).

### Ce que posséder ses tables a obligé chaque module à changer

Un module prend les entités et les repositories que lui seul possède. Quand un autre module les lisait,
la lecture est devenue un appel à l'API du propriétaire — la même requête, déléguée, avec la
transaction qu'elle avait :

| Propriétaire | Lecteur | Avant | Maintenant |
|---|---|---|---|
| `settings` | `crypto` (`SigningKeyService`) | repository `Settings` | `SettingsService.internalValue`, `storeInternal` |
| `audit` | `posture` (synthèse hebdomadaire) | `AuditLog.countBy…` | `AuditLogQueryService.countSince` |
| `audit` | `compliance` (lot de preuves) | `AuditLog.findAll…` | `AuditLogQueryService.asJsonLines` (mêmes lignes, mapper de l'appelant) |
| `gate` | `exports` (attestation) | `GateVerdicts.findFirst…` ×4 | `GateRegisterService.lastForRepository`, `lastForContainer` |
| `gate` | `compliance` (section 09) | `GateVerdicts.findAll…` | `GateRegisterService.newest` |
| `gate`, `compliance` | `access` (passe de nettoyage) | `GateVerdicts`, `ComplianceSnapshots` `.deleteBefore` | port `SessionCleanupService.EvidencePurge`, implémenté par les deux |
| `inventory` | `rules`, `compliance` | `Components` | `InventoryQueryService.distinctPurls…`, `distinct…WithComponents` |
| `access` | `agents` | `ApiKeysRepository` | `AgentKeys.issue`, `revoke` |
| `access` | `notifications` | `TeamTargets`, `TeamWebhooks` | `TeamChannels` |

Six arêtes que le découpage par couche cachait sont apparues ; chacune est dans `MAY_USE` avec sa
raison : `crypto` → `settings` (la clé de signature stockée), `rules` → `inventory` (la couverture
mesurée contre l'inventaire des composants), `agents` → `rules` (l'agent récupère un jeu de règles par
son empreinte, via son contrôleur), `exports` → `scanning` (une route de document refuse d'abord un scan
invisible), `gate` → `access` (le port de purge des preuves), `notifications` → `access` (le routage par
équipe). Aucune ne ferme de cycle.

### Ce qui a migré

Étape 3, le socle : `settings`, `outbound`, `crypto`, `audit`, `outbox`, `reporting` (`shared` n'a pas
pu se dissoudre — plus bas). Étape 4, dans un ordre où aucun module n'atteignait un module encore à venir
autrement que par les paquetages par couche : `siem`, `rules`, `ai`, `threatintel`, `tickets`, `agents`,
`notifications`, `exports`, `gate`, `inventory`, `posture`, `compliance`, `access` — `gate` et
`inventory` avant `posture` et `compliance`, qui les utilisent. 262 classes, dont quatre nouvelles
(`AgentKeys` et `TeamChannels` pour les méthodes d'API, `VerdictRetention` et `SnapshotRetention` pour
le port) : 108 aux racines des modules, 73 dans `web`, 26 dans `internal`, 55 dans `persistence`.

## L'état intermédiaire

`issues`, `scanning`, `targets`, `platform` et `shared` restent découpés par couche, et ce qu'ils
possèdent aussi. C'est attendu, et cela a un prix que le rapport de Modulith montre : pour Modulith, ce
sont les entrailles d'un seul module, `services`, si bien que chaque module qui appelle l'un d'eux
« dépend de types non exposés de services », et que chaque module qu'ils appellent ferme un cycle par
`services`. Un module peut dépendre des paquetages par couche ; chacune de ces dépendances est à
résoudre à l'étape 5.

Certaines choses sont restées par couche pour une raison qui leur est propre, et sont aussi des
constats :

- **La ligne d'agent** (`AgentEntity`, `Agents`) : `access` la lit pour authentifier une clé d'agent et
  porte `AgentView` pour le principal, pendant qu'`agents` l'administre. Possédée par `agents`, elle
  obligerait `access` à fouiller chez lui ; un port dans `access`, implémenté par `agents`, lui
  permettrait de migrer.
- **Les politiques de barrière enregistrées** (`GatePolicyEntity`, `GatePolicies`) : lues en dessous de
  `gate` — par `issues` (`IssueViews.storedPolicy`) et `tickets` (le balayage). Reste à décider si le
  magasin de politiques appartient à `issues` ou si `gate` publie un port plus bas.
- **Les routes du socle** — `AuditLogController`, `CryptoController` : elles ont besoin des marqueurs
  d'`access`, et `access` utilise `audit` et `crypto` ; dans ces modules, elles ferment un cycle. Elles
  attendent dans `core.api` qu'un module situé au-dessus d'`access` les prenne.
- **`SbomDiffController`** : il vérifie la visibilité des scans par `scanning`, qui utilise `inventory` ;
  dans `inventory`, il fermerait un cycle. Comparer deux scans est une route de `scanning`.
- **`TargetNaming`** (`shared`) : `access` et `scanning` lisent les noms par lui, et `targets` utilise
  les deux.

## Ce que l'étape 5 doit résoudre

- **Déplacer `issues`, `scanning` et `targets`** avec leurs contrôleurs, entités et repositories, et
  dissoudre `platform` (le tick de maintenance, la rétention et l'écran des paramètres deviennent la
  contribution de chaque module) et `shared` (`TargetNaming` dans `targets` dès que `targets` n'appelle
  plus directement `access` et `scanning`). Chaque module de l'étape 4 sauf `siem` dépend de l'un des
  types de persistance par couche : `IssueEntity`/`Issues`, `ScanEntity`/`Scans`,
  `RepositoryEntity`/`GitRepositories`, `ContainerEntity`/`Containers`, `FindingEntity`/`Findings`, et
  les projections de requête `IssueFilters`, `IssueRows`, `IssueAggregates`, `LatestScanRow` — un module
  aura besoin, à leur place, de l'API d'`issues` et de `scanning`, ou d'une interface de requête nommée.
- **Le code par couche qui atteint les internes d'un module** : l'écran des paramètres de `platform` lit
  `Users` d'`access` ; l'administration des solutions de `targets` écrit `TeamTargets` et `UserTargets`
  d'`access` ; les métriques de la plateforme de scan comptent par le repository d'`outbox` ; le
  répartiteur de scans et `ScanningConfiguration` prennent `SemgrepRuleSetEntity` de `rules` (que
  `RuleSetService` renvoie) ; `ApiExceptionHandler` traduit la `RequestBodyTooLargeException` de la
  chaîne.
- **Des types qui franchissent une frontière sans qu'une règle les voie** : `OutboxService.enqueue`
  renvoie l'entité du message (seuls les tests de l'outbox la lisent, mais `siem` et `notifications`
  dépendent du type par le descripteur de la méthode, que ni ArchUnit ni Modulith ne comptent), et
  `RuleSetSummary`, une projection de repository, passe sur le fil dans `RuleSetListing` — comme elle le
  faisait depuis `core.repositories`.
- **Où appartient le nettoyage des preuves** : la passe des tables d'authentification purge le registre
  de la barrière et les instantanés de conformité par un port ; une fois `platform` dissous, la
  rétention propre à chaque module en est la place naturelle.

## Conséquences

- Spring Modulith détecte 24 modules — les dix-neuf domaines et les cinq paquetages par couche — et
  `verify()` signalerait 554 messages au lieu de 1 304 : 278 de `core.api` vers `core.services` (les
  contrôleurs de l'étape 5), 201 des modules vers `core.services`, 18 des paquetages par couche vers les
  internes d'un module, et 57 cycles, tous par `core.services`. **Aucun module n'atteint les internes
  d'un autre.** `ModularityObservationTest` n'échoue toujours sur rien ; l'étape 6 le transforme en
  `verify()`.
- Chaque règle qui trouvait son sujet par paquetage lit les deux découpages, et chacune a été vérifiée
  par mutation contre une classe déplacée : `RouteAuthorizationTest` ne retenait que les handlers de
  `core.api`, `SchemaNameCollisionTest` cherchait les contrôleurs dans `core.api` et les entités dans
  `core.persistence`, `AuthorizationCoverageTest` et `RouteScopingTest` parcouraient `core/api` — chacune
  se serait tue au premier contrôleur déplacé. Le seuil de couverture listait les quatre paquetages par
  couche ; il exclut désormais au lieu d'inclure. Le job `engines` de la CI reconnaissait
  `/core/persistence/` ; il reconnaît aussi le `persistence` d'un module.
- Le nouveau code va dans le module de son domaine, à la place que ses appelants décident ; une nouvelle
  arête entre modules est une ligne de `MAY_USE`, dans la revue qui en a besoin, avec sa raison.
- « De paquetage » veut désormais dire « de la racine de ce module ». Deux classes ont été élargies par
  le déplacement — `Visibilities` (appelée par les contrôleurs de tous les modules) et `ViolationView`
  (partagée par les routes de la barrière et celles du tableau de bord, désormais à la racine de
  `gate`) — chacune dit pourquoi. Là où élargir aurait publié un membre, la classe est restée à la
  racine : `SiemDelivery` lit deux membres de paquetage des classes d'API de `siem`.
