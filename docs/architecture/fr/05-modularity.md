# 05 — La modularité vue par Spring Modulith

> **Observé le 2026-09-26, après les étapes 3 et 4 de la migration vers Spring Modulith**, avec
> l'observation de l'étape 2 gardée comme référence. Modulith est dans le build pour qu'on l'interroge,
> pas pour imposer ses réponses : `ModularityObservationTest` construit son modèle du plan de contrôle,
> écrit le rapport et les diagrammes générés dans `vectispire-java/vectispire-core/build/modulith-docs/`,
> et n'échoue sur rien de ce qu'il trouve. À l'exécution, il ne fait rien — `ModulithRuntimeInertTest`
> échoue si l'un de ses beans devient actif. Les règles qui *sont* imposées restent celles
> d'[`ArchitectureTest`](../../../vectispire-java/vectispire-core/src/test/java/com/asmolabs/vectispire/core/ArchitectureTest.java),
> telles que les décisions [0026](decisions/0026-services-are-grouped-by-domain.md) et
> [0028](decisions/0028-vertical-modules.md) les décrivent.

## Ce que Modulith détecte : dix-neuf domaines, et cinq couches restantes

Modulith prend pour modules les paquetages situés directement sous la classe de l'application,
`com.asmolabs.vectispire.core`. L'étape 2 en trouvait cinq, les couches d'un code découpé par couche —
`api`, `services`, `repositories`, `persistence`, `config` — et rien des domaines, qui étaient les
entrailles d'un seul module.

Les étapes 3 et 4 ont déplacé dix-neuf domaines dans des paquetages à eux
([0028](decisions/0028-vertical-modules.md)) : `core.<domaine>` pour l'API, `.web` pour les
contrôleurs, `.internal` pour l'implémentation, `.persistence` pour les entités et les repositories.
Modulith trouve maintenant **24 modules** :

| Module | Nature | Autres domaines dont il dépend | Paquetages par couche qu'il utilise |
|---|---|---|---|
| `settings`, `outbound`, `crypto`, `audit`, `outbox`, `reporting` | socle, **partagé** | — (`crypto` utilise `outbound` et `settings`) | — |
| `siem` | domaine | `access` | — |
| `rules` | domaine | `access`, `inventory` | `repositories` |
| `ai` | domaine | `access` | `persistence`, `repositories` |
| `threatintel` | domaine | `access`, `siem` | les trois |
| `tickets` | domaine | `access` | les trois |
| `agents` | domaine | `access`, `rules` | les trois |
| `notifications` | domaine | `access` | les trois |
| `exports` | domaine | `access`, `gate` | les trois |
| `gate` | domaine | `access`, `rules`, `siem` | les trois |
| `inventory` | domaine | `access` | les trois |
| `posture` | domaine | `access`, `gate`, `inventory`, `notifications` | les trois |
| `compliance` | domaine | `access`, `ai`, `exports`, `gate`, `inventory`, `posture`, `rules` | les trois |
| `access` | domaine | — | les trois |
| `api`, `services`, `repositories`, `persistence`, `config` | découpage par couche | — | l'étape 5 les vide |

« Les trois », ce sont `services`, `repositories` et `persistence` : les paquetages par couche où
vivent encore `issues`, `scanning`, `targets`, `platform` et `shared`. Le socle est déclaré partagé
(`@Modulithic(sharedModules = …)` sur `VectispireApplication`) et reste fermé : ses paquetages
`internal` et `persistence` sont cachés comme ceux de n'importe quel module. `access` publie une seule
interface nommée, `security` — les marqueurs de route, le principal et les utilitaires dont se servent
les contrôleurs de tous les modules.

`vectispire-common` est hors du paquetage de l'application et se lit comme une bibliothèque : une
dépendance vers `common.domain` est invisible pour Modulith, ce qu'il faut garder en tête pour les
types partagés qui y vivent — `ScanTarget` et, depuis l'étape 1, l'événement `TargetDeleted`.

## Ce que `verify()` rejetterait

| | Avant l'étape 3 (étape 2) | Après l'étape 4 |
|---|---|---|
| Modules | 5, tous des couches | 24 : 19 domaines (6 partagés), 5 couches |
| Messages | **1 304** | **554** |
| `api` → types non exposés de `services` (couche → couche) | 1 304 (208 types) | 278 (50 types) |
| un module → types non exposés de `services` (module → couche) | — | 201 |
| un paquetage par couche → types non exposés d'un module | — | 18 |
| un module → types non exposés d'un autre module | — | **0** |
| cycles | 0 | 57, **tous par `services`** |

Comme avant, un message est compté par dépendance fautive — paramètre de constructeur, champ, chaque
appel — si bien que les nombres mesurent des lignes de code plus que des problèmes. Ce que veut dire
chaque sorte restante :

- **`api` → `services`, 278.** Les contrôleurs d'`issues`, `targets`, `scanning` et `platform` encore
  dans `core.api`, qui appellent des services situés dans des sous-paquetages de `core.services`. Ils
  partent avec leurs domaines à l'étape 5.
- **Module → `services`, 201.** Un module qui appelle des services d'`issues`, de `scanning` ou de
  `targets`, ou `shared.TargetNaming` : `posture` et `compliance` lisent `SlaService`, `exports` importe
  le VEX par `issues`, `notifications` et `threatintel` implémentent les ports de `scanning`. Chacun est
  consigné comme constat pour l'étape 5 dans la 0028.
- **Couche → module, 18.** `core.services` qui atteint les internes d'un module — l'écran des
  paramètres lit `Users` d'`access`, l'administration des solutions écrit les attributions d'`access`,
  les métriques de la plateforme de scan comptent par le repository d'`outbox`, le répartiteur prend
  l'entité de `rules` — et `ApiExceptionHandler`, qui traduit une exception imbriquée dans la chaîne de
  filtres d'`access`.
- **Cycles, 57.** `services` est un seul module pour Modulith : un module qui utilise `issues` et qu'utilise
  `platform` — `posture`, `compliance`, `access`… — ferme un cycle en passant par lui. Aucun ne relie deux
  domaines sans passer par `services`, ce que confirme la règle de cycles d'`ArchitectureTest` —
  découpée par domaine, `core.services.issues` comme `core.access` : elle n'a aucun cycle à signaler.

**Le chiffre qui compte est le zéro.** Aucun module n'atteint le paquetage `internal`, `persistence`
ou `web` d'un autre : là où c'était le cas — neuf lecteurs du repository d'un autre domaine — la lecture
est devenue un appel à l'API du propriétaire ou un port, et `ArchitectureTest.modulesMeetAtTheirApi`
l'y maintient. Ce qui reste appartient au découpage par couche, et c'est à l'étape 5 de le supprimer.

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
  `ReachabilityAnalyzer`, un service que rien n'appelait, a été supprimé. `TargetNaming` reste dans
  `shared` : neuf autres domaines lisent les noms par lui, dont `access` et `scanning`, que `targets` utilise
  lui-même ; le déplacer dans `targets` fermerait deux cycles.

## Ce qu'ont changé les étapes 3 et 4

- **Dix-neuf domaines sont des modules**, le socle d'abord ; 262 classes, dont quatre nouvelles, avec
  leurs contrôleurs, entités, repositories et tests. Le contrat HTTP n'a pas changé (`openapi.json` se
  régénère à l'identique), et l'application démarre avec les mêmes 206 méthodes de routage.
- **`core.api.security` fait désormais partie d'`access`** : `core.access.web.security`, l'interface
  nommée, et `.chain` en dessous pour les filtres.
- **Neuf lectures des tables d'un autre module sont devenues des appels d'API ou des ports** — le
  tableau est dans la 0028 — et six dépendances que le découpage par couche cachait sont maintenant des
  lignes de `MAY_USE`, chacune avec sa raison.
- **Chaque règle qui trouvait son sujet par paquetage lit les deux découpages** : la règle des couches,
  les règles de domaine, les lints de route, le parcours des schémas, le seuil de couverture et le
  filtre de chemins du job `engines` de la CI.

## Ce que change l'étape 5

`issues`, `scanning` et `targets` deviennent des modules ; `platform` se dissout dans les modules qu'il
compose (la tâche périodique, la règle de rétention et la contribution aux paramètres de chaque module)
et `shared` dans `targets`. Les modules `services`, `api`, `repositories` et `persistence` de Modulith
sont alors vides, chaque cycle qu'il signale aujourd'hui disparaît avec eux, et le rapport devient la
liste des domaines qui fouillent les uns chez les autres — ce que l'étape 6 transforme en `verify()`
bloquant. La décision 0028 énumère ce qui devra être tranché en chemin : à qui appartiennent la ligne
d'agent et les politiques de barrière enregistrées, où vont les routes du socle et la comparaison de
SBOM, et les deux types qui franchissent une frontière sans qu'aucune règle les voie.
