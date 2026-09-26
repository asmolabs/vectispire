# 05 — La modularité vue par Spring Modulith

> **Observé le 2026-09-26, à l'étape 2 de la migration vers Spring Modulith.** Modulith est dans le
> build pour qu'on l'interroge, pas pour imposer ses réponses : `ModularityObservationTest` construit
> son modèle du plan de contrôle, écrit le rapport et les diagrammes générés dans
> `vectispire-java/vectispire-core/build/modulith-docs/`, et n'échoue sur rien de ce qu'il trouve. À
> l'exécution, il ne fait rien — `ModulithRuntimeInertTest` échoue si l'un de ses beans devient actif.
> Les règles qui *sont* imposées restent celles d'[`ArchitectureTest`](../../../vectispire-java/vectispire-core/src/test/java/com/asmolabs/vectispire/core/ArchitectureTest.java),
> telles que la [décision 0026](decisions/0026-services-are-grouped-by-domain.md) les décrit.

## Ce que Modulith détecte : les couches, pas les domaines

Modulith prend pour modules les paquetages situés directement sous la classe de l'application,
`com.asmolabs.vectispire.core`. Le plan de contrôle est découpé par couche ; il en trouve donc cinq :

| Module | Paquetage de base | Dépend de |
|---|---|---|
| `api` | `core.api` | `services` |
| `services` | `core.services` | `persistence`, `repositories` |
| `repositories` | `core.repositories` | `persistence` |
| `persistence` | `core.persistence` | — |
| `config` | `core.config` | — |

**C'est le constat attendu, et la raison d'être des étapes 3 à 5.** Les vingt-quatre domaines de la
décision 0026 — `issues`, `scanning`, `access`, `targets`… — sont des sous-paquetages de `services` :
pour Modulith, ce sont les entrailles d'un seul module. Le graphe ci-dessus est la règle des couches,
qu'`ArchitectureTest` vérifie déjà ; il ne dit rien des domaines.

`vectispire-common` est hors du paquetage de l'application et se lit comme une bibliothèque : une
dépendance vers `common.domain` est invisible pour Modulith, ce qu'il faut garder en tête pour les
types partagés qui y vivent — `ScanTarget` et, depuis l'étape 1, l'événement `TargetDeleted`.

## Ce que `verify()` rejetterait

**1 304 messages, d'une seule sorte : `api` dépend de types non exposés de `services`**, 208 types
distincts. Un module expose les types de son paquetage de base ; chaque service vit dans un
sous-paquetage de domaine, que Modulith traite comme interne. Chaque usage d'un service par son
contrôleur est donc une violation — paramètre de constructeur, champ et chaque appel comptés à part,
ce qui explique que le nombre mesure des lignes de code plus que des problèmes. Aucun cycle entre les
cinq modules, et rien de signalé entre `services`, `repositories` et `persistence` : ce sont des
paquetages plats, dont tous les types sont exposés.

Rien de tout cela n'est un défaut du code. C'est ce que la vérification dit d'un découpage par
couche, et c'est pourquoi le test observe au lieu de vérifier.

## Ce qui a changé avant cette observation (étape 1)

L'observation a été faite après avoir défait les nœuds que la décision 0026 avait consignés, pour que
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

## Ce que change l'étape 3

L'étape 3 commence le découpage par fonctionnalité : un domaine devient un paquetage de premier
niveau qui possède ses contrôleurs, services, dépôts et entités (`issues/api`, `issues/services`,
`issues/persistence`…), pour que les modules de Modulith soient les domaines. Le rapport devrait alors
passer de cinq modules de couche et une sorte de violation à un module par domaine et des violations
qui veulent dire quelque chose — un domaine qui fouille les entrailles d'un autre — ce que l'étape 6
transforme en `verify()` bloquant. Trois points demanderont une décision en chemin :

- **Où vivent les types transverses.** `TargetDeleted` est dans `common.domain` parce que `targets`
  dépend d'`access` et de `scanning`, qui l'écoutent. Quand `targets` cessera de les appeler (un port
  de visibilité, un événement de demande de scan), l'événement pourra rejoindre l'API du module
  `targets`.
- **`TargetNaming`**, pour la même raison : il appartient à `targets` dès que `targets` est sous les
  domaines qui lisent les noms.
- **Les racines de composition de `platform`** — le tick de maintenance, la rétention, l'écran des
  paramètres — qui se dissolvent dans les modules qu'elles appellent.

Le rapport régénéré est la mesure de chaque étape : les chiffres ci-dessus sont la référence.
