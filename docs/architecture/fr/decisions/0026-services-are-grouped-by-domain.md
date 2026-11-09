# 0026 — Les services sont regroupés par domaine, et les domaines dépendent dans un seul sens

**Date :** 2026-09-26 · **Statut :** **remplacé** par [0030](0030-modulith-verifies-the-module-boundaries.md) le 2026-09-26 · **Décideur :** Laurent Boucher

> **Remplacée le 2026-09-26 par la [0030](0030-modulith-verifies-the-module-boundaries.md).** Ce qui
> l'a démentie, c'est sa propre condition : elle écartait Spring Modulith *pour l'instant* parce que le
> code était rangé par couche, et nommait le rangement par fonctionnalité comme raison de reconsidérer.
> Les étapes 3 à 5 ont fait exactement cela, et deux autorités vérifiaient alors une même frontière.
> Les domaines et le sens de leurs dépendances tiennent, dans la [0028](0028-vertical-modules.md) et la
> [0029](0029-core-domains-become-modules.md) ; le tableau ci-dessous est devenu le `package-info` de
> chaque module, vérifié par Modulith, et `KNOWN_CYCLES` est parti avec les règles ArchUnit — un cycle
> se rompt dans la revue qui le trouve, il ne se consigne plus. Le reste de cette décision est le
> raisonnement tel qu'il était.

> **Voir aussi** [05 — La modularité vue par Spring Modulith](../05-modularity.md). Plus tard le
> même jour, l'étape 1 de la migration vers Spring Modulith a rompu les deux cycles consignés
> (`KNOWN_CYCLES` est vide), déplacé `ReportCursor` dans un domaine de fondation `reporting` et fait
> de la suppression d'une cible un événement que chaque domaine propriétaire purge ; l'étape 2 a
> ajouté Modulith en mode observation. Le tableau ci-dessous est la référence telle
> qu'`ArchitectureTest` l'impose désormais, avec `reporting` dans la fondation. Les étapes 3 et 4 ont
> fait de dix-neuf domaines des modules verticaux et ajouté six arêtes que le découpage par couche
> cachait — voir la [0028](0028-vertical-modules.md), qui prolonge cette décision sans la remplacer.

## Contexte

`core/services` contenait environ 155 classes dans un seul paquetage plat. Tout pouvait appeler
tout, et « visibilité paquetage » voulait dire « n'importe qui dans la couche service ». La règle
des couches (`ArchitectureTest`) tenait les contrôleurs à l'écart des dépôts et le SQL à l'écart des
services, mais ne disait rien de la forme de la couche service elle-même — et les revues
continuaient de trouver des défauts qu'une forme aurait rendus visibles : un appel HTTP fait dans
une transaction par un service situé à trois appels de celui qui l'avait ouverte, une tâche de
maintenance que personne n'appelait, une méthode `@Async` qui s'exécutait de façon synchrone dans la
transaction de son appelant. Aucun n'était une ligne manquante ; chacun était une dépendance que
personne ne voyait.

Deux manières de donner une forme à la couche ont été examinées.

**Spring Modulith.** Il vérifie les frontières de modules, les documente, et apporte un registre de
publication d'événements. Il a été écarté *pour l'instant*, pour trois raisons :

- **Ce code est rangé par couche, et Modulith lit comme modules les paquetages placés directement
  sous la classe de l'application.** Il verrait `api`, `services`, `repositories` et `persistence`
  comme quatre modules — ce qu'`ArchitectureTest` vérifie déjà — et non les domaines. Lui faire voir
  les domaines suppose un rangement par fonctionnalité (`issues/api`, `issues/services`,
  `issues/persistence`…), soit le déplacement de toutes les classes du plan de contrôle et de toutes
  les règles de couches écrites contre elles.
- **Son registre d'événements double l'outbox.** Les effets qui doivent survivre à une validation
  partent déjà par `t_outbox_message`, avec la réservation, le délai croissant et l'abandon que le
  relais applique à tous les types de message ([0025](0025-siem-events-leave-through-the-outbox.md)).
  Un second mécanisme, générique, serait une seconde réponse à « cet effet est-il parti », et les deux
  divergeraient.
- **La vérification et la documentation sont déjà couvertes.** ArchUnit vérifie les règles dans le
  build ; le modèle C4 et son contrôle de dérive (`c4-drift`) portent la documentation.

À reconsidérer si le code est un jour rangé par fonctionnalité, si l'outbox ne suffit plus (rejeu
d'événements, événements externalisés vers un broker), ou si un domaine doit être extrait en service
à part entière — les trois situations où ce qu'apporte Modulith cesse d'être un doublon.

## Décision

**`core/services` est divisé en sous-paquetages, un par domaine, et les domaines forment un graphe
orienté sans autre cycle que les deux consignés plus bas.** `ArchitectureTest` vérifie quatre
choses : que chaque classe de service vit dans un domaine connu, que
`slices().matching("..core.services.(*)..")` est sans cycle une fois les cycles consignés mis à
part, que chaque cycle consigné existe encore (la liste ne peut donc que raccourcir), et que chaque
domaine ne dépend que des domaines que le tableau ci-dessous lui permet.

**Un domaine est dessiné comme un futur module, pas comme un regroupement technique.** Une étude à
venir planifiera le passage à des modules *par domaine* — chacun possédant ses contrôleurs, ses
services, ses dépôts et ses entités. Les paquetages sont choisis pour qu'un domaine ici puisse aussi
posséder ceux-là : `issues` emporterait `IssuesController`, `Issues` et `IssueEntity`. Là où le code
a placé une classe du mauvais côté d'une frontière, elle reste là où son module la posséderait et le
cycle qu'elle ferme est consigné, plutôt que d'être déplacée au mauvais endroit pour faire
disparaître le cycle.

### Les domaines

| Domaine | Ce qu'il contient |
|---|---|
| `settings` | la configuration du déploiement : `SettingsService`, les réglages de première installation, et ce que Vectispire dit de lui-même (`ProductVersion`, `ExportProperties`, `BrandingProperties`) |
| `outbound` | l'unique porte de sortie : `PinnedHttpSender`, `OutboundJson`, `OutboundPost`, la configuration de la garde |
| `crypto` | le chiffrement au repos, les sources de la clé, Vault, la clé de signature |
| `audit` | le journal d'audit — son écriture, son miroir, sa relecture et le jugement de sa chaîne — et `RequestActor` |
| `outbox` | le relais : `OutboxService`, et les deux contrats vers lesquels il distribue, `OutboxHandler` et `NotificationChannel`, avec `GoneDestinationException` |
| `shared` | deux utilitaires encore sans domaine : `TargetNaming`, `ReportCursor` |
| `access` | comptes, équipes, visibilité et garde des lignes, sessions, parcours de connexion, seconds facteurs, OIDC, SCIM, clés API, amorçage |
| `siem` | le flux d'événements de sécurité et sa livraison |
| `rules` | jeux de règles, catalogue amont, couverture des règles |
| `inventory` | ce dont les cibles sont faites : composants, diff de SBOM, rayon d'impact, licences, contrats d'API |
| `ai` | la revue par modèle et le conseiller |
| `issues` | synchronisation, triage, décisions, SLA, historique, registre des exceptions, import VEX |
| `tickets` | le client du gestionnaire de tickets, les liens de tickets, le webhook du gestionnaire et le balayage des tickets |
| `scanning` | la file, la répartition, l'ingestion, le worker intégré, la planification, les lectures d'analyses |
| `agents` | l'administration des agents et le protocole agent |
| `targets` | dépôts, conteneurs, solutions et projets, identifiants de clonage, suppression |
| `threatintel` | flux KEV/EPSS, enrichissement, fin de vie |
| `gate` | la barrière, son registre et ses politiques |
| `notifications` | ce que dit le delta d'une analyse, et les canaux qui le disent |
| `exports` | VEX, CSAF, CycloneDX, attestation, les documents d'export |
| `posture` | les chiffres du risque : tableau de bord, scorecards, dette, qualité, remédiation, chemins d'attaque, le rapport hebdomadaire |
| `compliance` | référentiels, déclaration d'applicabilité, preuves, OWASP |
| `platform` | les racines de composition : la tâche de maintenance, la rétention, l'écran des réglages |

**`shared` contient deux classes et doit se vider.** `TargetNaming` appartient à `targets`, qui
possède les lignes qu'elle nomme ; elle ne peut pas y aller tant que `targets` appelle `scanning`
pour mettre une analyse en file et `access` pour filtrer par visibilité, car ces deux-là lisent aussi
des noms — neuf domaines le font. `ReportCursor`, la pagination PDF que partagent les rapports de
quatre domaines, n'a pas de domaine propre ; un module de rendu, ou une copie par module, est à
trancher par l'étude.

**`platform` n'est pas un futur module.** Ses trois classes atteignent de nombreux domaines par
nature : la tâche de maintenance appelle la tâche périodique de chaque domaine, la rétention purge
les tables de chaque domaine, et l'écran des réglages écrit les secrets de chaque domaine. Dans un
découpage en modules, elles se dissolvent dans les domaines qu'elles appellent — une tâche par
module, une règle de rétention par module, une contribution aux réglages par module.

### Qui peut dépendre de qui

Le **socle** — `settings`, `outbound`, `crypto`, `audit`, `outbox`, `shared` — peut être utilisé par
tous les domaines. À l'intérieur, `crypto` utilise `outbound` (Vault est atteint à travers la garde)
et rien d'autre ne dépend de rien, hormis l'arête consignée `audit` → `siem`.

Au-dessus du socle, chaque domaine ne peut utiliser que les domaines indiqués :

| Domaine | Peut aussi utiliser |
|---|---|
| `access`, `siem`, `rules`, `inventory` | — |
| `ai`, `issues` | `access` |
| `tickets` | `access`, `issues` |
| `scanning` | `access`, `inventory`, `issues`, `rules` |
| `agents` | `access`, `scanning` |
| `targets` | `access`, `scanning` |
| `threatintel` | `scanning`, `siem` |
| `gate` | `issues`, `rules`, `siem` |
| `notifications` | `issues`, `scanning` |
| `exports` | `gate`, `issues` |
| `posture` | `access`, `gate`, `inventory`, `issues`, `notifications` |
| `compliance` | `access`, `ai`, `exports`, `gate`, `inventory`, `issues`, `posture`, `rules` |
| `platform` | n'importe quel domaine ; rien ne dépend de lui |

Le tableau décrit le code tel qu'il est, et y ajouter une ligne est une décision : elle appartient à
la même revue que la dépendance qui la requiert, avec sa raison.

### Comment les domaines se parlent

- **Vers le bas, un appel.** Un domaine appelle un service d'un domaine qu'il peut utiliser, comme
  n'importe quel bean Spring.
- **Vers le haut, un port.** Quand un domaine inférieur a besoin d'un travail fait par un domaine
  supérieur, il déclare l'interface et le domaine supérieur l'implémente : `ScanIngestor.Enricher`,
  `LicenseSource`, `EndOfLifeSource` et `NotificationSink` (implémentées dans `threatintel`,
  `scanning` et `notifications`), `AuditLogService.Listener` (implémentée par `siem`),
  `OutboxHandler` (implémentée par `siem`).
- **Les effets qui doivent survivre à la validation passent par l'outbox.** Un message, un événement
  SIEM, tout ce qui quitte le processus après une écriture est une ligne écrite dans la transaction
  qui l'a causé et envoyée ensuite par le relais — jamais un appel direct depuis l'intérieur de la
  transaction, et jamais `@Async`, inerte ici.

### Trois cycles : un cassé, deux consignés

Le paquetage plat cachait trois cycles entre ce qui est devenu des domaines.

- **Cassé : `outbox` ↔ `notifications`.** Le relais interceptait
  `NotificationService.GoneDestinationException`, et les notifications écrivent dans le relais.
  L'exception est le contrat du relais, pas celui des notifications ; elle est devenue
  `outbox.GoneDestinationException`, de premier niveau, et `NotificationChannel`, l'interface vers
  laquelle le relais distribue les lignes de notification, l'a suivie.
- **Consigné : `audit` → `siem`**, par `AuditLogQueryService` → `SiemEvents`. Vérifier la chaîne
  publie `AUDIT_CHAIN_BROKEN`, tandis que le SIEM écoute le journal qu'elle vérifie. L'issue est un
  événement applicatif auquel le SIEM s'abonne — ce que ferait un module, et plus qu'un déplacement
  de paquetage.
- **Consigné : `issues` → `tickets`**, par `IssueDecisionService` → `TicketService`. Attacher un
  ticket valide la référence contre le gestionnaire configuré, tandis que le webhook du gestionnaire
  et le balayage des tickets font transiter des problèmes. La validation appartient à `tickets` ; la
  déplacer est un changement de méthode, pas de paquetage.

Les deux arêtes consignées figurent dans `ArchitectureTest.KNOWN_CYCLES` avec ces raisons,
exemptées de la règle des cycles et du tableau par classe — pas par paquetage — et un test échoue le
jour où l'une disparaît : la liste raccourcit avec le code.

## Conséquences

- Un nouveau service va dans le domaine dont la ligne du tableau correspond à ce dont il a besoin ;
  si aucune ne correspond, le tableau change d'abord, à découvert.
- « Visibilité paquetage » veut maintenant dire « ce domaine ». Le déplacement a élargi une seule
  classe — `ReportCursor`, et les membres qu'appellent les rapports PDF — parce que ses appelants
  vivent dans quatre domaines ; tout le reste de ce qui était de visibilité paquetage est resté privé
  à son domaine.
- La règle des couches ne change pas : `..services..` couvre les sous-paquetages. Décidé le même
  jour et vérifié à côté : aucune classe d'`api` ne dépend de `persistence`. Les services répondent
  par des records `…View`, le principal porte `UserView`, `SessionView` et `AgentView` — d'où
  l'usage d'`access` par `agents` — et une route qui ne tenait une ligne que pour la rendre passe
  un identifiant.
- Une règle ArchUnit peut être supprimée par le commit qui la viole, comme `vectispire-java/README.md`
  le dit déjà des couches. Le tableau de cet enregistrement est la référence contre laquelle la règle
  est relue.
