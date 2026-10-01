# 0033 — Une réaction entre modules qui doit survivre à un commit passe par l'outbox, pas par le registre de Modulith

**Date :** 2026-10-01 · **Statut :** acceptée · **Amende :** [0030](0030-modulith-verifies-the-module-boundaries.md), [0025](0025-siem-events-leave-through-the-outbox.md) · **Décideur :** Laurent Boucher

## Contexte

L'étape 7 du passage à Spring Modulith a été planifiée le 2026-09-26 comme « registre de publication
JPA de Modulith pour les événements entre modules, outbox maison pour ce qui sort de l'application ».
Elle a été notée comme décidée avant que l'une ou l'autre moitié ait été mesurée. Cet enregistrement
est la mesure, et il renverse ce plan.

**Ce qui se perd aujourd'hui.** Un relevé de tous les effets qui suivent un scan, un import, une
entrée d'audit et un verdict de barrière (2026-10-01) en a trouvé quatre qui s'exécutent *après* le
commit du travail qui les cause, par appel direct, sans rien pour les refaire si le processus s'arrête
entre les deux :

| Effet | Où | Rattrapé par |
|---|---|---|
| Les réponses automatiques d'une checklist après un scan ou un import | `ScanDispatcher.announce` → `RepositoryScanned` ; `ReportedRepositories` → `RepositoryReported` | le scan suivant d'un dépôt du projet, ou une révision ouverte, déplacée ou rouverte — rien d'autre |
| Chaque événement SIEM signalé par une entrée d'audit | synchronisation après commit d'`AuditLogService` → `SiemEvents.recorded` (`REQUIRES_NEW`) | rien |
| `SECURITY_GATE_FAILED` | `GateService` → `SiemEvents.publish`, après l'écriture du verdict | rien |
| L'entrée d'audit `AGENT_RESULT_SUBMITTED` du chemin agent | `AgentProtocolService.submitResult`, après `record` | rien — un nouvel envoi reçoit `NoLongerYours` |

Tout le reste de ce qui suit un scan est déjà atomique avec lui : la réconciliation des issues,
l'inventaire et les constats sont des appels directs dans la transaction du scan, et les
notifications et les fuites de secrets sont des lignes d'outbox écrites dans cette transaction
([0025](0025-siem-events-leave-through-the-outbox.md)).

**Ce que l'outbox garantit déjà.** `t_outbox_message` est écrite dans la transaction de l'appelant
(`MANDATORY`), réservée par une mise à jour conditionnelle que toutes les instances peuvent tenter et
qu'une seule gagne (fenêtre de 5 minutes), relancée avec un backoff de 60 s × 2ⁿ plafonné à une heure,
abandonnée après huit tentatives en gardant sa dernière erreur, abandonnée tout de suite sur une
destination disparue, dédoublonnée par le destinataire sur `message_id`, purgée après sept jours — sur
PostgreSQL, MySQL et la fixture SQLite. Elle distribue déjà à un `OutboxHandler` dans le processus
(`SiemDelivery`), pas seulement à un canal.

**Ce qu'apporterait le registre de Spring Modulith 2.1.1**, lu dans ses sources et ses tickets 2.1.1 :

- **Il ne démarre pas sur SQLite.** Le `DatabaseType` du registre JDBC connaît H2, HSQLDB, MySQL,
  MariaDB, PostgreSQL, SQL Server et Oracle, et lève une exception pour le reste, depuis un bean qui
  n'est pas conditionnel. Le registre JPA ne livre aucun DDL et son entité a eu des écarts répétés
  avec `validate` (#1057, #1389, #1543) ; les mainteneurs recommandent le JDBC « même dans les
  applications JPA ».
- **Ni relance, ni backoff, ni plafond, ni lettre morte.** Une publication en échec reste `FAILED` ;
  l'application planifie elle-même `FailedEventPublications.resubmit(...)` et écrit son propre
  plafond. Un état `ABANDONED` arrive en 2.2.0-M2 (#1764). La relance automatique est une demande
  ouverte (#1439).
- **Au moins une fois, avec une réservation plus faible que la nôtre.** La resoumission réserve une
  ligne en la passant à `RESUBMITTED` seulement ; une liste périmée sur une seconde instance peut
  re-réserver une ligne que la première a déjà passée à `PROCESSING`. La réponse des mainteneurs aux
  resoumissions concurrentes est un verrou distribué (ShedLock, Spring Integration) (#926, #663).
- **Des identités fragiles.** L'identifiant d'un listener vaut par défaut la signature de sa méthode,
  donc la renommer rend orphelines ses lignes en attente ; la complétion retombe sur la comparaison de
  l'événement sérialisé, donc deux événements identiques se complètent l'un l'autre (#486, #1008) et
  un événement dont le JSON ne fait pas l'aller-retour n'est jamais complété (#556).
- **La 2.1.1 juge les relances périmées par rapport à la date de publication d'origine** (#1837,
  corrigé dans la 2.1.2, pas encore publiée). Ses starters remettent `spring-modulith-core` —
  ArchUnit compris — sur le classpath d'exécution que l'étape 6 avait vidé (`ModulithRuntimeInertTest`).

L'adopter voudrait dire écrire autour de lui la relance, le plafond, l'abandon, la purge et la
réservation multi-instance que l'outbox a déjà — et garder deux réponses à « cet effet a-t-il eu
lieu », la dérive pour laquelle [0026](0026-services-are-grouped-by-domain.md) et
[0030](0030-modulith-verifies-the-module-boundaries.md) l'avaient refusé. La seule condition où cette
raison tomberait — l'outbox qui ne suffit plus — ne s'est pas produite : chaque trou du tableau
ci-dessus est un appel fait *après* un commit, pas une limite de l'outbox.

## Décision

**Une réaction d'un module à un autre qui doit survivre à un commit est un message d'outbox, écrit
dans la transaction du travail qui la cause, et traité dans le processus par un `OutboxHandler` du
module qui réagit.** Elle hérite de la réservation, du backoff, du plafond, de l'abandon et de la purge
de tout message. Son traitement est idempotent, parce que la livraison est au moins une fois : une
réponse automatique de checklist ne réécrit déjà une ligne que lorsque ce qu'elle énonce change.

**Le registre de publication d'événements de Spring Modulith n'est pas adopté.** Le « toujours pas
retenu » de [0030](0030-modulith-verifies-the-module-boundaries.md) tient, désormais avec sa mesure.

**Une réaction qui doit être atomique avec sa cause reste un `@EventListener` synchrone dans la
transaction de l'émetteur**, comme les purges `TargetDeleted` : la suppression et sa purge sont
validées ou annulées ensemble, ce qu'aucune livraison après commit ne peut offrir.

**Un module qui a seulement besoin de dire quelque chose à un autre, dans la même transaction, publie
un événement de domaine au lieu de l'appeler.** `issues`, `gate` et `threatintel` listent `siem` parmi
leurs dépendances pour un seul appel chacun ; un événement synchrone que `siem` écoute, en écrivant
dans l'outbox dans la même transaction, retire ces lignes d'`allowedDependencies` sans changer ce qui
est durable.

**Ce qui sort de l'application ne change pas** ([0025](0025-siem-events-leave-through-the-outbox.md)).

## Le travail, par lots

1. **Le crochet `beforeCommit` du scan, sous test d'abord.** `IssueSyncService` intercepte l'échec du
   crochet de notification « pour que les résultats du scan soient gardés », mais ce crochet appelle
   des proxys transactionnels ; une exception qui en traverse un marque la transaction du scan
   rollback-only, et le scan serait abandonné plutôt que gardé. Un test tranche avant que quoi que ce
   soit soit construit dessus.
2. **Les événements SIEM du journal d'audit et de la barrière, dans la transaction qui les cause.**
   L'entrée d'audit et sa ligne d'outbox sont validées ensemble ; un verdict et son
   `SECURITY_GATE_FAILED` aussi.
3. **Les réponses automatiques d'une checklist comme message `checklist_answer`**, écrit dans la
   transaction du scan ou de l'import, traité par `checklists`.
4. **`AGENT_RESULT_SUBMITTED` dans la transaction du résultat.**
5. **Des événements de domaine à la place des appels vers `siem`**, et `notifications` → `issues`
   examiné de la même façon ; chaque ligne d'`allowedDependencies` retirée est une ligne de la revue.

Chaque lot porte ses tests sur les trois moteurs de la campagne, une vérification par mutation de
chaque nouveau test, et sa documentation dans les deux langues.

## Alternatives envisagées

- **Le registre de Modulith pour les événements internes** (le plan du 2026-09-26). Refusé pour les
  raisons ci-dessus ; à reconsidérer quand une version livrera la relance plafonnée, un état
  d'abandon et une réservation qui exclut les lignes en cours, *et* que la fixture de test sera un
  moteur qu'il prend en charge — voir [0034](0034-mysql-replaces-the-sqlite-fixture.md), qui lève le
  second obstacle et pas le premier.
- **Déplacer les appels d'après commit dans la transaction, en appels directs.** Cela ferme la perte,
  mais lie la cause aux échecs de la réaction : une checklist impossible à répondre annulerait le
  scan. Un message découple l'échec tout en gardant la durabilité.
- **Un balayage qui redérive ce qui a été perdu** (comme les tickets sont réconciliés chaque heure).
  Juste pour un état recalculable depuis zéro ; faux pour un événement SIEM issu de l'audit, qui est
  un fait sur un instant et ne peut pas être redérivé plus tard.

## Conséquences

- Quatre effets cessent d'être perdus sur un arrêt au mauvais moment, sans second mécanisme de
  livraison.
- Les messages internes partagent la cadence du relais (60 s par défaut) : les réponses automatiques
  d'une checklist arrivent jusqu'à une minute après le scan au lieu de tout de suite. Accepté : une
  checklist est lue par une personne, à l'échelle d'une revue, pas d'une minute.
- Le relais sert les réactions internes autant que les webhooks ; son `MAX_PER_PASS` et la santé de
  `t_outbox_message` concernent désormais les deux. Un type de message est nommé par réaction, donc
  les comptes de l'outbox par type disent toujours lequel est en retard.
- Trois lignes d'`allowedDependencies` disparaissent quand le lot 5 arrive, et leur disparition est la
  preuve exécutable que le découplage a eu lieu.
