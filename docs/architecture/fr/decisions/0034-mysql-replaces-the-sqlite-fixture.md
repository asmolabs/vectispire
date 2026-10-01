# 0034 — MySQL remplace SQLite comme fixture des suites unitaires et HTTP

**Date :** 2026-10-01 · **Statut :** acceptée · **Amende :** [0014](0014-two-engines-and-a-test-fixture.md), [0027](0027-common-migrations-with-type-placeholders.md) · **Décideur :** Laurent Boucher

## Contexte

[0014](0014-two-engines-and-a-test-fixture.md) a gardé SQLite comme fixture de la suite de tests
ordinaire — pas comme déploiement — pour une seule raison, que `ApiTestBase` énonce toujours : *il ne
demande aucun démon*, donc la suite HTTP tourne à chaque `./gradlew build` au lieu d'une campagne
qu'il faut penser à lancer. Le même enregistrement a refusé H2, parce qu'une base de test que personne
ne déploie répète l'erreur de SQLite avec un troisième dialecte, et que ses modes de compatibilité
cachent les divergences que la campagne doit trouver. Il ajoutait : « si le but était des tests plus
rapides, un conteneur MySQL démarre en six secondes environ. »

Ce que la fixture a coûté depuis, mesuré le 2026-10-01 :

- **Un troisième jeu de migrations.** 41 fichiers sous `db/migration/sqlite/` ; depuis V40, chaque
  migration dont la structure diverge est écrite trois fois
  ([0027](0027-common-migrations-with-type-placeholders.md)), et `MigrationDialect` épelle chaque
  placeholder de type une troisième fois.
- **Du code de production qui existe pour un moteur de test.** `SqliteForeignKeys` et
  `SqliteWriteAheadLog` dans `core/config/`, et la gestion ou le raisonnement autour de `SQLITE_BUSY`
  dans `ScanQueue`, `AuditLogService`, `AgentRepository` et `ScimProvisioningService` — un verrou à
  écrivain unique qu'aucun moteur déployé n'a. Cinquante-sept sources de production mentionnent SQLite.
- **La suite HTTP ne valide pas le schéma.** `application-apitest.yaml` règle `ddl-auto: none` parce
  que SQLite renvoie chaque horodatage comme FLOAT ; les 120 classes `ApiTestBase` tournent sur un
  schéma qu'Hibernate n'a jamais vérifié. Seule la campagne le fait, et elle ne tourne pas à chaque push.
- **Une classe de défauts que la suite ne peut pas voir.** Un comportement qui diffère entre SQLite et
  les moteurs — une requête que SQLite accepte et que PostgreSQL refuse
  (`HistoryQueriesIntegrationTest`), la limite de paramètres, le verrouillage — est invisible aux 278
  classes de la suite ordinaire, quoi qu'elles affirment.
- **Elle bloque l'infrastructure écrite pour les moteurs déployés.** Le registre d'événements JDBC de
  Spring Modulith ne démarre pas sur SQLite ([0033](0033-internal-reactions-leave-through-the-outbox.md)).

## Décision

**La suite de tests ordinaire tourne sur MySQL, le moteur déployé par défaut, dans un conteneur.**
MySQL plutôt que PostgreSQL parce que c'est le moteur que livre `docker-compose.yml`, et celui dont les
réglages par défaut ont déjà produit un défaut ici — un `DATETIME` nu tronqué à la seconde a cassé la
vérification de la chaîne d'audit (0014). PostgreSQL reste dans la campagne.

- **En local**, un conteneur par exécution de Gradle via Testcontainers avec réutilisation, une base
  neuve par JVM de test comme `ApiTestBase` le fait aujourd'hui avec un fichier SQLite temporaire.
- **En CI**, le job `jvm` tourne dans `eclipse-temurin:25-jdk` ; un `services: mysql` à côté partage
  son réseau, donc la suite atteint `mysql:3306` sans Testcontainers ni socket Docker.
- **`ddl-auto: validate` dans la suite HTTP**, comme en production.
- **SQLite s'en va** : son jeu de migrations, son entrée dans `MigrationDialect`, le pilote et le
  dialecte communautaire, `SqliteForeignKeys`, `SqliteWriteAheadLog`, et les contournements
  `SQLITE_BUSY` une fois chacun montré propre à SQLite. `MigrationLayoutTest` et `check-doc-facts.py`
  comptent deux moteurs.
- **La campagne garde PostgreSQL et MySQL** sous `integrationTestAll` ; sa jambe SQLite est retirée.

**H2 reste refusé**, pour les raisons de 0014 : remplacer un moteur que personne ne déploie par un
autre garderait tous les coûts ci-dessus et ajouterait un mode de compatibilité qui cache ce que la
campagne cherche.

## Ce que cela coûte

- **Docker devient un prérequis de `./gradlew build`**, c'est-à-dire exactement la propriété pour
  laquelle 0014 avait gardé SQLite. Une machine sans démon peut encore compiler et lancer les tests
  d'architecture ; les suites de contexte et HTTP refusent de démarrer, et disent pourquoi — jamais
  d'omission silencieuse (AGENTS.md).
- **Du temps.** Environ six secondes de démarrage de conteneur par exécution de Gradle, et un nettoyage
  entre tests plus lent sur MySQL que la suppression d'un fichier ; à mesurer dans le premier lot face
  à la durée actuelle de la suite, et le passage s'arrête si la suite fait plus que doubler.
- **Un lot de migration, de taille L** : le changement de fixture, la configuration, le service de CI,
  le retrait du jeu et du code SQLite, et la documentation dans les deux langues — puis une nightly
  verte sur le résultat avant la release suivante.

## Ce que cela apporte

- Deux jeux de migrations au lieu de trois pour chaque changement de structure, et un dialecte de
  moins dans `MigrationDialect`.
- La suite HTTP valide le schéma et exerce le verrouillage et les limites du moteur déployé à chaque
  push, pas seulement dans la campagne.
- Le code de production ne porte plus de contournements de verrouillage pour un moteur sur lequel il
  n'est jamais déployé.
- L'obstacle au registre de Modulith qu'était SQLite disparaît. Les autres restent, et
  [0033](0033-internal-reactions-leave-through-the-outbox.md) ne dépend pas de cet enregistrement.

## Alternatives envisagées

- **Garder SQLite** — le statu quo ; chaque coût du contexte continue.
- **H2** — refusé, voir ci-dessus et 0014.
- **PostgreSQL comme fixture** — tout aussi réel, mais pas le moteur livré par défaut.
- **Testcontainers en CI aussi** — demande le socket Docker dans le conteneur du job `jvm` ; un
  service de job est le mécanisme que GitHub fournit exactement pour cela.

## Amende

- [0014](0014-two-engines-and-a-test-fixture.md) : « SQLite reste … comme fixture sur laquelle tourne
  la suite HTTP » ne tient plus ; les moteurs pris en charge ne changent pas.
- [0027](0027-common-migrations-with-type-placeholders.md) : une migration qui diverge est écrite deux
  fois, sous `db/migration/{postgresql,mysql}/`.
