# 0014 — Deux moteurs déployables, et SQLite comme fixture de test

**Date :** 2026-08-25 · **Statut :** accepté · **Remplace :** [0009](0009-four-engines.md)

## Contexte

Le périmètre des moteurs supportés a changé trois fois en six jours —
[0004](0004-sqlite-and-postgresql-only.md) (SQLite + PostgreSQL),
[0008](0008-postgresql-and-mysql.md) (PostgreSQL + MySQL), [0009](0009-four-engines.md) (quatre
moteurs) — et aucun de ces enregistrements ne dit *pourquoi*. Celui-ci le dit, parce que la raison
est la seule partie qui survit au renversement suivant.

Deux faits ont motivé le réexamen, et les deux ont été mesurés plutôt que raisonnés :

**SQLite ne peut pas exécuter l'application packagée.** Démarrer le jar contre SQLite sous le
`ddl-auto: validate` livré échoue net :

```
Schema validation: wrong column type encountered in column [created_at] in table [t_agent];
found [numeric (Types#FLOAT)], but expecting [timestamp (Types#TIMESTAMP_UTC)]
```

SQLite a des *affinités* de type plutôt que des types : il rend une colonne `numeric` en FLOAT et
Hibernate rejette chaque horodatage. La campagne unitaire l'a toujours su — son profil pose
`ddl-auto: none` et le dit en commentaire — mais le moteur restait documenté comme l'un des quatre
déploiements supportés. Il n'est pas déployable du tout, et l'appeler supporté était une
sur-affirmation, pas une décision.

**MariaDB est un quatrième jeu de migrations natives pour une différence marginale.** Chaque
changement de schéma était écrit quatre fois, et la campagne qui le justifiait ne tourne pas en CI :
elle échouait donc depuis une durée inconnue sur un compteur d'entités périmé sans que personne ne
le voie. Le coût était continu ; la couverture, intermittente.

## Décision

**PostgreSQL et MySQL sont les moteurs supportés.** MySQL est le défaut — le moteur que livre
`docker-compose.yml` — et le moteur est choisi par la seule `VECTISPIRE_DB_URL`.

**SQLite reste, et est documenté pour ce qu'il est : la fixture sur laquelle tourne la campagne
HTTP.** Ses migrations sont conservées et la campagne continue de les appliquer, parce que la
campagne unitaire en dépend. Il n'est pas proposé comme déploiement.

**MariaDB est retiré** : pilote, module Testcontainers, jeu de migrations et tâche de campagne.

## Conséquences

**Ce que cela coûte.** Un déploiement MariaDB cesse d'être possible sans que quelqu'un remette le
jeu en place. Son dialecte est assez proche de celui de MySQL pour que l'essentiel fonctionnerait —
et c'est précisément pourquoi il ne faut pas l'affirmer : « probablement compatible » est
l'affirmation que ce projet dépense une campagne multi-moteurs à éviter.

**Ce que cela apporte.** Chaque changement de schéma s'écrit deux fois au lieu de quatre, la
campagne est divisée par deux, et le périmètre supporté est désormais celui dont on a démontré
qu'il démarre. Les deux moteurs restants ont été vérifiés lors de l'audit du 25 août 2026 en
démarrant le jar packagé contre chacun, en insérant des lignes et en appelant les endpoints.

**Ce qui ne change pas.** Le SQL natif par dialecte reste — voir
[0013](0013-flyway-multi-dialect-migrations.md). La raison est `datetime(6)` : un `DATETIME` nu sur
MySQL tronque à la seconde, ce qui fait échouer à la chaîne d'audit sa propre vérification
d'intégrité. Cette précision doit être déclarée, et la déclarer est ce qu'une abstraction de
migration retirerait.

**H2 a été envisagé et refusé.** C'est une base de test que personne ne déploie : l'ajouter
répéterait l'erreur SQLite avec un troisième dialecte à maintenir. Pire, ses modes de compatibilité
masquent exactement les divergences que la campagne existe pour trouver — le défaut qui a produit
`HistoryQueriesIntegrationTest` était une requête que SQLite acceptait et que PostgreSQL refusait.
Si l'objectif était d'accélérer les tests, un conteneur MySQL démarre en six secondes environ.
