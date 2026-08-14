# 0008 — Deux moteurs de base : PostgreSQL et MySQL

**Date :** 2026-08-14 · **Statut :** acceptée · **Remplace :** [0004](0004-sqlite-et-postgresql-seulement.md)

## Contexte

La décision 0004 gardait SQLite et PostgreSQL, et **refusait MySQL à la configuration**.
Elle était juste avec ce qu'on savait alors : la pile Python avait mesuré trois divergences
MySQL qui ne produisaient aucune erreur mais des données fausses, dont l'une —
l'horodatage tronqué à la seconde — faisait que **le journal d'audit se déclarait falsifié
sans que rien ne l'ait été**.

Deux choses ont changé.

D'abord le besoin : certains clients n'ont pas de PostgreSQL, ils ont MySQL. Un moteur
refusé à la configuration n'est pas un compromis technique, c'est un déploiement impossible.

Ensuite le portage : le plan de contrôle est passé à NestJS/TypeORM, et les trois
divergences ont été réexaminées **en exécutant**, pas en relisant l'analyse de la pile
précédente.

## Décision

`ZANSHIN_DB_DIALECT` vaut `postgres` ou `mysql`. Les deux sont pris en charge et **les deux
passent la campagne d'intégration complète** — 249 tests, chaque moteur démarré à son tour
par testcontainers avec son propre jeu de migrations.

**SQLite part.** Il accepte `FOR UPDATE SKIP LOCKED` puis le supprime en silence : la
réclamation ressemble à une transaction, passe tous les tests sur une machine de
développement, et remet le même scan à deux processus en production. C'est le pire des
comportements — un moteur qui refuse est préférable à un moteur qui ment.

## Ce que la mesure a corrigé

**Les horodatages.** `datetime(6)` est déclaré dans `column-types.ts`, en un seul endroit
plutôt que colonne par colonne, et la connexion est fixée en UTC. La chaîne d'audit hache
l'horodatage sérialisé en ISO — donc à la milliseconde — et elle vérifie. Le défaut qui
avait fait retirer MySQL n'existe plus, parce que sa cause a été supprimée et non
contournée.

**La réclamation.** Le module de dialectes déclarait `canClaimTransactionally: false` pour
MySQL. **C'était faux**, et le laisser aurait écarté MySQL pour une mauvaise raison : la
campagne montre qu'aucune ligne n'est jamais remise à deux réclamants. Le vrai écart est
ailleurs, et il a désormais son propre drapeau — `claimsCompleteBatches`. MySQL compte les
lignes sautées dans le `LIMIT`, donc un lot revient court sous contention ; le reste part au
tour suivant. C'est du débit, pas de la correction.

**Un défaut que MySQL a révélé des deux côtés.** Il n'y avait aucun index sur la file de
scans. MySQL l'a dit brutalement — « Lock wait timeout exceeded » — parce que sans index le
moteur verrouille chaque ligne examinée. PostgreSQL tolérait l'absence sur une table de
test, ce qui a gardé le défaut invisible. **La cause est la même sur les deux moteurs, seule
sa manifestation diffère**, et l'index est posé des deux côtés.

## Ce qui reste vrai de 0004

Le prix du support multi-dialecte reste payé de la même façon : les capacités sont
**déclarées** dans `dialects.ts` plutôt que devinées, et un opérateur apprend au démarrage
ce que son moteur ne sait pas faire. Rien n'est interdit en silence.

## Ce qui n'est pas décidé ici

**MariaDB reste non pris en charge**, et par prudence plutôt que par constat : il n'a pas
été mesuré. Le supposer identique à MySQL serait exactement le raisonnement que cette
décision a dû corriger.
