# 0009 — Quatre moteurs de base de données, chacun mesuré

**Date :** 2026-08-16 · **Statut :** **remplacé** par [0014](0014-two-engines-and-a-test-fixture.md) le 2026-08-25 · **Remplace :** [0008](0008-postgresql-and-mysql.md) · **Décideur :** Laurent Boucher

## Contexte

La [0008](0008-postgresql-and-mysql.md) avait restreint le périmètre à PostgreSQL et MySQL. Deux
pressions l'ont rouvert : SQLite était déjà ce sur quoi tournait la campagne de tests HTTP, et
MariaDB était demandé par des déploiements qui en disposaient et ne voulaient pas d'un second
serveur.

## Décision

Supporter PostgreSQL, MySQL, MariaDB et SQLite, avec un jeu de migrations SQL natives par dialecte
et une campagne d'intégration (`integrationTestAll`) qui exécute la suite complète contre chacun.

## Conséquences

**Ce que cela a apporté, et cette part est réelle.** Exécuter les quatre a révélé des défauts de
portabilité invisibles à la lecture et à un moteur unique — un paramètre nullable comparé à une
colonne, que SQLite accepte et que PostgreSQL refuse par *could not determine data type of parameter
$2* ; un `DATETIME` nu sur MySQL tronquant à la seconde et faisant échouer à la chaîne d'audit sa
propre vérification. Aucun des deux n'est visible en relecture. Les deux ont été trouvés en
exécutant.

**Ce que cela a coûté, et cette part a été sous-estimée.** Chaque changement de schéma devait être
écrit quatre fois, et la campagne n'a jamais été branchée à la CI — l'argument justifiant le coût
dépendait donc de quelqu'un se souvenant de la lancer. En août 2026, elle échouait depuis une durée
inconnue sur un compteur d'entités périmé, ce qui est la forme même d'une garantie que personne ne
vérifie.

**Ce qui n'a jamais été établi.** Que les quatre puissent réellement être *déployés*. SQLite ne le
pouvait pas : sous le `ddl-auto: validate` livré, il refuse de démarrer, ses affinités de type
rendant une colonne d'horodatage en FLOAT. C'était su à l'intérieur du profil de test et n'a jamais
été reflété dans le périmètre supporté. La [0014](0014-two-engines-and-a-test-fixture.md) le
corrige.
