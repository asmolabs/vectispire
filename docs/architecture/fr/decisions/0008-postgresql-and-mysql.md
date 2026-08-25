# 0008 — Deux moteurs de base de données : PostgreSQL et MySQL

**Date :** 2026-08-14 · **Statut :** **remplacé** par [0009](0009-four-engines.md) le 2026-08-16 · **Remplace :** [0004](0004-sqlite-and-postgresql-only.md) · **Décideur :** Laurent Boucher

## Contexte & Décision

PostgreSQL et MySQL, après réexamen de la précision temporelle de MySQL, jugée praticable : un
`DATETIME` nu tronque à la seconde, un `datetime(6)` non, et la chaîne d'audit a besoin de la
milliseconde qu'elle hache. SQLite est sorti du périmètre supporté.

## Pourquoi elle a été remplacée — et pourquoi ce fut un détour

La [0009](0009-four-engines.md) a élargi le périmètre à quatre moteurs deux jours plus tard, sous
deux pressions qu'elle consigne : SQLite était déjà ce sur quoi tournait la suite de tests HTTP, et
MariaDB était réclamé par des déploiements qui en disposaient.

**La [0014](0014-two-engines-and-a-test-fixture.md) est ensuite revenue exactement à la réponse de
cet enregistrement** — PostgreSQL et MySQL, SQLite étant nommé fixture de test et non moteur. Le
registre a passé six jours et deux enregistrements à revenir à son point de départ.

Cela mérite d'être conservé plutôt que rangé. Ce qui a rendu ce retour défendable n'est pas un
meilleur jugement : c'est que la campagne quatre moteurs avait été *exécutée*, et son coût mesuré —
chaque changement de schéma écrit quatre fois, une campagne jamais câblée à la CI, et une assertion
périmée en échec depuis une durée inconnue. Le renversement provoqué par le remplacement de cet
enregistrement fut bon marché parce que personne ne l'avait expliqué ; celui de la 0014 a coûté
cher à établir, et c'est donc celui qui devrait tenir.
