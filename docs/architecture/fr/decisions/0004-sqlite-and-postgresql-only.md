# 0004 — Deux moteurs de base de données : SQLite et PostgreSQL

**Date :** 2026-08-10 · **Statut :** **remplacé** par [0008](0008-postgresql-and-mysql.md) le 2026-08-14

## Contexte & Décision

SQLite pour les déploiements autonomes embarqués, PostgreSQL pour les déploiements de production en
cluster. L'attrait était que le plus petit déploiement n'exigeait aucun serveur.

## Pourquoi elle était fausse

**SQLite n'a jamais été un moteur déployable, et c'est ici que cette erreur est entrée.** Sous le
`ddl-auto: validate` livré, l'application refuse de démarrer dessus : SQLite a des *affinités* de
type plutôt que des types, il renvoie donc une colonne d'horodatage comme un FLOAT et Hibernate
rejette la correspondance. C'était connu à l'intérieur du profil de test et cela a contredit le
périmètre supporté pendant quinze jours. La [0014](0014-two-engines-and-a-test-fixture.md) l'a
enfin établi en l'exécutant, et a rétrogradé SQLite à ce qu'il avait toujours été en réalité : la
fixture sur laquelle tourne la suite HTTP.

La [0008](0008-postgresql-and-mysql.md) a remplacé cet enregistrement quatre jours plus tard pour
une autre raison — MySQL — et n'a pas propagé l'erreur SQLite, mais ne l'a pas nommée non plus.
Personne n'y est revenu avant que le périmètre des moteurs ne se soit renversé deux fois de plus.
