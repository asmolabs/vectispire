# 0047 — Une version corrective ne porte aucune migration

**Date :** 2026-10-29 · **Statut :** proposée · **S'appuie sur :** [0043](0043-what-1-0-promises.md) §5, [0027](0027-common-migrations-with-type-placeholders.md) · **Décideur :** Laurent Boucher

## Contexte

[0043](0043-what-1-0-promises.md) §5 promet des correctifs de sécurité sur la mineure précédente pendant
trois mois après la sortie de la suivante, et dit qu'une version corrective n'a jamais besoin d'une migration
qu'une mineure ultérieure ne porterait pas aussi ; la règle de numérotation restait à écrire.

Les migrations sont numérotées par un entier (`V91__…`), appliquées par Flyway avec `outOfOrder` désactivé,
et `MigrationLayoutTest` n'accepte que `V<entier>__<description>.sql`. Jusqu'ici, chaque version corrective
a été coupée depuis `develop` lui-même : 0.11.1 a ajouté `V91` et 0.11.2 aucune, alors que `develop`
n'avait rien de plus récent. Une fois la mineure suivante sortie, ce n'est plus vrai, et une migration sur
l'ancienne ligne rencontre l'un de deux échecs :

- **Elle prend le prochain numéro libre** de l'ancienne ligne, que `develop` a déjà utilisé pour autre
  chose : deux migrations différentes sous une même version, et Flyway refuse la seconde sur sa somme de
  contrôle.
- **Elle prend un numéro dans un trou** sous ce que `develop` livre déjà. Une installation déjà sur la
  mineure plus récente rencontre alors une migration plus ancienne que son schéma, et Flyway la refuse
  sauf si `outOfOrder` est activé. Activé, plus rien ne distingue une fusion oubliée d'un correctif voulu.

## Décision

- **Une version corrective ne porte aucune migration.** Un correctif qui demande un changement de schéma va
  dans la mineure suivante. Un correctif de sécurité sur la ligne précédente est écrit pour fonctionner sur
  le schéma de cette ligne ; s'il ne peut pas l'être, il ne sort que dans la mineure suivante, et l'avis de
  sécurité le dit.
- **Vérifié par le workflow de publication.** `release.yml` refuse un tag `vX.Y.Z` avec `Z > 0` dont les
  répertoires de migration diffèrent de ceux de `vX.Y.0`. Une règle tenue de mémoire est celle qu'on oublie
  le jour d'un correctif urgent.
- **Si une exception devient nécessaire**, c'est une décision à part, prise à ce moment-là, l'état de la
  ligne sous les yeux. Le schéma des trous réservés ci-dessous est le point de départ, et il n'est pas
  adopté maintenant.

## Conséquences

- Un correctif de sécurité qui ne peut éviter un changement de schéma arrive tard sur la ligne précédente,
  ou pas du tout ; le tableau des versions maintenues de `SECURITY.md` dit que les versions correctives ne
  changent pas le schéma.
- `MigrationLayoutTest` et `outOfOrder: false` de Flyway restent tels quels.
- Le workflow de publication gagne une étape, exécutée avant toute construction.

## Écarté

- **Des trous réservés** — la première migration de chaque mineure commence au multiple de dix suivant,
  laissant le trou aux correctifs de cette mineure. Cela règle le numéro, pas l'installation déjà sur la
  mineure plus récente, qui a besoin d'`outOfOrder` pour l'appliquer, avec `develop` portant le même fichier
  à la même version. Deux lignes, des migrations hors ordre et une vérification affaiblie pour un cas que
  personne n'a rencontré.
- **Des versions décimales** (`V91.1`). Flyway les ordonne, mais le même problème d'`outOfOrder` se pose, et
  `MigrationLayoutTest` devrait accepter une seconde forme de nom.
- **Des doublons idempotents** — le même changement sous un nouveau numéro sur chaque ligne, écrit pour ne
  rien faire la seconde fois. Chaque ligne porte alors une migration que l'autre n'a pas, et la validation de
  Flyway échoue lors d'une mise à niveau depuis l'ancienne ligne, sauf à ignorer les migrations manquantes,
  ce qui cache aussi les vraies.
