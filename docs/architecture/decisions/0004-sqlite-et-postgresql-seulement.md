# 0004 — Deux moteurs de base : SQLite et PostgreSQL

**Date :** 2026-08-10 · **Statut :** **remplacée** par [0008](0008-postgresql-et-mysql.md) le 2026-08-14

> Cette décision refusait MySQL sur des divergences mesurées, et elle était juste avec ce
> qu'on savait alors. La 0008 le rouvre après les avoir réexaminées en exécutant — et
> retire SQLite, qui supprime `FOR UPDATE SKIP LOCKED` en silence. Le texte ci-dessous est
> conservé tel quel : il dit ce qui était su à cette date.

## Contexte

Trois moteurs étaient pris en charge et testés : SQLite, PostgreSQL 16, MySQL 8.4. La
suite multi-backends existait pour de bonnes raisons — six défauts de portabilité de ce
schéma étaient invisibles à la fois depuis SQLite et à la lecture, tous trouvés en
exécutant.

La question posée était : faut-il abandonner SQLite, dont la limite d'un seul écrivain
complique le déploiement en flotte ?

## Décision

Non — **c'est MySQL qui part.**

`SUPPORTED_BACKENDS` vaut `("sqlite", "postgresql")`. SQLite est le déploiement à une
instance ; PostgreSQL est tous les autres. Une URL MySQL ou MariaDB est **refusée à la
configuration**, avec la raison et la migration à faire.

### Pourquoi garder SQLite

Le prix du support multi-dialecte est déjà payé, et correctement : `supports_skip_locked`
teste le dialecte au lieu de le supposer, `startup_guard` refuse au démarrage le
déploiement qui ne peut pas marcher. Il ne reste presque rien à écrire.

En face, SQLite achète la seule chose qui décide de l'adoption d'un outil libre : **on peut
l'essayer.** Exiger un PostgreSQL avant le premier résultat déplace l'évaluation d'un quart
d'heure à une demi-journée.

Et abandonner SQLite ne réglerait pas le problème qu'on croirait régler : sur les trois
obstacles au déploiement en flotte, PostgreSQL n'en lève qu'un. L'état serveur de Reflex
reste collé à l'instance qui a accepté la socket — il faut Redis — et le verrou de
migration reste par hôte.

### Pourquoi MySQL part

Il ne remplissait **aucun rôle** que les deux autres ne couvrent : ni l'option sans
configuration, ni la cible de déploiement. Il avait en revanche son comportement propre à
trois endroits, chacun trouvé par un test et non par une relecture :

- **`DATETIME` tronqué à la seconde entière**, silencieusement, sauf précision
  fractionnaire déclarée. Le journal d'audit hache `timestamp.isoformat()`, donc une entrée
  relue après écriture retombait sur une empreinte différente et **se déclarait falsifiée** ;
- **`SKIP LOCKED` comptant les lignes sautées dans `LIMIT`**, donc six réclamants sur dix
  repartaient les mains vides alors que vingt scans attendaient ;
- **`NULLS LAST` en erreur de syntaxe.**

Trois branches par dialecte dans du code dont le sujet est l'intégrité, exercées par un
seul job de CI. Le coût n'était pas le code : c'était qu'un défaut à cet endroit ressemble
à un comportement correct partout où on le teste.

## Ce qu'on a écarté

**Abandonner SQLite** — voir ci-dessus.

**Laisser MySQL fonctionner sans le tester.** SQLAlchemy s'y connecterait et la majorité
de Zanshin marcherait, donc un opérateur qui garderait son URL rencontrerait le retrait
des mois plus tard, sous la forme d'un journal d'audit qui se dit falsifié. Un backend qui
n'est plus testé doit échouer bruyamment à la première ligne, pas subtilement à la
centième.

## Conséquences

Ce qui a été **conservé bien que motivé par MySQL**, et pourquoi :

- **le budget de réessais de la réclamation.** Presque jamais dépensé sur PostgreSQL, mais
  retirer un garde-fou de concurrence dans le commit qui supprime les tests censés en
  constater l'absence serait la mauvaise façon de le retirer ;
- **le tri sur `colonne IS NULL` plutôt que `nullslast()`.** Écrit pour MySQL, il se trouve
  être aussi ce dont SQLite a besoin : sans lui, les problèmes sans score EPSS passeraient
  devant ceux qui en ont un, silencieusement, sur le moteur que presque tout le monde
  utilise.

Les migrations ne sont pas réécrites : ce sont des enregistrements de ce qui a été
appliqué. Leurs branches MySQL sont mortes et inoffensives, et les toucher est ce qui a
déjà cassé une installation neuve une fois.
