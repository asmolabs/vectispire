# 0013 — Flyway avec des migrations natives par dialecte

**Date :** 2026-08-22 · **Statut :** accepté · **Remplace :** [0011](0011-liquibase-rather-than-flyway.md) · **Décideur :** Laurent Boucher

## Contexte

Le portage est arrivé avec Liquibase et un changelog agnostique : une description du schéma,
traduite par moteur par l'outil. L'attrait est évident — le schéma s'écrit une fois — et il a tenu
jusqu'à ce que le schéma ait besoin de quelque chose que l'abstraction ne savait pas dire.

Deux cas ont tranché, et tous deux sont porteurs plutôt que cosmétiques :

* **`datetime(6)` sur MySQL.** Un `DATETIME` nu tronque à la seconde. La chaîne d'audit hache un
  horodatage canonisé à la milliseconde : une colonne tronquée fait donc échouer au journal *sa
  propre* vérification d'intégrité — un contrôle de sécurité signalant une altération qui n'a jamais
  eu lieu, ce qui est pire qu'un contrôle qui ne signale rien.
* **Les clés étrangères et le comportement de cascade diffèrent** assez entre moteurs pour que le
  DDL généré doive de toute façon être inspecté moteur par moteur. À ce stade, l'abstraction est une
  couche entre l'auteur et l'instruction qu'il est déjà en train de lire.

## Décision

Flyway, avec un jeu de migrations SQL natives par dialecte sous
`src/main/resources/db/migration/{vendor}/`. `ddl-auto` reste à `validate` : le schéma appartient
aux migrations, et Hibernate ne doit jamais le réconcilier à l'exécution.

## Conséquences

**Le coût est la duplication, et il est réel.** Chaque changement de schéma s'écrit une fois par
moteur supporté. La [0014](0014-two-engines-and-a-test-fixture.md) l'a ramené de quatre jeux à deux,
ce qui est le principal argument qui plaiderait sinon pour un retour en arrière.

**Ce que l'on achète, c'est que l'instruction dans le fichier est l'instruction que le serveur
exécute.** Aucune étape de traduction ne s'interpose entre une relecture et le DDL, et la précision
dont dépend la chaîne d'audit est déclarée là où un lecteur la voit.

**Quand réexaminer.** Si le périmètre supporté s'élargit de nouveau, ou si les changements de schéma
se révèlent identiques sur tous les moteurs assez longtemps pour que la duplication devienne pure
cérémonie. Pas avant : la raison d'être de cette décision est un contrôle qui échoue silencieusement
quand l'abstraction se trompe de type.
