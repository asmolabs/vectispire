# 0027 — Migrations communes avec des placeholders de type ; répertoires par moteur pour les divergences de structure

**Date :** 2026-09-26 · **Statut :** acceptée · **Amende :** [0013](0013-flyway-multi-dialect-migrations.md) · **Décideur :** Laurent Boucher

## Contexte

La [0013](0013-flyway-multi-dialect-migrations.md) a choisi Flyway avec un jeu SQL natif par
moteur, et a nommé la condition pour la revoir : *« si les changements de schéma se révèlent identiques
sur tous les moteurs assez longtemps pour que la duplication devienne pure cérémonie »*. Les jeux
ont été mesurés le 2026-09-26, après trente-neuf migrations écrites chacune trois fois sous
`db/migration/{mysql,postgresql,sqlite}` :

* **Treize sont identiques en substance sur les trois.**
* **L'essentiel des autres différences sont des noms de type** : un horodatage est `datetime(6)`,
  `timestamp with time zone` ou `numeric` ; une identité est `bigint auto_increment`, `bigint
  generated always as identity` ou `integer primary key autoincrement` ; un booléen est `bit(1)` avec
  `b'0'`, `boolean` avec `false`, ou `boolean` avec `0` ; un texte long est `longtext` ou `text`.
* **Les divergences de structure sont plus rares** : les contraintes de clé étrangère nommées de
  MySQL (il analyse un `references` en ligne puis l'ignore), les changements de colonne (`modify`,
  `alter column … type`, reconstruction de table ou rien sur SQLite), l'arithmétique de dates, les
  corrections de données.

La duplication n'est pas qu'une affaire de frappe. Trois copies, ce sont trois occasions de
diverger, et le jeu MySQL diverge déjà *de lui-même* : V1, V4 et V14 déclarent les booléens en
`bit(1)`, V8, V25 et V27 en `boolean` — que MySQL stocke en `tinyint(1)`. Personne ne l'a décidé ;
chaque auteur a recopié le voisin qui était ouvert.

La raison de la 0013 pour le SQL natif tient toujours et n'est pas rouverte ici : une abstraction de
migration qui choisit le type à votre place, c'est ainsi qu'un `datetime` sans sa précision arrive
sur MySQL, et que la chaîne d'audit signale une altération qui n'a jamais eu lieu. La question est de
savoir si les types peuvent être nommés une fois *sans* être cachés.

## Décision

**À partir de V40, une migration qui ne diffère d'un moteur à l'autre que par ses types de colonne
est écrite une fois, sous `db/migration/common`, avec des placeholders de type ; une migration dont
la structure diverge est écrite dans chacun des trois répertoires par moteur.** Flyway lit
`classpath:db/migration/common,classpath:db/migration/{vendor}`.

**Les placeholders sont fixés par moteur par `MigrationPlaceholders`, un
`FlywayConfigurationCustomizer`, depuis une seule table dans `MigrationDialect`** (tous deux dans
`core/config`) :

| Placeholder | MySQL | PostgreSQL | SQLite (fixture) |
|---|---|---|---|
| `${ts}` | `datetime(6)` | `timestamp with time zone` | `numeric` |
| `${id}` | `bigint auto_increment primary key` | `bigint generated always as identity primary key` | `integer primary key autoincrement` |
| `${bool}` | `bit(1)` | `boolean` | `boolean` |
| `${true}` / `${false}` | `b'1'` / `b'0'` | `true` / `false` | `1` / `0` |
| `${text}` | `longtext` | `text` | `text` |
| `${double}` | `double` | `double precision` | `double` |

Cette table *est* la réponse à l'inquiétude de la 0013 : le type que reçoit chaque moteur est écrit
dans un seul fichier, à côté de la raison pour laquelle `${ts}` vaut `datetime(6)`, et rien ne le
traduit en chemin. Flyway substitue le texte et le moteur l'exécute.

* **Le moteur est identifié comme Spring Boot l'identifie pour `{vendor}`** — l'URL de la source de
  données, via `DatabaseDriver` — de sorte que le répertoire lu et les types substitués ne peuvent
  pas diverger. Un moteur sans correspondance arrête le démarrage ; une propriété
  `spring.flyway.placeholders.*` qui tenterait de redéfinir l'un de ces types l'arrête aussi.
* **`${id}` porte lui-même `primary key`**, et une nouvelle table écrit `id ${id},`. C'est SQLite
  qui l'impose : seule la formule exacte `integer primary key` fait de la colonne le rowid,
  `autoincrement` est refusé partout ailleurs, et `integer primary key` sans lui redonne l'id d'une
  dernière ligne supprimée à l'insertion suivante.
* **`${bool}` vaut `bit(1)` sur MySQL** — le type auquel Hibernate y associe un booléen, et celui
  de V1 — ce qui met fin à la dérive décrite plus haut pour tout ce qui s'écrit désormais.

**La règle, exécutée.** Une version vit soit dans `common`, une fois, soit dans les trois
répertoires par moteur — jamais dans un ou deux d'entre eux, jamais dans `common` et un répertoire
de moteur. Un fichier de `common` ne nomme aucun moteur : `MigrationLayoutTest`, dans la suite
unitaire, refuse le reste et fait échouer le build. Il refuse aussi un nom de fichier que Flyway
ignorerait sans rien dire, un placeholder inconnu, `${id} primary key`, un répertoire qui ne
correspond à aucun moteur, un nouveau triplet identique octet pour octet (sa place est dans
`common`), et toute migration de V1 à V39 qui quitterait les répertoires par moteur. Les jetons
propres à un moteur qu'il refuse dans `common` comprennent `auto_increment`, `autoincrement`,
`generated always`, `datetime`, `timestamp`, `bit(`, `boolean`, `longtext`, les accents graves et
les guillemets doubles, et — parce qu'ils sont structurels — `references`, `modify`, `alter column`
et les fonctions de date.

**Une clé étrangère est une divergence de structure.** MySQL exige un `alter table … add
constraint` nommé ; SQLite ne peut pas ajouter de contrainte après le `create table`. Une table qui
porte une clé étrangère s'écrit donc trois fois, comme V19 et V39.

**V1 à V39 ne sont pas réécrites.** Flyway valide la somme de contrôle de chaque migration appliquée
et refuse de démarrer si l'une a changé : déplacer les treize fichiers identiques dans `common`, ou
modifier un fichier pour y mettre un placeholder, arrêterait toutes les installations existantes.
Activer les placeholders ne déplace pas ces sommes : dans Flyway 12.4, `SqlMigrationResolver` calcule
celle d'une migration versionnée avec `ChecksumCalculator` sur la ressource brute, et seule celle
d'une migration répétable est prise après remplacement des placeholders. Le remplacement était déjà
actif — c'est le défaut de Flyway — et aucun des trente-neuf fichiers ne contient `${`.

**Démontré sur les moteurs.** La campagne ajoute un emplacement réservé aux tests, qui contient une
migration commune de sonde, `V9000__placeholder_probe`, utilisant chaque placeholder ;
`MigrationPlaceholdersIntegrationTest` l'applique par le Flyway de l'application elle-même sur MySQL,
PostgreSQL et SQLite, lit le catalogue de chaque moteur (`datetime(6)`, `timestamp with time zone`,
une identité `ALWAYS`, une clé primaire `integer`) et fait l'aller-retour d'une milliseconde, des
deux valeurs par défaut booléennes, d'un texte de plus de 64 Kio, d'un double et d'une identité qui
ne réutilise pas un id supprimé. La sonde n'est jamais sur le classpath de production.

### Pourquoi pas Liquibase, à nouveau

C'est l'outil qui écrit un schéma une fois, et il a été examiné.

* **Licence.** Liquibase Community est publié depuis la 5.0 sous Functional Source License
  (FSL-1.1-ALv2), qui n'est pas une licence open source au sens de l'OSI. Gouverner les licences de
  ses clients fait partie du métier de Vectispire, qui est distribué sous Apache 2.0
  ([0012](0012-apache-2-0.md)) ; un composant non OSI dans son propre cœur est une contradiction que
  les achats d'un client trouveront avant que nous l'expliquions.
* **La 4.x est en fin de vie** : rester sur la dernière ligne sous licence Apache, c'est ne plus
  recevoir de correctifs.
* **Les raisons de la 0013 n'ont pas changé.** Un changelog indépendant du moteur traduit les
  types, et c'est cette étape qui a caché `datetime(6)`.
* **L'historique devrait migrer.** Chaque installation existante porte un `flyway_schema_history` ;
  changer d'outil suppose une opération `changelogSync` sur chacune, et une migration de l'outil de
  migration est une panne que vivent les clients, pas nous.

## Conséquences

**Ce que l'on gagne.** Une migration qui ne fait qu'ajouter des tables et des colonnes s'écrit une
fois, et les trois moteurs ne peuvent plus diverger sur elle. Les types sont décidés en un seul
endroit relu, au lieu d'être redécidés par chaque auteur.

**Ce que cela coûte.** Le lecteur d'une migration commune cherche `${ts}` une fois, dans
`MigrationDialect`. Et une version a désormais deux endroits où vivre ; c'est le test qui empêche
que cela devienne « n'importe où ».

**Une valeur de la table est aussi figée qu'une migration appliquée.** Flyway ne rejoue pas ce qu'il
a appliqué : changer plus tard, par exemple, `${text}` ne change que les colonnes des *nouvelles*
installations, et les deux populations divergent sans bruit. Un changement de type est une nouvelle
migration qui modifie les colonnes existantes — écrite dans les répertoires par moteur, puisqu'un
changement de colonne est structurel — et seulement ensuite un changement de la table.

**Quand la revoir.** Si une divergence de structure revient assez souvent sous la même forme (une
clé étrangère par nouvelle table, par exemple) pour qu'un second genre de placeholder la porte sans
la cacher ; ou si l'ensemble des moteurs pris en charge change, auquel cas la table gagne une
colonne et chaque placeholder doit répondre sur le nouveau moteur avant que la première migration
commune ne s'y applique.
