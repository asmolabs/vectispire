# Étude : SeaORM pour la persistance du plan de contrôle Rust

**Date :** 26 octobre 2026 · **Arbre étudié :** le portage Rust, `rust/p3-4-gate` @ `0081a85c3`, avec SeaORM
2.0.4 résolu à côté dans un arbre de travail jetable · **Statut :** proposition, aucun code écrit · **En
anglais :** [Study: SeaORM for the Rust control plane's persistence](../en/2026-10-26_rust_seaorm_study.en.md)

Demandée le 2026-10-26 : « pour la partie Rust, étudier une solution comme SeaORM ».

## La question

Le portage Rust du plan de contrôle écrit son accès à la base à la main. Un ORM — SeaORM, celui qui est bâti sur
les bibliothèques que le portage utilise déjà — rendrait-il ce code plus petit et plus sûr, à quel coût, et pour
quelle partie ?

## Ce que le portage a aujourd'hui

`cp-db` et les crates des modules (`cp-issues`, `cp-inventory`, `cp-scanning`, `cp-gate`, `cp-agents`,
`cp-rules`…) parlent à MySQL et PostgreSQL par **sqlx 0.9**, de trois façons :

| Façon | Nombre | Vérifiée | Où |
|---|---|---|---|
| `sqlx::query!`, `query_as!`, `query_scalar!` | 372 | **à la compilation, contre les deux moteurs**, par les deux caches hors ligne de `.sqlx/` | requêtes fixes |
| `sea-query` par `VisibleSelect` | quelques constructeurs | à l'exécution ; la garde de visibilité est dans le type | sélections dynamiques sur les lignes d'une cible |
| `sqlx::query(AssertSqlSafe(…))` | **317** | **pas du tout**, tant qu'un test ne les exécute pas | le CRUD des dépôts — 83 dans `cp-inventory`, 60 dans `cp-issues`, 40 dans `cp-scanning`, 30 dans `cp-gate`, 28 dans `cp-agents` |

Le coût est dans la troisième façon. Une méthode de dépôt typique écrit son instruction **deux fois**, une par
moteur (`?` contre `$1`), choisit selon le moteur de la transaction, et relit la ligne **par nom de colonne, à
l'exécution**, par une macro écrite à la main (`parse_issue_row!`). Une colonne mal orthographiée, un mauvais
type ou un nombre de paramètres qui ne concorde pas se trouve par un test, ou pas du tout.

Le schéma appartient aux migrations Flyway du côté Java, appliquées par `vectispire-migrate` avec les sommes de
contrôle de Flyway, et `parity::check` compare les tables déclarées à ce qu'elles ont construit — le pendant
Rust de `ddl-auto: validate`.

## Ce qu'est SeaORM 2.0, ici

SeaORM est un ORM écrit **sur sqlx et sea-query**, les deux bibliothèques que le portage utilise déjà : des
entités dérivées de structures, une `Column` typée par table, des `find`/`filter`/`update_many` rendus pour le
moteur du moment, `ActiveModel` pour les mises à jour partielles, des relations.

Mesuré contre le portage :

- **Les mêmes fondations.** SeaORM 2.0.4 se résout sur `sqlx 0.9.0` et `sea-query 1.0` — les versions mêmes du
  portage. Pas de second sqlx, pas de second constructeur de requêtes.
- **20 nouvelles crates**, presque toutes des outils de dérivation et de macros procédurales (`sea-orm`,
  `sea-orm-macros`, `sea-query-derive`, `sea-bae`, `darling`, `derive_more`, `derive-where`, `async-stream`,
  `async-trait`, `itertools`, `ordered-float`, `pluralizer`…). Chacune demande un audit `cargo vet` ou une
  exemption nommée, et une licence dans `deny.toml`.
- **Une nouvelle version en double** : `heck` 0.4 à côté de 0.5, utilisé à la compilation seulement. `deny.toml`
  refuse les versions multiples : elle serait nommée dans sa liste `skip`, avec la raison.
- Aucune crate `unsafe` autoréférente (`ouroboros`, que tirait SeaORM 1, a disparu en 2.0).

## Ce qu'il apporterait

- **Les 317 requêtes non vérifiées deviennent typées.** `Issue::find_by_id(id)`,
  `Issue::find().filter(issue::Column::Id.is_in(ids))` : les colonnes sont une énumération, une colonne mal
  orthographiée ne compile pas, et les paramètres du moteur sont l'affaire de SeaORM — l'instruction s'écrit une
  fois, pas deux.
- **Les lignes sont lues dans des structures par la dérivation**, et non par des `try_get` écrits colonne par
  colonne.
- **Les mises à jour conditionnelles comptent leurs lignes** (`update_many().col_expr(…).filter(…).exec()` rend
  le nombre de lignes touchées) : les réclamations et baux que le côté Java tranche par nombre de lignes — la
  réclamation du balayage des tickets de V93, le bail du chef — s'expriment tels quels.

## Ce qu'il coûterait, et ce qu'il ne donnerait pas

- **Aucune vérification contre le schéma à la compilation.** `query!` vérifie une instruction contre le schéma
  réel des deux moteurs ; une entité SeaORM n'est vérifiée contre rien avant de s'exécuter. La réponse est celle
  que `validate` d'Hibernate donne au côté Java : étendre `parity::check` pour comparer les colonnes et les types
  de chaque entité au schéma migré, sur les deux moteurs, dans la suite — un test, pas un espoir.
- **Les transactions.** Le `Tx` du portage est une énumération sur les connexions sqlx des deux moteurs, et
  SeaORM a sa propre `DatabaseTransaction`. Une unité de travail qui mêle un `query!` vérifié et un appel
  d'entité doit tourner sur une seule connexion. SeaORM peut se bâtir sur les pools existants du portage ;
  **qu'une même transaction puisse servir les deux est la question ouverte**, et la maquette ci-dessous y
  répond d'abord.
- **La garde de visibilité.** `VisibleSelect` rend impossible une requête sur les lignes d'une cible sans
  `Visibility`. Un `Select<Entity>` de SeaORM demanderait la même enveloppe, sans quoi la garde est plus faible
  qu'aujourd'hui.
- **Les migrations restent à Flyway.** Jamais `sea-orm-migration` : le schéma est celui du côté Java, appliqué
  avec les sommes de contrôle de Flyway par `vectispire-migrate`, et une seconde autorité sur lui est le défaut
  que `ddl-auto: validate` existe pour empêcher. Les entités peuvent être générées une fois depuis le schéma
  (`sea-orm-cli generate entity`), puis relues et tenues à la main.
- **La chaîne d'approvisionnement** : les 20 audits ci-dessus, une fois.

## Options

1. **En l'état.** Garde les vérifications à la compilation, et les 317 requêtes écrites à la main et en double.
2. **SeaORM partout.** Réécrit aussi les 372 requêtes vérifiées, et perd la seule vérification du portage contre
   le schéma réel à la compilation. Non recommandé.
3. **Hybride.** SeaORM pour le CRUD des dépôts — les 317 requêtes non vérifiées — et `query!` gardé pour les
   instructions fixes, qui restent vérifiées contre les deux moteurs. `sea-query` reste où il est.

## Recommandation

**L'option 3, sous condition d'une maquette sur un module.** Porter le dépôt de `cp-issues` (60 requêtes) et
exiger :

- le rejeu doré du trafic du côté Java et les tests du module verts sur MySQL et PostgreSQL ;
- une transaction exécutant à la fois un `query!` et un appel d'entité, faute de quoi l'hybride est écarté ;
- `parity::check` étendu aux entités du module, qui échoue sur une colonne renommée par un mutant ;
- la garde de visibilité gardée dans le type ;
- les lignes et les instructions en double comptées avant et après.

**Coût** : 2 à 3 jours-dev pour la maquette, les 20 audits de la chaîne d'approvisionnement compris. Si elle
tient, environ 8 à 12 pour les autres dépôts, module par module, chacun derrière son propre rejeu doré. Le
portage reste en pause tant que ce n'est pas tranché ; rien ici ne change le côté Java.

## Résultat de la maquette (26 octobre 2026)

Menée sur la branche `rust/seaorm-spike` (commits 0f1490288 et 7274cd728, non poussés : les contrôles de chaîne
d'approvisionnement de la CI la refusent tant que la décision ci-dessous n'est pas prise). **Les cinq conditions
tiennent ; le coût en chaîne d'approvisionnement est plus élevé qu'estimé plus haut.**

**Comment elle a été jugée.** `cp-issues` n'avait aucun test de son dépôt sur aucun moteur — son seul test vérifiait
la liste des routes — : la maquette a commencé par en écrire un, chaque fonction du dépôt sur MySQL 9.4 et
PostgreSQL 17, tenue à ce que répondent `IssueRepository` et `IssueSpecifications` côté Java. Exécuté d'abord sur le
code écrit à la main, puis sur SeaORM.

**Sa première trouvaille est une fuite du portage écrit à la main, indépendante de SeaORM.** Un lecteur à qui l'on
accorde une *image* voyait aussi les anomalies qui nomment le *dépôt* de cette image : le backlog, les comptes par
sévérité et le registre des exceptions écrivaient `repo_id in (…) or container_id in (…)`, là où Java ne lit l'image
que lorsque le dépôt est nul (0.11.1). Le portage n'est pas livré : personne n'y a été exposé. La version SeaORM lit
la condition dans la fonction même qu'utilise déjà `VisibleSelect`, et la fuite disparaît.

| Condition | Résultat |
|---|---|
| Rejeu doré et tests du module sur les deux moteurs | Suite verte sur les deux. Les routes des anomalies n'avaient jamais été rejouées (`deferred.txt`, phase 3) ; rejouées pour la maquette contre le dépôt écrit à la main et contre SeaORM, sur un même enregistrement de la suite Java (2 368 tests) : **327 → 333 enregistrements verts sur 523, aucun perdu**. Les six gagnés sont le `DualTargetVisibilityRoutesTest` de Java lui-même — la fuite ci-dessus. |
| Une transaction pour un `query!` et un appel d'entité | **Par construction.** SeaORM construit l'instruction ; `cp-db::orm` la rend pour le moteur et l'exécute avec sqlx sur la connexion que tient déjà le `Tx` du portage. Aucune connexion ni transaction SeaORM n'existe. La suite montre chaque côté lisant l'écriture non validée de l'autre, et un seul retour arrière emportant les deux. |
| `parity::check` étendu aux entités | `parity::check_entities` lit colonnes, longueurs et nullabilité sur l'entité et les compare au schéma migré ; vert sur les deux moteurs. Une colonne renommée et une longueur changée sont chacune détectées. |
| La garde de visibilité gardée dans le type | `Visible<E>` ne se construit qu'à partir d'une `Visibility`, n'ajoute que des conditions `AND` et ne rend jamais le `Select` de SeaORM, dont `query()` laisserait revenir un `OR`. L'entité des anomalies n'est pas exportée de son module : `Entity::find()` ne compile pas dans le dépôt. Comme pour `VisibleSelect` et une table nommée dans une chaîne, un détour délibéré par un type associé reste possible. |
| Lignes et instructions en double | Ci-dessous. |

| Persistance de `cp-issues` | écrite à la main | SeaORM |
|---|---|---|
| lignes (code seul) | 1 836 (1 721) | 1 209 (1 046), plus 248 dans `cp-db::orm`, partagées par tous les modules |
| instructions vérifiées par rien | 60 | 0 |
| bras `match` par moteur | 80 | 0 |
| appels `.bind(` | 320 | 0 |
| `query!` vérifiés (deux moteurs) | 0 | 8 — l'insertion d'une ligne, deux comptes, le balayage des orphelins |
| fragments de SQL brut | 0 | 3 — l'âge de résolution (`TIMESTAMPDIFF` / `EXTRACT(EPOCH …)`), l'ordre des sévérités |

Cinq mutants ont été exécutés, chacun détecté sur les deux moteurs : une colonne renommée dans l'entité, une
longueur changée, `Visible` abandonnant la visibilité, la règle de l'image perdant `repo_id is null`, une mise à jour
ignorant la révision.

**Ce que la maquette a coûté et que l'étude ne comptait pas.**

- **cargo vet demande 48 crates, pas 20.** Il juge toutes les fonctionnalités du fichier de verrouillage : la prise
  en charge facultative d'Arrow par SeaORM (douze crates `arrow-*`), les analyseurs `lexical-*`, `sea-schema` et
  `num-bigint` comptent bien que la compilation ne les construise jamais ; la compilation elle-même en lie vingt.
  Chacune demande un audit ou une exemption nommée.
- **cargo deny** refuse une chose : `heck` 0.4 à côté de 0.5, à nommer dans `skip`.
- **Une entité est vérifiée quand la suite s'exécute, pas quand le code compile.** Une colonne renommée fait échouer
  chaque instruction qui la nomme — à l'exécution, par la suite et par `check_entities` — là où un `query!` n'aurait
  pas compilé.

**Trouvé en chemin, quelle que soit la décision.**

- Aucun démarrage n'exécute `parity::check` pour aucun module : le `ddl-auto: validate` du portage existe et n'est
  pas branché (2.11).
- Le rejeu montre deux réponses qui diffèrent de Java dans les deux versions : un `source` absent répondu `""` au
  lieu de `null`, et le `decided_at` des exceptions sérialisé en tableau de nombres au lieu d'un instant.
- Chaque enregistrement de l'historique des dépôts échoue dans le module des scans, sur une requête nommant une
  colonne `repository_id` qui n'existe pas.

**Recommandation : adopter l'hybride**, module par module, chacun derrière la même suite et un rejeu de ses routes,
une fois les 48 entrées de cargo vet ajoutées avec leurs raisons et `heck` nommé dans `skip`. Les dépôts restants
portent environ 257 instructions non vérifiées ; l'estimation de 8 à 12 jours-dev tient, la partie commune
(`cp-db::orm`, `Visible`, la parité des entités) étant désormais écrite. S'il n'est pas adopté, le seul correctif de
visibilité est porté dans le dépôt écrit à la main avant 2.11.
