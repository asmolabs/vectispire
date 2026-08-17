# Zanshin — plan de contrôle NestJS

Le backend, porté depuis Python. Voir
[`docs/migration-nestjs-angular.md`](../docs/migration-nestjs-angular.md) pour ce que le
portage a retenu, écarté et corrigé au passage.

```bash
npm run start:backend                      # depuis la racine, écoute sur :3000
npm test --workspace @zanshin/backend      # suite unitaire
npm run test:integration --workspace @zanshin/backend       # PostgreSQL, exige Docker
npm run test:integration:all --workspace @zanshin/backend   # les quatre moteurs
```

Les tests d'intégration n'exigent aucune base installée : `test/jest-global-setup.ts`
démarre un conteneur par testcontainers et applique les migrations, une fois pour la
campagne. Il n'y a pas de garde « sauter si la base est absente » — une suite qui se
saute rapporte vert sans rien vérifier.

## Les couches, et la règle qui les tient

```
api/ ──► services/ ──► repositories/ ──► persistence/ ──► base
           │                                  │
           └──────────────┬───────────────────┘
                          ▼
                       domain/          (pur, ne dépend de rien)
```

**Une couche ne connaît que celle du dessous.** C'est la règle de la pile Python
(`docs/architecture/01`), reprise telle quelle, avec une couche de plus.

| Couche | Contenu | Ne connaît pas |
|---|---|---|
| `domain/` | Les calculs qui décident : empreinte, verdict du gate, chaîne d'audit, exports | Tout le reste — ni TypeORM, ni NestJS, ni `pg` |
| `persistence/` | Entités TypeORM, dialectes, décodage des types du pilote | Les dépôts, les services, l'API |
| `repositories/` | Accès aux données. Aucune règle métier | Les services, l'API |
| `services/` | Orchestration, transactions. Aucune requête SQL écrite ici | L'API |
| `api/` | Contrôleurs, DTO, gardes | — |

`src/architecture.spec.ts` **vérifie cette règle** en lisant le graphe d'imports : une
couche qui importe au-dessus d'elle, ou un fichier du domaine qui importe un framework,
fait échouer la suite. Une règle d'architecture écrite dans un document n'est pas une
règle — elle est vraie le jour où on l'écrit et fausse six mois plus tard. La pile Python
faisait déjà cela pour l'agent, dont l'invariant d'import est une propriété de sécurité.

### Pourquoi `domain/` est pur

Il porte les calculs dont une erreur ne lève aucune exception mais détruit des données :
l'empreinte d'un problème (une divergence d'un octet efface tout le triage), la chaîne
d'intégrité du journal d'audit, le verdict qui fait échouer une compilation. Trois
conséquences : ils se testent exhaustivement sans base ; le même calcul sert l'API,
l'ordonnanceur et l'interface, donc le verdict affiché *est* celui du gate ; et ils
survivraient à un changement d'ORM ou de framework — l'évènement que ce projet vient
précisément de traverser.

Une seule exemption dans le test : un `*.module.ts` est du câblage, c'est *le* fichier
dont le rôle est de connaître NestJS. `domain/` n'y a pas droit, parce qu'il n'a rien à
injecter.

## Le schéma appartient aux migrations

`synchronize` est à `false`. Les migrations de `persistence/migrations/<dialecte>/` sont
l'unique source du schéma, et les entités le *décrivent* — chaque moteur a son propre jeu,
parce qu'une même intention s'écrit différemment sur chacun.

Ce n'est pas une précaution héritée de la période où Alembic tenait le schéma : c'est
`synchronize: true` qui est le danger. Il modifie la base à partir des entités, au
démarrage, sans trace ni revue — une colonne renommée dans le code s'y traduit par une
colonne détruite en production.

`persistence/schema-parity.integration-spec.ts` tient l'accord entre les deux. Il pose la
question de `migration:generate` — « que faudrait-il changer pour que la base ressemble
aux entités ? » — dont la bonne réponse est « rien ». Il tourne sur le moteur de la
campagne en cours, donc les quatre sont couverts tour à tour, et c'est le seul endroit du
dépôt qui vérifie cet accord. Les deux divergences qu'il a déjà rattrapées — un index
déclaré côté migration mais pas côté entité, et l'inverse — ne changeaient aucun résultat,
seulement leur coût : rien d'autre ne les aurait vues.

## Bases prises en charge

`ZANSHIN_DB_DIALECT` accepte `postgres` (défaut), `sqlite`, `mysql` et `mariadb`. Les
limites de chacun sont **annoncées au démarrage** plutôt que découvertes en production
— voir `persistence/dialects.ts`, dont chaque avertissement nomme la conséquence.

**Les quatre passent la campagne d'intégration entière**, chacun avec son propre jeu de
migrations. Le tableau ci-dessous est mesuré, ligne par ligne, et non déduit.

| | PostgreSQL | MariaDB | MySQL | SQLite |
|---|---|---|---|---|
| Réclamation transactionnelle des scans | oui | oui | oui | **non** |
| Lot de réclamation complet sous contention | oui | oui | **non** | s.o. |
| Horodatages à la milliseconde | oui | oui | oui | oui |
| `NULLS LAST` | oui | non | non | oui |
| Plusieurs écrivains | oui | oui | oui | **non** |

Chaque « non » vient d'un défaut trouvé en exécutant, et **aucun ne produit d'erreur** :

- **`SKIP LOCKED` de MySQL compte les lignes sautées dans le `LIMIT`.** Deux réclamants,
  quatre scans en file : le second repart les mains vides alors que la file n'est pas vide.
  Rien n'est servi deux fois et le reste part au tour suivant — c'est du débit, pas de la
  correction. MariaDB, mesuré sur le même scénario, rend un lot complet comme PostgreSQL.
- **SQLite n'a qu'un écrivain.** Une deuxième instance sur le même fichier ne serait pas
  lente, elle corromprait les données. Sa réclamation retombe donc sur un `UPDATE`
  conditionnel gardé par le statut, ce qui est correct pour les fils d'un même processus.
  Son pilote **refuse** `FOR UPDATE` au lieu de l'ignorer — la pile Python le laissait
  tomber en silence, produisant une réclamation d'apparence transactionnelle qui remettait
  le même scan à deux processus en production.
- **`DATETIME` tronqué à la seconde** était le défaut qui avait coûté MySQL à la pile
  Python : la chaîne d'audit couvre l'horodatage, donc chaque entrée échouait à sa propre
  vérification et le journal se déclarait falsifié sans que rien ne l'ait été. `datetime(6)`
  est déclaré en un seul endroit — `column-types.ts` — plutôt que colonne par colonne, où
  une seule oubliée suffirait.

PostgreSQL reste le moteur de référence : c'est celui sur lequel tout est vrai sans réserve,
et celui que le code choisit par défaut.
