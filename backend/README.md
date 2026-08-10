# Zanshin — plan de contrôle NestJS

Le backend en cours de portage depuis Python. Voir
[`docs/migration-nestjs-angular.md`](../docs/migration-nestjs-angular.md) pour le plan
d'ensemble.

```bash
npm run start:backend                      # depuis la racine, écoute sur :3000
npm test --workspace @zanshin/backend      # suite unitaire
npm run test:integration --workspace @zanshin/backend   # exige un PostgreSQL réel
```

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
règle — elle est vraie le jour où on l'écrit et fausse six mois plus tard. Le projet
Python fait déjà cela pour l'agent, dont l'invariant d'import est une propriété de
sécurité.

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

## Le schéma appartient à Alembic

`synchronize` est à `false`, et ce n'est pas négociable tant que les deux plans de
contrôle coexistent : les quinze révisions Alembic restent l'unique source du schéma,
et les entités le *décrivent*. Laisser TypeORM le modifier ferait diverger les deux
applications sur la base qu'elles partagent.

`persistence/schema-parity.integration-spec.ts` est l'équivalent d'`alembic check` : il
construit la base avec `alembic upgrade head`, interroge `information_schema`, et
confronte pour chaque entité la table, la liste exacte des colonnes dans les deux sens,
et pour chacune le type, la nullabilité et la longueur.

## Bases prises en charge

`ZANSHIN_DB_DIALECT` accepte `postgres` (défaut), `sqlite`, `mysql` et `mariadb`. Les
limites de chacun sont **annoncées au démarrage** plutôt que découvertes en production
— voir `persistence/dialects.ts`, dont chaque avertissement nomme la conséquence.

| | PostgreSQL | SQLite | MySQL / MariaDB |
|---|---|---|---|
| Réclamation transactionnelle des scans | oui | non | non |
| Horodatages à la microseconde | oui | oui | **non** |
| `NULLS LAST` | oui | oui | non |
| Plusieurs écrivains | oui | **non** | oui |

Ces quatre lignes ne sont pas des préférences. Chacune vient d'un défaut trouvé en
exécutant, du temps où la pile Python prenait MySQL en charge, et aucun ne produit
d'erreur :

- **MySQL tronque `DATETIME` à la seconde.** La chaîne d'intégrité du journal d'audit
  couvre l'horodatage : chaque entrée échoue alors à sa propre vérification et le
  journal se déclare falsifié, sans que rien ne l'ait été. `DATETIME(6)` sur *toutes*
  les colonnes de date est la parade ; une seule oubliée suffit à casser la chaîne.
- **`SKIP LOCKED` de MySQL compte les lignes sautées dans le `LIMIT`.** La réclamation
  d'un lot de scans revient courte sous charge, et la concurrence réelle s'effondre en
  silence.
- **SQLite ignore `FOR UPDATE`** au lieu de le refuser. La réclamation ressemble à une
  transaction, passe tous les tests sur une machine de développement, et remet le même
  scan à deux processus en production. D'où l'écrivain unique : un fichier, un
  processus.

PostgreSQL reste le moteur de référence, et le seul sur lequel tout est vrai.
