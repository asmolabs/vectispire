# 04 — Exécution et déploiement

Ce qu'un déploiement a le droit d'être, ce qui lui est refusé, et ce qui coordonne plusieurs
instances.

## Les deux formes

Un seul binaire et un seul interrupteur. `VECTISPIRE_EMBEDDED_WORKER` décide si le plan de contrôle
analyse aussi.

| | Worker embarqué (`true`, par défaut) | Agents distants (`false`) |
|---|---|---|
| Qui détient la socket Docker | le plan de contrôle | chaque agent |
| Qui atteint la base de données | le plan de contrôle | le plan de contrôle, **uniquement** |
| Qui détient `ENCRYPTION_KEY` | le plan de contrôle | le plan de contrôle, **uniquement** |
| Ce qu'un agent reçoit | — | un jeton restreint, et du matériel scellé par analyse |

**L'interrupteur est porteur, pas cosmétique.** `ScanDispatcher` prend un `Optional<ScanRunner>` et
refuse de réclamer du travail lorsqu'il est vide — un plan de contrôle sans capacité d'analyse ne
doit pas réclamer une analyse pour ensuite la faire échouer. Mettre l'indicateur à `false` est ce
qui fait dire à cette branche vide *« servi par des agents »* plutôt que *« personne n'a câblé le
runner »* ; la seconde a été vraie, et chaque analyse en file restait `pending` pour toujours sans
une seule ligne de journal.

Un agent n'ouvre jamais de connexion JDBC et ne détient jamais la clé de chiffrement. Il reçoit le
travail par long polling ([0003](decisions/0003-long-polling-for-agents.md)) et renvoie les
résultats par le même canal.

## La base de données

**PostgreSQL ou MySQL. MySQL est le défaut** — c'est ce que livre `docker-compose.yml` — et le
moteur est choisi par la seule variable `VECTISPIRE_DB_URL`
([0014](decisions/0014-two-engines-and-a-test-fixture.md)).

**SQLite est refusé, et le refus mérite d'être énoncé parce qu'il a été documenté comme
supporté.** Sous le `ddl-auto: validate` livré, l'application ne démarre pas dessus : SQLite a des
*affinités* de type plutôt que des types, il renvoie donc une colonne d'horodatage comme un FLOAT
et Hibernate rejette la correspondance. Il demeure dans le dépôt comme la fixture sur laquelle
tourne la suite de tests HTTP, et ses migrations sont maintenues pour cette seule raison.

Le schéma appartient aux migrations Flyway, un jeu SQL natif par dialecte
([0013](decisions/0013-flyway-multi-dialect-migrations.md)). Hibernate valide et ne réconcilie
jamais : un déploiement dont le schéma diverge des entités échoue au démarrage plutôt qu'à la
première requête qui touche la différence.

## Plusieurs instances à la fois

Quatre tâches périodiques tournent dans chaque instance, et **une seule est élue par bail.** Cette
distinction fait tout l'objet de cette section, car le résumé évident — « les tâches de fond sont
coordonnées par un bail » — est faux et enverrait un lecteur chercher un bail qui n'existe pas.

| Tâche | Période | Coordination |
|---|---|---|
| Tick du worker d'analyse | 15 s | inutile : **réclamer** une analyse en file est le contrôle de concurrence |
| Planificateur d'analyses | 60 s | **leader seul**, sur le bail `scheduler` dans `t_leader_lease` |
| Relais de notifications | 60 s | aucune : l'outbox marque ce qu'il a envoyé |
| Maintenance horaire | 1 h | aucune : l'élagage est idempotent |

Le planificateur est élu parce qu'il *crée* du travail : deux instances décidant indépendamment
qu'une analyse nocturne est due la mettraient deux fois en file. Les autres réclament ce qui existe
déjà ou répètent une opération dont la seconde exécution ne coûte rien — et une élection n'y
apporterait rien tout en ajoutant un bail qui peut expirer en cours de passe.

**Chaque tâche attend avant sa première exécution.** `fixedDelay` espace les exécutions suivantes
et ne fait rien pour la première, qui partirait sinon alors que Flyway vient de terminer et que le
pool se remplit encore.

## Ce qu'un déploiement doit recevoir

Deux variables n'ont pas de valeur par défaut, délibérément, et le conteneur refuse de démarrer
sans elles :

- `ENCRYPTION_KEY` — déchiffre chaque clé SSH de déploiement et chaque jeton d'intégration que
  l'instance détient. Un défaut partagé signifierait que quiconque possède une copie de ce dépôt
  peut les lire.
- le mot de passe de la base, et celui du premier administrateur.

`VECTISPIRE_TRUSTED_PROXIES` est vide par défaut, ce qui signifie que `X-Forwarded-For` est
**ignoré** et que l'adresse du pair sert de clé de limitation de débit. Ne la renseigner que
lorsqu'il y a réellement quelque chose devant : faire confiance à l'en-tête sans proxy laisse un
appelant choisir son propre seau de limitation.

## Le miroir d'audit

`VECTISPIRE_AUDIT_MIRROR` est **désactivé dans l'application et activé dans compose**, ce qui
paraît incohérent et ne l'est pas : l'application le livre désactivé parce qu'écrire vers un chemin
par défaut échoue sur un système de fichiers en lecture seule, et un déploiement compose dispose
d'un volume inscriptible — c'est donc le seul endroit où le défaut peut être « activé ».

Il ferme le cas que la chaîne de hachage ne peut pas voir. Supprimer la *dernière* entrée — celle
dont rien ne descend — laisse une chaîne qui se vérifie parfaitement. Le miroir impose à cette
suppression une seconde édition dans un second médium, et un collecteur de journaux expédie
normalement le fichier hors de la machine en quelques secondes. Pointez un collecteur sur ce
volume ; un miroir que personne ne collecte ne fait qu'augmenter le coût d'une suppression.

## Les images

Deux images sont publiées, et la voie `Dockerfile` est celle qui est livrée : elle peut faire un
`chown` du répertoire du miroir d'audit, là où Jib ne peut poser qu'un mode. Jib construit les deux
mêmes à chaque poussée parce qu'il n'a besoin d'aucun démon et qu'il est rapide ; la construction
`Dockerfile` tourne la nuit. Les deux embarquent `LICENSE` et `NOTICE`, et la tâche nocturne
vérifie que le jar est bien là où l'image le dit — le défaut qui a rendu cette tâche nécessaire
était un `COPY` d'un fichier que la construction ne produisait pas.
