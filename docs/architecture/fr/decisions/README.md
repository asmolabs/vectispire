# Registre des Décisions d'Architecture (ADR) — Français

Ce répertoire répertorie l'ensemble des décisions structurelles d'architecture (ADR) de Vectispire.

| ADR | Titre | Statut |
|---|---|---|
| [0001](0001-pluggable-scan-layer.md) | Couche d'analyse extensible | remplacée par [0010](0010-one-scan-runner.md) |
| [0002](0002-the-database-carries-the-queue.md) | La base de données porte la file d'attente | acceptée |
| [0003](0003-long-polling-for-agents.md) | Long-polling pour la communication avec les agents distants | acceptée |
| [0004](0004-sqlite-and-postgresql-only.md) | Support initial de SQLite et PostgreSQL | remplacée par [0008](0008-postgresql-and-mysql.md) |
| [0005](0005-quality-never-blocks-the-gate.md) | Les règles de qualité de code ne bloquent jamais les gates | acceptée |
| [0006](0006-semgrep-rules-written-here.md) | Inclusion native des règles Semgrep dans l'application | acceptée |
| [0007](0007-none-is-not-an-empty-list.md) | L'absence d'analyse n'est pas une liste vide | acceptée |
| [0008](0008-postgresql-and-mysql.md) | Prise en charge combinée de PostgreSQL et MySQL | remplacée par [0009](0009-four-engines.md) |
| [0009](0009-four-engines.md) | Quatre moteurs de base de données, chacun mesuré | remplacée par [0014](0014-two-engines-and-a-test-fixture.md) |
| [0010](0010-one-scan-runner.md) | Exécuteur ScanRunner unique et concret | acceptée |
| [0011](0011-liquibase-rather-than-flyway.md) | Liquibase, avec le DDL structurel écrit à la main | remplacée par [0013](0013-flyway-multi-dialect-migrations.md) |
| [0012](0012-apache-2-0.md) | Licence Apache 2.0 | acceptée |
| [0013](0013-flyway-multi-dialect-migrations.md) | Migrations Flyway multi-dialectes nativement gérées | acceptée |
| [0014](0014-two-engines-and-a-test-fixture.md) | Deux moteurs déployables, et SQLite comme fixture de test | acceptée |
| [0015](0015-one-secrets-engine.md) | Un seul moteur de secrets | acceptée |
| [0016](0016-no-spdx-document.md) | CycloneDX est le SBOM généré ; SPDX n'est pas produit | acceptée |
| [0017](0017-custom-checks-as-container-images.md) | Checks personnalisés en images de conteneur, pas en JAR | proposée |
| [0018](0018-the-docker-socket-is-never-mounted.md) | Le socket Docker n'est jamais monté dans le plan de contrôle | acceptée |
| [0019](0019-screen-text-is-translated-on-the-client.md) | Le serveur envoie un jeton ; l'écran détient la phrase | acceptée |
| [0020](0020-screenshots-stay-png.md) | Les captures restent en PNG, et le déclencheur qui changera cela est nommé | acceptée |
| [0021](0021-the-docs-site-stays-on-mkdocs-1.md) | Le site de documentation reste sur MkDocs 1, jusqu'à ce qu'un autre outil sache le publier en deux langues | acceptée |
| [0022](0022-https-clone-tokens-are-bound-to-a-host.md) | Le clonage HTTPS utilise un jeton géré, lié à un hôte | acceptée |
| [0023](0023-solutions-projects-and-repositories.md) | Une solution contient des projets, un projet référence des dépôts, et un droit peut viser un projet | acceptée |
| [0024](0024-integration-api-keys-act-for-an-account.md) | Une clé API d'intégration agit pour un compte, sur les routes qui l'acceptent | acceptée |
| [0025](0025-siem-events-leave-through-the-outbox.md) | Les événements SIEM partent par l'outbox, après validation, et leur catalogue est un contrat | acceptée |
| [0026](0026-services-are-grouped-by-domain.md) | Les services sont regroupés par domaine, et les domaines dépendent dans un seul sens | acceptée |

**Sur la longueur.** Les ADR [0004](0004-sqlite-and-postgresql-only.md),
[0008](0008-postgresql-and-mysql.md) et [0011](0011-liquibase-rather-than-flyway.md) sont courtes
parce qu'elles sont **remplacées** — mais courte ne veut pas dire muette. Chacune dit désormais ce
qu'elle a décidé et **ce qui l'a démentie**, car c'est la partie dont un lecteur a besoin et celle
que l'enregistrement qui l'a remplacée ne peut pas fournir : un successeur plaide sa propre cause,
pas l'échec de son prédécesseur. La [0001](0001-pluggable-scan-layer.md) est courte pour la même
raison.

Une décision consignée sans son raisonnement est une ligne de changelog. Ce registre en comptait
neuf au 25 août 2026 ; le périmètre des moteurs s'était renversé trois fois en six jours
précisément parce qu'aucun enregistrement n'expliquait le renversement précédent. Chaque
enregistrement de ce registre porte maintenant son argument. L'histoire des moteurs est celle qui mérite d'être lue de bout en
bout — [0004](0004-sqlite-and-postgresql-only.md) → [0008](0008-postgresql-and-mysql.md) →
[0009](0009-four-engines.md) → [0014](0014-two-engines-and-a-test-fixture.md) — parce qu'elle se
termine à un moteur près de son point de départ, et que les enregistrements disent maintenant
pourquoi le retour fut le renversement coûteux, et donc celui qui devrait tenir.
