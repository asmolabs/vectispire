# Registre des Décisions d'Architecture (ADR) — Français

Ce répertoire répertorie l'ensemble des décisions structurelles d'architecture (ADR) de Vectispire.

| ADR | Titre | Statut |
|---|---|---|
| [0001](0001-pluggable-scan-layer.md) | Couche d'analyse extensible | remplacée par [0010](0010-one-scan-runner.md) |
| [0002](0002-the-database-carries-the-queue.md) | La base de données porte la file d'attente | acceptée |
| [0003](0003-long-polling-for-agents.md) | Long-polling pour la communication avec les agents distants | acceptée (amendée par [0031](0031-a-sealing-key-is-believed-only-on-the-pinned-key.md)) |
| [0004](0004-sqlite-and-postgresql-only.md) | Support initial de SQLite et PostgreSQL | remplacée par [0008](0008-postgresql-and-mysql.md) |
| [0005](0005-quality-never-blocks-the-gate.md) | Les règles de qualité de code ne bloquent jamais les gates | acceptée |
| [0006](0006-semgrep-rules-written-here.md) | Inclusion native des règles Semgrep dans l'application | acceptée |
| [0007](0007-none-is-not-an-empty-list.md) | L'absence d'analyse n'est pas une liste vide | acceptée |
| [0008](0008-postgresql-and-mysql.md) | Prise en charge combinée de PostgreSQL et MySQL | remplacée par [0009](0009-four-engines.md) |
| [0009](0009-four-engines.md) | Quatre moteurs de base de données, chacun mesuré | remplacée par [0014](0014-two-engines-and-a-test-fixture.md) |
| [0010](0010-one-scan-runner.md) | Exécuteur ScanRunner unique et concret | acceptée |
| [0011](0011-liquibase-rather-than-flyway.md) | Liquibase, avec le DDL structurel écrit à la main | remplacée par [0013](0013-flyway-multi-dialect-migrations.md) |
| [0012](0012-apache-2-0.md) | Licence Apache 2.0 | acceptée |
| [0013](0013-flyway-multi-dialect-migrations.md) | Migrations Flyway multi-dialectes nativement gérées | acceptée (amendée par [0027](0027-common-migrations-with-type-placeholders.md)) |
| [0014](0014-two-engines-and-a-test-fixture.md) | Deux moteurs déployables, et SQLite comme fixture de test | acceptée |
| [0015](0015-one-secrets-engine.md) | Un seul moteur de secrets | acceptée |
| [0016](0016-no-spdx-document.md) | CycloneDX est le SBOM généré ; SPDX n'est pas produit | acceptée |
| [0017](0017-custom-checks-as-container-images.md) | Checks personnalisés en images de conteneur émettant du SARIF, et SARIF seulement de sources internes déclarées | acceptée (amendée par [0032](0032-security-checklists.md)) |
| [0018](0018-the-docker-socket-is-never-mounted.md) | Le socket Docker n'est jamais monté dans le plan de contrôle | acceptée |
| [0019](0019-screen-text-is-translated-on-the-client.md) | Le serveur envoie un jeton ; l'écran détient la phrase | acceptée |
| [0020](0020-screenshots-stay-png.md) | Les captures restent en PNG, et le déclencheur qui changera cela est nommé | acceptée |
| [0021](0021-the-docs-site-stays-on-mkdocs-1.md) | Le site de documentation reste sur MkDocs 1, jusqu'à ce qu'un autre outil sache le publier en deux langues | acceptée |
| [0022](0022-https-clone-tokens-are-bound-to-a-host.md) | Le clonage HTTPS utilise un jeton géré, lié à un hôte | acceptée |
| [0023](0023-solutions-projects-and-repositories.md) | Une solution contient des projets, un projet référence des dépôts, et un droit peut viser un projet | acceptée |
| [0024](0024-integration-api-keys-act-for-an-account.md) | Une clé API d'intégration agit pour un compte, sur les routes qui l'acceptent | acceptée |
| [0025](0025-siem-events-leave-through-the-outbox.md) | Les événements SIEM partent par l'outbox, après validation, et leur catalogue est un contrat | acceptée |
| [0026](0026-services-are-grouped-by-domain.md) | Les services sont regroupés par domaine, et les domaines dépendent dans un seul sens | remplacée par [0030](0030-modulith-verifies-the-module-boundaries.md) |
| [0027](0027-common-migrations-with-type-placeholders.md) | Migrations communes avec des placeholders de type ; répertoires par moteur pour les divergences de structure | acceptée |
| [0028](0028-vertical-modules.md) | Les domaines deviennent des modules verticaux, et le socle est partagé | acceptée (achevée par la [0029](0029-core-domains-become-modules.md)) |
| [0029](0029-core-domains-become-modules.md) | Les domaines cœur deviennent des modules, et les paquetages par couche disparaissent | acceptée |
| [0030](0030-modulith-verifies-the-module-boundaries.md) | Spring Modulith vérifie les frontières des modules, et ArchUnit garde les couches | acceptée |
| [0031](0031-a-sealing-key-is-believed-only-on-the-pinned-key.md) | La clé de scellement d'un agent n'est crue que sur la parole de sa clé de signature épinglée | acceptée |
| [0032](0032-security-checklists.md) | Une checklist de sécurité est le modèle de l'organisation, versionné, rempli par projet par des personnes, et prérempli seulement à partir de preuves qui ont été produites | acceptée |
| [0033](0033-internal-reactions-leave-through-the-outbox.md) | Une réaction entre modules qui doit survivre à un commit passe par l'outbox, pas par le registre de Modulith | acceptée |
| [0034](0034-mysql-replaces-the-sqlite-fixture.md) | MySQL remplace SQLite comme fixture des suites unitaires et HTTP | acceptée, réalisée |
| [0035](0035-report-plugins.md) | Un plugin de rapport est une image de conteneur signée qui transforme un export de projet en un document, que la plateforme vérifie, signe et conserve avec sa provenance | acceptée |
| [0036](0036-the-posture-score-formula.md) | Le score de posture baisse d'une part par problème, une licence pèse comme un haut, un problème exploité plafonne à D, une portée est notée par sa cible la plus faible, le portefeuille par sa répartition, et les points de risque sont affichés | acceptée |
| [0037](0037-discovering-repositories-at-setup.md) | Les dépôts sont découverts par une connexion de forge en lecture seule, choisis par une personne, et importés comme des cibles ordinaires | acceptée |
| [0038](0038-deploying-on-kubernetes.md) | Sur Kubernetes, le plan de contrôle tourne sans point d'accès aux conteneurs, les scans tournent sur des agents dotés de leur propre démon Docker, la base est externe, et les plugins de rapport attendent un exécuteur capable de joindre un démon distant | acceptée |
| [0039](0039-a-build-sbom-completes-the-scanners-inventory.md) | Le SBOM d'un build complète l'inventaire du scanner : l'union, la version déclarée par le build l'emporte, le plus récent pour chaque scan suivant | proposée |
| [0040](0040-integrations-are-switched-on-not-installed.md) | Une intégration s'active, elle ne s'installe pas : les forges, les transports SIEM, les fournisseurs d'IA, les canaux de notification et les trackers que le gouverneur active | acceptée |
| [0041](0041-will-not-fix-is-not-not-affected.md) | « Ne sera pas corrigé » n'est pas « non affecté » : un risque accepté reste exposé dans le VEX, et chaque format lit le même triage | acceptée |
| [0042](0042-a-report-document-is-read-by-who-sees-what-it-carried.md) | Un document de rapport est lu par qui voit ce qu'il contient, pas seulement par qui voit le projet aujourd'hui | acceptée |

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
