# Registre des Décisions d'Architecture (ADR) — Français

Ce répertoire répertorie l'ensemble des décisions structurelles d'architecture (ADR) de Vectispire.

| ADR | Titre |
|---|---|
| [0001](0001-pluggable-scan-layer.md) | Couche d'analyse extensible |
| [0002](0002-the-database-carries-the-queue.md) | La base de données porte la file d'attente |
| [0003](0003-long-polling-for-agents.md) | Long-polling pour la communication avec les agents distants |
| [0004](0004-sqlite-and-postgresql-only.md) | Support initial de SQLite et PostgreSQL |
| [0005](0005-quality-never-blocks-the-gate.md) | Les règles de qualité de code ne bloquent jamais les gates |
| [0006](0006-semgrep-rules-written-here.md) | Inclusion native des règles Semgrep dans l'application |
| [0007](0007-none-is-not-an-empty-list.md) | L'absence d'analyse n'est pas une liste vide |
| [0008](0008-postgresql-and-mysql.md) | Prise en charge combinée de PostgreSQL et MySQL |
| [0009](0009-four-engines.md) | Validation sur les 2 moteurs de bases de données |
| [0010](0010-one-scan-runner.md) | Exécuteur ScanRunner unique et concret |
| [0011](0011-liquibase-rather-than-flyway.md) | Choix de Flyway au lieu de Liquibase |
| [0012](0012-apache-2-0.md) | Licence Apache 2.0 |
| [0013](0013-flyway-multi-dialect-migrations.md) | Migrations Flyway multi-dialectes nativement gérées |
| [0014](0014-two-engines-and-a-test-fixture.md) | Deux moteurs déployables, et SQLite comme fixture de test |
| [0015](0015-one-secrets-engine.md) | Un seul moteur de secrets |
