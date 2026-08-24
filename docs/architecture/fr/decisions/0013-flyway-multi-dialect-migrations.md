# 0013 — Migrations Flyway natives multi-dialectes

**Date :** 2026-08-22 · **Statut :** accepté · **Remplace :** [0011](0011-liquibase-rather-than-flyway.md)

## Contexte & Décision

Adoption de Flyway avec migrations SQL natives par dialecte (`src/main/resources/db/migration/{vendor}/`) pour PostgreSQL, MySQL, MariaDB et SQLite afin de maîtriser parfaitement le DDL et d'assurer la parité de schéma.
