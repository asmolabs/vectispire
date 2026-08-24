# 0006 — Les règles Semgrep sont intégrées nativement et non redistribuées

**Date :** 2026-08-07 · **Statut :** accepté

## Contexte

Les contraintes de licence upstream interdisent la redistribution de jeux de règles propriétaires ou sous clauses restrictives.

## Décision

Vectispire embarque son propre jeu de règles natif, permet de spécifier un répertoire personnalisé via `VECTISPIRE_SEMGREP_RULES_DIR`, et garantit des scans autonomes et reproductibles hors-ligne.
