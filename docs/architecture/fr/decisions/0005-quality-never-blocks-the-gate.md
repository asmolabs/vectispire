# 0005 — Les règles de qualité et de revue IA ne bloquent jamais les portes de sécurité

**Date :** 2026-08-07 · **Statut :** accepté

## Contexte

Les constats de qualité de code (règles Semgrep non liées à la sécurité) et les revues IA génèrent des volumes importants qui doivent informer les développeurs sans bloquer inutilement les builds CI/CD.

## Décision

Les failles de qualité et résultats de revue IA sont suivis dans le backlog de Qualité mais **ne font jamais échouer la Porte de Sécurité (Policy Gate)**.
