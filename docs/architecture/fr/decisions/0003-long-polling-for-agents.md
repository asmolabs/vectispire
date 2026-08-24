# 0003 — Les agents communiquent en HTTP long-polling, jamais directement avec la base de données

**Date :** 2026-08-06 · **Statut :** accepté

## Contexte

L'exécution des scans sur des machines distantes (agents) exigeait un protocole de communication sécurisé n'exposant ni les identifiants de la base de données ni la clé de déchiffrement globale.

## Décision

Les agents utilisent l'API HTTP via un appel long-polling (`GET /api/v1/agents/jobs?wait=30`). L'agent ne se connecte jamais directement au SGBD et ne possède pas la variable `ENCRYPTION_KEY`.
