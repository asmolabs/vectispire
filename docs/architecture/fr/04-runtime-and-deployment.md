# 04 — Exécution et déploiement

## Vue d'ensemble

Vectispire prend en charge aussi bien les déploiements autonomes en instance unique que les architectures distribuées multi-agents.

| Mode | Base de données | Emplacement des scanners | Déférent du socket Docker |
|---|---|---|---|
| Monolithique | SQLite intégré ou SGBD externe | Même processus | Plan de contrôle |
| Distribué (Agents) | PostgreSQL / MySQL / MariaDB | Agents distants | Agents distants |

## Leader Lease et Concurrence

Les tâches d'arrière-plan (planification des scans, purge de rétention, relais outbox) sont coordonnées via des baux de leadership enregistrés dans la table `t_leader_lease`, garantissant l'exécution par un unique nœud actif lors de la montée en charge.
