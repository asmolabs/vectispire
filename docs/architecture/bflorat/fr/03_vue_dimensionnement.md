# Dossier d'Architecture — 03. Vue Dimensionnement & Performances

* **Projet :** Vectispire — ASPM & Control Plane de Sécurité
* **Modèle :** `bflorat/modele-da` — Modèle de Dossier d'Architecture (Bertrand Florat)
* **Statut :** Validé · **Version :** 1.0

---

## 1. Exigences Non Fonctionnelles (ENF) de Performance

1. **Temps de Réponse Quality Gate (`POST /api/v1/gate`)** : $< 300\text{ ms}$ (évaluation
   déterministe en mémoire).
2. **Capacité d'Ingestion des Scans** : Traitement asynchrone des analyses en tâche d'arrière-plan
   sans bloquer l'API.
3. **Mise à l'Échelle Horizontale** : Coordination sans conflit sur plusieurs instances grâce aux
   baux de leadership (`t_leader_lease`).
4. **Stabilité Mémoire du Démon Docker** : Quotas de mémoire et CPU imposés sur chaque conteneur
   pour prévenir l'épuisement hôte.

---

## 2. Volumétrie & Dimensionnement de la Base de Données

| Entité / Table | Estimation Volumétrique (100 Cibles, 10 000 Scans) | Stratégie de Gestion & Optimisation |
|---|---|---|
| **`t_scan` (Historique scans)** | ~ 100 000 lignes / an | Nettoyage des métadonnées de scans obsolètes via `RetentionService`. |
| **`t_finding` (Constats bruts)** | ~ 500 000 lignes | Transitoire, purgé périodiquement par la tâche de rétention. |
| **`t_issue` (Backlog réconcilié)** | ~ 10 000 à 50 000 issues uniques | Indexation sur `target_id`, `status`, `fingerprint` pour accès rapides. |
| **`t_audit_log` (Journal scellé)** | ~ 50 000 entrées d'audit / an | Immuable, stockage d'empreintes SHA-256 compactes. |

---

## 3. Coordination d'Échelle & Baux de Leadership (`t_leader_lease`)

En environnement distribué multi-instances, la coordination des tâches d'arrière-plan (planification
des scans cron, purge de rétention, relais outbox) est régie par la table `t_leader_lease` :

```sql
SELECT * FROM t_leader_lease WHERE lease_name = 'SCHEDULER' AND expires_at > NOW() FOR UPDATE;
```

- **Garantie** : Un seul nœud actif (*Leader*) exécute la tâche à un instant donné.
- **Failover** : Si le nœud leader ne renouvelle pas son bail dans l'intervalle imparti, le bail
  expire et un autre nœud reprend la main automatiquement.

---

## 4. Quotas de Ressources & Contraintes Mémoire (JVM / Docker)

### 4.1 Dimensionnement JVM (Spring Boot Control Plane)
- **Heap RAM recommandé** : `2 GB` à `4 GB` (`-Xms1024m -Xmx4096m`).
- **Garbage Collector** : G1GC adapté au JDK 25 avec pause faible latence.

### 4.2 Resource Caps par Conteneur de Scan (`ContainerRunner`)
Chaque conteneur exécuté est contraint pour éviter l'épuisement mémoire de la machine hôte :
- **Mémoire maximale par conteneur** : `1.5 GB` RAM.
- **Quota CPU** : `2.0 vCPUs`.
- **Timeout d'exécution maximal** : `10 minutes` par scanner. Un dépassement entraîne la destruction
  forcée du conteneur.
