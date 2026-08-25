# Dossier d'Architecture — 03. Vue Dimensionnement & Performances

* **Projet :** Vectispire — ASPM & Control Plane de Sécurité
* **Modèle :** `bflorat/modele-da` — Modèle de Dossier d'Architecture (Bertrand Florat)
* **Statut :** Validé · **Version :** 1.1 (2026-08-25 — chiffres vérifiés contre le code)

---

## 1. Exigences Non Fonctionnelles (ENF) de Performance

1. **Temps de Réponse Quality Gate (`POST /api/v1/gate`)** : $< 300\text{ ms}$. La règle
   elle-même — `PolicyGate.evaluate` — est une fonction pure, en mémoire, des anomalies qu'on lui
   passe. **Les obtenir ne l'est pas** : la requête lit d'abord les politiques actives, puis
   *toutes* les anomalies ouvertes du parc, en conserve la part d'une seule cible et jette le
   reste. La cible de latence tient donc sur un backlog réduit et se dégrade avec la taille du parc
   entier plutôt qu'avec celle de la cible. Consigné ici comme une limite connue plutôt que passé
   sous silence, car ce point d'entrée est appelé par chaque pipeline à chaque build.
2. **Capacité d'Ingestion des Scans** : Traitement asynchrone des analyses en tâche d'arrière-plan
   sans bloquer l'API.
3. **Mise à l'Échelle Horizontale** : Sans conflit sur plusieurs instances, par deux mécanismes
   distincts — le **planificateur** d'analyses détient un bail dans `t_leader_lease` parce qu'il
   *crée* du travail, et le **worker** n'en a pas besoin car réclamer une ligne en file est
   lui-même le contrôle de concurrence. Voir §3.
4. **Stabilité Mémoire du Démon Docker** : Quotas de **mémoire et de nombre de processus** imposés
   sur chaque conteneur. **Aucun quota CPU n'est appliqué** — voir §4.2, où le manque est énoncé
   plutôt que masqué.

---

## 2. Volumétrie & Dimensionnement de la Base de Données

| Entité / Table | Estimation Volumétrique (100 Cibles, 10 000 Scans) | Stratégie de Gestion & Optimisation |
|---|---|---|
| **`t_scan` (Historique scans)** | ~ 100 000 lignes / an | Nettoyage des métadonnées de scans obsolètes via `RetentionService`. |
| **`t_finding` (Constats bruts)** | ~ 500 000 lignes | Transitoire, purgé périodiquement par la tâche de rétention. |
| **`t_issue` (Backlog réconcilié)** | ~ 10 000 à 50 000 anomalies uniques | **Aucun index au-delà de la clé primaire.** Le schéma déclare neuf index et aucun ne porte sur cette table, alors que `state` et `fingerprint` sont lus à chaque appel du gate et à chaque ingestion. Énoncé parce qu'une estimation volumétrique ne vaut rien à côté d'une stratégie d'accès qui n'existe pas. |
| **`t_audit_log` (Journal scellé)** | ~ 50 000 entrées d'audit / an | Immuable, stockage d'empreintes SHA-256 compactes. |

---

## 3. Coordination d'Échelle & Baux de Leadership (`t_leader_lease`)

**Une seule tâche prend un bail, pas toutes.** Quatre tâches périodiques tournent dans chaque
instance : le worker d'analyse (15 s), le planificateur (60 s), le relais de notifications (60 s)
et la maintenance horaire. Seul le **planificateur** est élu, parce qu'il est le seul à créer du
travail — deux instances décidant indépendamment qu'une analyse nocturne est due la mettraient deux
fois en file. Le relais et la passe de maintenance sont idempotents, et le worker réclame des
lignes.

**Le mécanisme est un compare-and-swap, pas un verrou de ligne.** Aucun `SELECT … FOR UPDATE`
n'est jamais émis ; l'acquisition est un `UPDATE` conditionnel qui ne réussit que pour une
instance :

```sql
update t_leader_lease
   set holder = :holder, expires_at = :expiresAt, acquired_at = :at, updated_at = :at
 where name = 'scheduler' and holder = :previousHolder and expires_at = :previousExpiry;
```

- **Garantie** : l'update ne touche aucune ligne pour toutes les instances sauf une, donc
  exactement une devient leader — sans tenir de verrou pendant toute la passe, ce que ferait un
  `FOR UPDATE` et qui transformerait une ronde de planification lente en blocage partout ailleurs.
- **Failover** : un leader qui cesse de renouveler laisse son bail expirer, et la première instance
  à retenter l'échange trouve la ligne expirée et reprend la main.

---

## 4. Quotas de Ressources & Contraintes Mémoire (JVM / Docker)

### 4.1 Dimensionnement JVM (Spring Boot Control Plane)
- **Heap RAM recommandé** : `2 GB` à `4 GB` (`-Xms1024m -Xmx4096m`).
- **Garbage Collector** : G1GC adapté au JDK 25 avec pause faible latence.

### 4.2 Resource Caps par Conteneur de Scan (`ContainerRunner`)
Chaque conteneur exécuté est contraint pour éviter l'épuisement mémoire de la machine hôte :
- **Mémoire maximale par conteneur** : `2 GB` (`ScannerLimits.DEFAULT`). Un conteneur qui la
  dépasse meurt ; l'hôte non.
- **Nombre maximal de processus** : `512` PID. C'est ce qui transforme une fork bomb en conteneur
  mort, et c'est le plafond que ce document omettait.
- **Timeout d'exécution maximal** : `15 minutes` par scanner. Un dépassement entraîne la
  destruction forcée du conteneur.
- **Quota CPU** : **aucun n'est appliqué.** `ContainerRunner` pose la mémoire, les PID et un
  timeout, et aucune limite CPU d'aucune sorte. Un scanner peut donc saturer tous les cœurs pendant
  toute la durée de son timeout. Le timeout borne la durée ; rien ne borne la consommation. Laissé
  comme un manque énoncé plutôt que taire — le texte précédent annonçait `2.0 vCPUs`, qu'aucun code
  n'imposait.
