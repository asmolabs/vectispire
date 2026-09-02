# Dossier d'Architecture — 03. Vue Dimensionnement & Performances

* **Projet :** Vectispire — ASPM & Control Plane de Sécurité
* **Modèle :** `bflorat/modele-da` — Modèle de Dossier d'Architecture (Bertrand Florat)
* **Statut :** Validé · **Version :** 1.3 (2026-08-25 — le quota CPU existe désormais)

---

## 1. Exigences Non Fonctionnelles (ENF) de Performance

1. **Temps de Réponse Quality Gate (`POST /api/v1/gate`)** : $< 300\text{ ms}$. La règle
   elle-même — `PolicyGate.evaluate` — est une fonction pure, en mémoire, des anomalies qu'on lui
   passe, et **les obtenir coûte désormais une lecture indexée du backlog ouvert de cette seule
   cible**. Jusqu'au 25 août 2026 la requête lisait *toutes* les anomalies ouvertes du parc et
   jetait tout sauf une cible, sur le point d'entrée appelé par chaque pipeline à chaque build : le
   coût suivait le parc et non la cible. Les deux moitiés ont été réparées ensemble, car une
   requête par cible contre une colonne `state` non indexée n'aurait fait que déplacer le
   balayage.
2. **Capacité d'Ingestion des Scans** : Traitement asynchrone des analyses en tâche d'arrière-plan
   sans bloquer l'API.
3. **Mise à l'Échelle Horizontale** : Sans conflit sur plusieurs instances, par deux mécanismes
   distincts — le **planificateur** d'analyses détient un bail dans `t_leader_lease` parce qu'il
   *crée* du travail, et le **worker** n'en a pas besoin car réclamer une ligne en file est
   lui-même le contrôle de concurrence. Voir §3.
4. **Stabilité des Ressources Docker** : Quotas de mémoire, de nombre de processus **et de CPU**
   imposés sur chaque conteneur de scan. La part CPU était annoncée ici depuis des semaines sans
   qu'aucun code ne l'applique ; elle existe depuis le 25 août 2026 et `ContainerHardeningTest`
   vérifie chacun de ces drapeaux sur la requête remise au démon.

---

## 2. Volumétrie & Dimensionnement de la Base de Données

| Entité / Table | Estimation Volumétrique (100 Cibles, 10 000 Scans) | Stratégie de Gestion & Optimisation |
|---|---|---|
| **`t_scan` (Historique scans)** | ~ 100 000 lignes / an | Nettoyage des métadonnées de scans obsolètes via `RetentionService`. Ajoutés le 2026-09-02 : `(repo_id, id)` et `(container_id, id)`, parce que « le dernier scan par cible » est une sous-requête corrélée — sans index sur `repo_id`, la liste des dépôts était quadratique en nombre de scans. |
| **`t_finding` (Constats bruts)** | ~ 500 000 lignes | Transitoire, purgé périodiquement par la tâche de rétention. Ajoutés le 2026-09-02 : `(scan_id)`, `(package_name)` et `(issue_id)`. **La plus grande table du schéma ne portait rien d'autre que sa clé primaire** — `scan_id` était déclaré par un `references` en ligne, forme qui ne crée d'index sur aucun des trois moteurs. |
| **`t_issue` (Backlog réconcilié)** | ~ 10 000 à 50 000 anomalies uniques | `(state, repo_id)` et `(state, container_id)` pour le gate et le sommaire de conformité, `(fingerprint)` pour la recherche d'identité par finding à l'ingestion, et `(identifier)` depuis le 2026-09-02 parce que le générateur CycloneDX et l'ingesteur VEX cherchent par CVE dans une boucle. Ajoutés le 2026-08-25 : cette table ne portait **aucun index** alors que ce document en annonçait trois, et `SchemaParityIntegrationTest` vérifie désormais leur existence sur chaque moteur, si bien qu'un refactoring ne peut plus les faire disparaître en silence. |
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
- **Quota CPU** : **tous les cœurs sauf un**, avec un plancher à un. Pas un nombre fixe, car un
  nombre fixe est faux à la fois sur une VM à deux cœurs et sur un serveur de build à
  soixante-quatre, et parce que le préjudice n'est pas qu'un scanner travaille dur — semgrep et
  grype sont limités par le CPU, et les affamer transforme une analyse de cinq minutes en timeout,
  soit un déni de service livré par la défense. Le préjudice est qu'un dépôt que personne ne
  contrôle prenne le *dernier* cœur et laisse le plan de contrôle incapable de répondre à un appel
  du gate pendant quinze minutes. Laisser un cœur est ce qui sépare les deux.

  Cette entrée annonçait `2.0 vCPUs` depuis des semaines sans qu'aucune limite CPU ne soit
  appliquée. Elle l'est désormais, et elle est vérifiée : rien n'avait jamais contrôlé aucun de ces
  drapeaux, ce qui est la façon dont un contrôle reste documenté et absent en même temps.

  **Le compte de cœurs est celui du démon, et pas celui de la JVM** (2026-09-02). La limite était
  calculée depuis `availableProcessors()`, qui compte les cœurs de la machine portant le plan de
  contrôle — alors que le conteneur s'exécute sur la machine portant le démon. Les deux diffèrent
  dès que Docker Desktop est interposé, que `DOCKER_HOST` pointe ailleurs, ou que le plan de
  contrôle est lui-même conteneurisé avec son propre quota. Ce n'est pas une erreur conservatrice :
  Docker n'arrondit pas vers le bas, il refuse la création avec *« Range of CPUs is from 0.01 to
  N »* et plus aucun scan ne démarre. `ContainerRunner` interroge maintenant `docker info` et borne
  le quota à tous les cœurs du démon sauf un. Dimensionnez donc la **VM du démon**, pas l'hôte.
