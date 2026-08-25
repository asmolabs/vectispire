# Dossier d'Architecture — 04. Vue Infrastructure & Déploiement

* **Projet :** Vectispire — ASPM & Control Plane de Sécurité
* **Modèle :** `bflorat/modele-da` — Modèle de Dossier d'Architecture (Bertrand Florat)
* **Statut :** Validé · **Version :** 1.1 (2026-08-25 — périmètre des moteurs réconcilié avec l'ADR 0014)

---

## 1. Topologie de Déploiement & Architecture Physique

Vectispire prend en charge deux topologies de déploiement complémentaires :

```mermaid
flowchart TB
    subgraph Mono["Mode Monolithique (Instance Unique)"]
        Ctrl1["Plan de Contrôle (Spring Boot + UI)"]
        Docker1["Démon Docker Local"]
        DB1[("PostgreSQL ou MySQL")]
        Ctrl1 --> Docker1
        Ctrl1 --> DB1
    end

    subgraph Dist["Mode Distribué Multi-Agents"]
        Ctrl2["Plan de Contrôle Clusterisé (PostgreSQL / MySQL)"]
        DB2[("SGBD d'Entreprise (PostgreSQL / MySQL)")]
        AgentA["Agent Distant Site A"]
        AgentB["Agent Distant Site B"]
        
        Ctrl2 --> DB2
        AgentA -.->|"HTTP Long-Polling (/api/v1/agent/jobs)"| Ctrl2
        AgentB -.->|"HTTP Long-Polling (/api/v1/agent/jobs)"| Ctrl2
    end
```

---

## 2. Matrice de Compatibilité SGBD & Migrations Flyway

**Deux moteurs sont déployables. Un troisième est une fixture de test et ne peut pas être déployé
du tout** — voir l'[ADR 0014](../../fr/decisions/0014-two-engines-and-a-test-fixture.md), qui a
corrigé un périmètre supporté qui en annonçait quatre. Les migrations sont du SQL natif par
dialecte sous `src/main/resources/db/migration/{vendor}/`, gérées par **Flyway** ([ADR
0013](../../fr/decisions/0013-flyway-multi-dialect-migrations.md)) :

| Moteur de SGBD | Version Min. Supportée | Dialecte Flyway | Usage Cible |
|---|---|---|---|
| **PostgreSQL** | 14+ | `postgresql` | Production recommandée (Cluster d'Entreprise) |
| **MySQL** | 8.0+ | `mysql` | Production alternative (Environnements Cloud / RDS) |
| **SQLite** | 3.35+ | `sqlite` | **Non déployable.** La fixture sur laquelle tourne la suite de tests HTTP : sous le `ddl-auto: validate` livré, l'application refuse de démarrer, car les affinités de type de SQLite renvoient une colonne d'horodatage comme un FLOAT. Ses migrations sont maintenues pour la seule suite. |

### 2.1 Intégrité du Schéma & `ddl-auto`
Le paramètre Hibernate `ddl-auto` est obligatoirement maintenu à `validate`. Seul Flyway détient
l'autorité sur le schéma DDL pour prévenir toute divergence ou perte silencieuse de données.

---

## 3. Interaction avec le Démon Docker & Confinement

1. **Montage du Socket Docker (`/var/run/docker.sock`)** : Seul le plan de contrôle (ou le processus
   agent) communique avec le démon Docker via le socket hôte.
2. **Conteneurs d'Analyse Éphémères** : `ContainerRunner` instancie des conteneurs isolés qui
   s'arrêtent et se détruisent immédiatement après le traitement.

---

## 4. Architecture des Agents Distants (`vectispire-agent`)

L'agent distant permet de déporter le scan au plus près des réseaux d'entreprise isolés :

- **Canal Réseau** : Communication unidirectionnelle sortante via HTTP Long-Polling (`GET
  /api/v1/agent/jobs?wait=<secondes>` ; `wait` vaut 0 par défaut, un agent qui l'omet reçoit donc
  une réponse immédiate plutôt qu'une connexion maintenue).
- **Aucune dépendance DB** : `vectispire-agent` ne possède aucun composant JDBC sur son classpath.
- **Sécurité des clés** : L'agent ne détient jamais la clé maître `ENCRYPTION_KEY` ([ADR
  0003](../../fr/decisions/0003-long-polling-for-agents.md)).
