# Dossier d'Architecture — 02. Vue Sécurité

* **Projet :** Vectispire — ASPM & Control Plane de Sécurité
* **Modèle :** `bflorat/modele-da` — Modèle de Dossier d'Architecture (Bertrand Florat)
* **Statut :** Validé · **Version :** 1.0

---

## 1. Exigences Non Fonctionnelles de Sécurité (ENF)

1. **Confidentialité des Données au Repos** : Chiffrement systématique des secrets d'intégration et clés SSH privées.
2. **Isolation Étanche du Code Scanné** : Aucun risque d'exfiltration de code source par les conteneurs d'analyse.
3. **Infalsificabilité du Journal d'Audit** : Impossibilité d'altérer les traces d'actions d'administration et de qualification VEX.
4. **Moindre Privilège des Agents Distants** : Interdiction totale d'accès direct à la base de données SQL par les agents.

---

## 2. Authentification, Sécurité des Sessions & RBAC

### 2.1 Hachage des Mots de Passe & Clés API
- **Mots de passe utilisateurs** : Hachés avec l'algorithme fort **Argon2id** (protection contre les attaques GPU).
- **Protection contre le Brute-Force** : Suivi et blocage automatique des tentatives infructueuses via `t_login_attempt`.
- **Clés API d'intégration CI/CD** : Stockées uniquement sous forme de hash Argon2id (préfixées `vectispire_`) avec périmètres de droits (scopes) et date d'expiration.

### 2.2 Contrôle d'Accès basé sur les Rôles (RBAC)
L'application applique un contrôle strict sur tous les endpoints REST via Spring Security `@PreAuthorize` :
- `ROLE_ADMIN` : Gestion des utilisateurs, clés SSH, politiques de Gate et configuration système.
- `ROLE_USER` / `ROLE_ANALYST` : Consultation du posture dashboard, qualification VEX des vulnérabilités.
- `ROLE_CI` : Exécution exclusive des requêtes de Gate (`POST /api/v1/gate`).

---

## 3. Protection des Données au Repos & Chiffrement

### 3.1 Chiffrement AES-256-GCM (`EncryptionService`)
Toutes les clés SSH privées de déploiement (`t_ssh_key`) et jetons d'intégration sont chiffrés avec **AES-256-GCM** avec authentification de données associées (AEAD). La clé maître provient de la variable d'environnement `ENCRYPTION_KEY`.

### 3.2 Purge et Rétention des Secrets
1. **Rapports bruts de scanners** : Les payloads bruts JSON conservés temporairement dans `scan.cves` sont purgés automatiquement par le service de rétention (`RetentionService`).
2. **Stockage minimal des constats** : Les entités `Finding` et `Issue` enregistrent **uniquement l'emplacement (fichier, ligne) et le type de règle**, et ne stockent **jamais la valeur du secret en clair**.

---

## 4. Isolation des Conteneurs d'Analyse

Tous les conteneurs d'analyse exécutés par `ContainerRunner` sont durcis pour empêcher tout échappement ou exfiltration :

| Mesure de Sécurité | Implémentation | Objectif de Confinement |
|---|---|---|
| **Suppression des privilèges** | `cap_drop: ALL`, `no-new-privileges` | Empêcher toute élévation de privilège root dans le conteneur. |
| **Montage en Lecture Seule** | Volume source monté en `read-only` | Garantir que l'analyseur ne modifie jamais le code source. |
| **Isolation Réseau** | **`network: none`** (Secrets, SAST, IaC) | Empêcher toute exfiltration de code source vers l'extérieur. |
| **Socket Docker** | **Aucun accès au socket Docker** | Interdire la prise de contrôle du démon Docker de l'hôte. |

---

## 5. Infalsificabilité de l'Audit Log (Scellement Cryptographique)

La table `t_audit_log` conserve l'historique de toutes les actions d'administration et de triage VEX. Chaque entrée intègre un hash SHA-256 calculé à partir de la ligne courante et du hash de la ligne précédente :

```
Hash_N = SHA256( Id_N + Action_N + User_N + Timestamp_N + Hash_N-1 )
```

La méthode `AuditLogService.verifyIntegrity()` vérifie automatiquement l'intégralité de la chaîne et détecte la moindre altération ou suppression SQL.

---

## 6. Analyse de Menaces STRIDE

La modélisation complète des menaces selon la méthode **STRIDE par Entité DFD** est documentée séparément dans [`STRIDE_THREAT_MODEL.fr.md`](../../security/fr/STRIDE_THREAT_MODEL.fr.md).
