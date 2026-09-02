# Dossier d'Architecture — 02. Vue Sécurité

* **Projet :** Vectispire — ASPM & Control Plane de Sécurité
* **Modèle :** `bflorat/modele-da` — Modèle de Dossier d'Architecture (Bertrand Florat)
* **Statut :** Validé · **Version :** 1.0

---

## 1. Exigences Non Fonctionnelles de Sécurité (ENF)

1. **Confidentialité des Données au Repos** : Chiffrement systématique des secrets d'intégration et
   clés SSH privées.
2. **Isolation Étanche du Code Scanné** : Aucun risque d'exfiltration de code source par les
   conteneurs d'analyse.
3. **Infalsificabilité du Journal d'Audit** : Impossibilité d'altérer les traces d'actions
   d'administration et de qualification VEX.
4. **Moindre Privilège des Agents Distants** : Les agents distants ne peuvent pas atteindre la base
   SQL — imposé par le graphe de modules, la violation échoue donc à la compilation — et ne
   détiennent jamais l'`ENCRYPTION_KEY`. Ils reçoivent *bien* des clés de déploiement de dépôt en
   mode `DELEGATED`, scellées vers la clé publique que l'agent a annoncée à l'enrôlement (X25519 →
   HKDF → AES-256-GCM) et auditées à chaque envoi ; `LOCAL`, le défaut, n'envoie rien. Énoncé en
   entier plutôt qu'en « les agents ne détiennent aucun identifiant », qui est l'affirmation la plus
   courte et la fausse — voir la [décision
   0003](../../fr/decisions/0003-long-polling-for-agents.md).

---

## 2. Authentification, Sécurité des Sessions & RBAC

### 2.1 Hachage des Mots de Passe & Protection Anti-Brute-Force
- **Mots de passe utilisateurs** : Hachés avec l'algorithme fort **Argon2id** (protection contre les
  attaques GPU).
- **Rate-Limiting Dynamique en Mémoire (`Bucket4j`)** : Filtre HTTP `LoginRateLimitFilter` sur
  **les trois points d'entrée qui présentent des identifiants** — `POST /api/v1/auth/login`,
  `/api/v1/auth/mfa/verify` et `/api/v1/auth/session/exchange` — évaluant le quota d'IP (Bucket4j:
  10 jetons par minute). La portée est de trois points d'entrée et non d'un seul parce qu'un
  limiteur qui ne garde que l'étape du mot de passe laisse le second facteur ouvert à un nombre
  illimité de tentatives, et c'est la plus intéressante des deux cibles.
- **Confiance dans l'adresse du client** : `X-Forwarded-For` n'est honoré que depuis les adresses
  listées dans `VECTISPIRE_TRUSTED_PROXIES`, vide par défaut. Faire confiance à l'en-tête sans
  condition laisse un appelant choisir son propre seau — soit un limiteur qui ne limite personne.
  Bloque les attaques
  par déni de service et bursts d'essais bruts avec HTTP `429 Too Many Requests` et en-tête
  `Retry-After` **sans effectuer de requête SQL ni de dérivation de hash Argon2id**.
- **Protection Brute-Force Persistante (`t_login_attempt`)** : Suivi des échecs de connexion par
  compte utilisateur et par identifiant client dans la base de données via `LoginThrottle`.
- **Clés API d'intégration CI/CD** : Stockées uniquement sous forme de hash Argon2id (préfixées
  `vectispire_`) avec périmètres de droits (scopes) et date d'expiration.

### 2.2 Contrôle d'Accès basé sur les Rôles (RBAC) & Double Validation
L'application applique un contrôle strict sur tous les endpoints REST via Spring Security :
- `ROLE_ADMIN` / `ROLE_SUPERUSER` / `ROLE_CISO` : Gestion de la configuration système, des
  utilisateurs, des clés SSH et basculement de la **Double Validation (Four-Eyes Approval)**
  (`triage_four_eyes_required`).
- **Double Validation Optionnelle** : Configurable dynamiquement via l'UI par un Admin ou CISO (`PUT
  /api/v1/settings`). Lorsqu'elle est activée, toute décision VEX de type `NOT_AFFECTED` ou `FIXED`
  émise par un utilisateur non-CISO/Admin passe en état `PENDING_APPROVAL`. Lorsqu'elle est
  désactivée, tout utilisateur autorisé peut triager directement.
- **Identités Distinctes Imposées** : L'approbateur est comparé au demandeur enregistré sur
  l'événement `PENDING_APPROVAL`, et non au seul rôle d'approbation. Un compte qui demande une
  dérogation ne peut pas l'approuver, même après avoir obtenu le rôle — quatre yeux signifie deux
  personnes, et une simple barrière de rôle laisse une seule personne tenir les deux moitiés.
- **Audit des Modifications** : Tout changement de l'option de double validation est immédiatement
  consigné dans le journal d'audit scellé SHA-256 (`t_audit_log`) avec l'identifiant de l'opérateur
  (`SETTING_UPDATED`).
- `ROLE_USER` / `ROLE_SECURITY_CHAMPION` : Consultation du posture dashboard et qualification des
  vulnérabilités. Le référent sécurité peut approuver un triage, mais dans le seul périmètre que sa
  visibilité lui donne — il n'a pas de portée globale.
- `ROLE_AUDITOR` (2026-09-02) : **lit la gouvernance et n'en écrit rien.** Portée globale, aucune
  approbation, aucune écriture nulle part. Le rôle existe parce que jusqu'à cette date la lecture
  du journal d'audit, des preuves de conformité, de la politique de barrière et de la destination
  SIEM demandait le même marqueur que leur écriture : le seul compte capable d'inspecter la posture
  était un compte capable de la réécrire. Qui vérifie le travail ne devrait pas pouvoir le changer
  d'abord.

  **Le rôle a menti pendant une journée, et cela vaut d'être consigné.** Il a été livré le
  1er septembre avec cette phrase dans sa documentation, alors que six routes d'écriture ne
  portaient que `@RequiresAccount` : un auditeur pouvait régler une anomalie, ouvrir un ticket
  chez un client, et envoyer la liste des constats d'une cible vers un hôte de modèle. Refermé le
  2 septembre par `@RequiresWriteAccount`, après avoir énuméré toutes les routes non-GET qu'un
  simple compte connecté atteint — et non les seules qu'on soupçonnait.

**Lire la gouvernance et l'écrire sont deux marqueurs distincts** (2026-09-02). Ils portaient le
même nom, posé au niveau classe sur huit contrôleurs, ce qui confondait consulter et modifier.

| Marqueur | Rôles | Ce qu'il ouvre |
|---|---|---|
| `@RequiresAdministrator` | SUPERUSER, ADMIN | Comptes, équipes, clés, agents, réglages |
| `@RequiresSecurityLead` | SUPERUSER, ADMIN, CISO | **Écriture** : politique de barrière, jeux de règles, destination SIEM, politique de licences |
| `@RequiresGovernanceRead` | + AUDITOR | **Lecture** : journal d'audit, preuves de conformité, barrières, jeux de règles, config SIEM |
| `@RequiresPlatformGovernor` | SUPERUSER seul | **Les règles** : qui voit quelles cibles (`target_visibility`), et faut-il deux personnes pour écarter une vulnérabilité (`triage_four_eyes_required`) |
| `@RequiresWriteAccount` | tous sauf AUDITOR et SUPERUSER | **Agir** : trier une anomalie, ouvrir un ticket, lancer une revue OWASP ou une explication par modèle |
| `@RequiresAccount` | tout compte connecté | Le reste, restreint ensuite par la visibilité |

Ces trois listes de rôles ne sont pas recopiées : `RouteAuthorizationTest` vérifie que chaque
expression correspond exactement au drapeau de `Role` qui la définit, et refuse toute route qui
écrirait sa propre liste au lieu de porter un marqueur.

Le gate (`POST /api/v1/gate`) ne demande **aucun rôle particulier** : il porte `@RequiresAccount`
et s'appelle en pratique avec une clé API, dont les scopes sont un axe d'autorisation séparé. Ce
document annonçait un `ROLE_CI` qui n'a jamais existé.

---

## 3. Protection des Données au Repos & Chiffrement

### 3.1 Chiffrement AES-256-GCM (`EncryptionService`)
Toutes les clés SSH privées de déploiement (`t_ssh_key`) et jetons d'intégration sont chiffrés avec
**AES-256-GCM** avec authentification de données associées (AEAD). La clé maître provient de la
variable d'environnement `ENCRYPTION_KEY`.

### 3.2 Purge et Rétention des Secrets
1. **Rapports bruts de scanners** : Les payloads bruts JSON conservés temporairement dans
   `scan.cves` sont purgés automatiquement par le service de rétention (`RetentionService`).
2. **Stockage minimal des constats** : Les entités `Finding` et `Issue` enregistrent **uniquement
   l'emplacement (fichier, ligne) et le type de règle**, et ne stockent **jamais la valeur du secret
   en clair**.

---

## 4. Isolation des Conteneurs d'Analyse

Tous les conteneurs d'analyse exécutés par `ContainerRunner` sont durcis pour empêcher tout
échappement ou exfiltration :

| Mesure de Sécurité | Implémentation | Objectif de Confinement |
|---|---|---|
| **Suppression des privilèges** | `cap_drop: ALL`, `no-new-privileges` | Empêcher toute élévation de privilège root dans le conteneur. |
| **Montage en Lecture Seule** | Volume source monté en `read-only` | Garantir que l'analyseur ne modifie jamais le code source. |
| **Isolation Réseau** | **`network: none`** (Secrets, SAST, IaC) | Empêcher toute exfiltration de code source vers l'extérieur. |
| **Socket Docker** | **Aucun accès au socket Docker** | Interdire la prise de contrôle du démon Docker de l'hôte. |

---

## 5. Infalsificabilité de l'Audit Log (Scellement Cryptographique)

La table `t_audit_log` conserve l'historique de toutes les actions d'administration et de triage
VEX. Chaque entrée intègre un hash SHA-256 calculé à partir de la ligne courante et du hash de la
ligne précédente :

```
Hash_N = SHA256( Id_N + Action_N + User_N + Timestamp_N + Hash_N-1 )
```

La méthode `AuditLogService.verifyIntegrity()` vérifie automatiquement l'intégralité de la chaîne et
détecte la moindre altération ou suppression SQL.

---

## 6. Analyse de Menaces STRIDE

La modélisation complète des menaces selon la méthode **STRIDE par Entité DFD** est documentée
séparément dans [`STRIDE_THREAT_MODEL.fr.md`](../../security/fr/STRIDE_THREAT_MODEL.fr.md).
