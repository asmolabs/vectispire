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
3. **Altération Détectable du Journal d'Audit** : Une modification ou une suppression sélective des
   traces d'actions d'administration et de qualification VEX est détectée. Elle n'est pas empêchée :
   qui peut écrire dans la table peut réécrire toute la chaîne.
4. **Moindre Privilège des Agents Distants** : Les agents distants ne peuvent pas atteindre la base
   SQL — imposé par le graphe de modules, la violation échoue donc à la compilation — et ne
   détiennent jamais l'`ENCRYPTION_KEY`. Ils reçoivent *bien* des clés de déploiement de dépôt en
   mode `DELEGATED`, scellées (X25519 → HKDF → AES-256-GCM) uniquement pour une clé que l'agent a
   signée avec sa clé de signature des résultats épinglée, jamais en clair, et auditées à chaque
   envoi ([décision 0031](../../fr/decisions/0031-a-sealing-key-is-believed-only-on-the-pinned-key.md)) ;
   `LOCAL`, le défaut, n'envoie rien. Énoncé en
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
L'autorisation a deux moitiés, et une route a besoin des deux.

**Ce que le rôle de l'appelant peut faire** est une annotation composée posée sur chaque route —
`@RequiresAdministrator`, `@RequiresSecurityLead`, `@RequiresGovernanceRead`, `@RequiresPlatformGovernor`,
`@RequiresWriteAccount`, `@RequiresAccount` — chacune un `@PreAuthorize` de Spring Security sur une
expression de rôles (`hasAnyRole('SUPERUSER', 'ADMIN', 'CISO')`, etc.) qui correspond à un drapeau de
l'énumération `Role` ; le tableau ci-dessous donne les rôles de chaque marqueur. Aucune route n'écrit
sa propre liste de rôles.

**De quel parc parle la réponse** est la seconde moitié, et le marqueur n'en dit rien :
`@RequiresAccount` prouve que l'appelant est connecté, pas que le dépôt qu'il nomme est le sien. Une
route qui nomme une cible résout une `Visibility` — `VisibilityService.of(user, credentialRestriction)`,
l'accès du compte croisé avec celui de l'identifiant présenté — et la passe à la requête, ou refuse par
`Visibilities.requireVisible(...)`, qui répond **404, jamais 403**, pour qu'un refus ne confirme pas
que la cible existe. `AuthorizationCoverageTest` attrape la route qui l'oublie.

- **Administrateurs** (SUPERUSER, ADMIN) : comptes, équipes, clés, agents, clés SSH.
- **Double Validation Optionnelle** (`triage_four_eyes_required`) : une règle de la plateforme, donc
  celle du seul **Super-administrateur** — `@RequiresPlatformGovernor`, et le réglage fait partie de
  ceux que `Setting.governsSecurity()` réserve. Activée, une décision VEX qui clôt une anomalie
  (`NOT_AFFECTED` ou `FIXED`) émise par un compte qui ne peut pas approuver passe en état
  `PENDING_APPROVAL`. Désactivée, les utilisateurs autorisés qualifient directement.
- **Identités Distinctes Imposées** : L'approbateur est comparé au demandeur enregistré sur
  l'événement `PENDING_APPROVAL`, et non au seul rôle d'approbation. Un compte qui demande une
  dérogation ne peut pas l'approuver, même après avoir obtenu le rôle — quatre yeux signifie deux
  personnes, et une simple barrière de rôle laisse une seule personne tenir les deux moitiés.
- **Audit des Modifications** : Tout changement de l'option de double validation est immédiatement
  consigné dans le journal d'audit chaîné par empreintes SHA-256 (`t_audit_log`) avec l'identifiant de l'opérateur
  (`SETTING_UPDATED`).
- **USER / SECURITY_CHAMPION** : Consultation du posture dashboard et qualification des
  vulnérabilités. Le référent sécurité peut approuver un triage, mais dans le seul périmètre que sa
  visibilité lui donne — il n'a pas de portée globale.
- **AUDITOR** (2026-09-02) : **lit la gouvernance et n'en écrit rien.** Portée globale, aucune
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

## 5. Altération Détectable de l'Audit Log (Chaîne d'Empreintes)

La table `t_audit_log` conserve l'historique de toutes les actions d'administration et de triage
VEX. Chaque entrée intègre une empreinte SHA-256 sans clé de ses champs et de l'empreinte de la
ligne précédente (`AuditChain.computeEntryHash`), les champs séparés par un octet NUL :

```
Hash_N = SHA256( Hash_N-1 | Timestamp_N | Operation_N | Resource_N | User_N | IP_N | UserAgent_N | Description_N )
```

`AuditLogService.verify()` recalcule la chaîne et signale la première rupture : une modification
ou une suppression sélective casse toutes les empreintes qui suivent. L'empreinte est sans clé, ce
qui ne rend donc pas le journal immuable — qui peut écrire dans la table peut recalculer toute la
chaîne ; c'est la comparaison avec le miroir hors base (`verifyAgainstMirror`) qui le révèle.

---

## 6. Analyse de Menaces STRIDE

La modélisation complète des menaces selon la méthode **STRIDE par Entité DFD** est documentée
séparément dans [`STRIDE_THREAT_MODEL.fr.md`](../../security/fr/STRIDE_THREAT_MODEL.fr.md).
