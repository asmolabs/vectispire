# Rapport d'Audit Approfondi : Documentation, Code Source & Sécurité (Français)

* **Projet :** Vectispire — Control Plane ASPM & Sécurité Logicielle
* **Date d'analyse :** 25 août 2026
* **Évaluateur :** Claude (Anthropic) — audit automatisé du code, de la sécurité et de la documentation
* **Méthode :** Lecture directe des sources et vérification mécanique (résolution des liens, mesure de la parité, inspection du graphe de tâches CI, reconstruction de la chaîne de filtres). Chaque affirmation ci-dessous cite le fichier qui l'établit.
* **Périmètre :** Backend (`vectispire-java`), Frontend (`vectispire-angular`), Documentation (`docs/`), Architecture (`docs/architecture/`), CI (`.github/workflows/`), Déploiement (`Dockerfile`, `docker-compose.yml`)

> **Note de lecture.** Cet audit re-vérifie délibérément plutôt qu'il ne reconfirme. Là où le rapport précédent ([24 août 2026](2026-08-24_audit_approfondi_code_securite_doc.fr.md)) décrivait une intention de conception, celui-ci vérifie si le code l'applique. Plusieurs contrôles correctement *conçus* ne sont pas correctement *câblés*, et les notes ci-dessous reflètent le câblage, non l'intention.

## ✅ 0. État de Remédiation

**Les quatre points 🔴 du §6 ont été corrigés le 25 août 2026 dans le commit `a9ad6fd`, postérieurement à la rédaction de cet audit.** Les constats ci-dessous sont laissés exactement tels qu'ils ont été rapportés — un audit est le relevé de ce qui était vrai au moment où il a tourné, non un tableau de bord vivant — et cette section est la seule chose ajoutée.

| # | Constat | Statut |
|:--:|---|---|
| **F1** | `/api/v1/auth/mfa/verify` injoignable à travers la chaîne de filtres | ✅ `permitAll` ajouté, plus une sonde anonyme à travers la vraie chaîne pour chaque route `@OpenToAnonymous` (`anOpenRouteIsReallyReachableWithoutCredentials`). Vérifié par mutation. |
| **§3.3** | Force brute TOTP sans plafond | ✅ Trois tentatives par défi, défi détruit au dernier échec, défis expirés balayés à l'écriture et map plafonnée. Nouveau `MfaVerificationRoutesTest`. |
| **F2** | Limiteur de débit contournable par `X-Forwarded-For`, map non bornée | ✅ En-tête honoré uniquement derrière `vectispire.security.trusted-proxies` ; LRU bornée élaguée à l'insertion ; périmètre élargi aux routes d'authentification anonymes. |
| **§3.5** | `docker-compose.yml` livrant des secrets fonctionnels | ✅ Les trois secrets sont requis et non plus défaultés, MySQL lié à la boucle locale, `group_add` accorde le groupe de la socket. `.env.example` portait les mêmes valeurs et a été réécrit. |

**Les cinq points 🟠 ont été corrigés dans la même session.**

| # | Constat | Statut |
|:--:|---|---|
| **F3 / §2.2** | 53 liens relatifs cassés sur 305 | ✅ Tous réparés (`decisions/` déplacé dans `en/`+`fr/`, plus corrections de profondeur). `scripts/check-doc-links.py` tourne désormais comme job de CI, le compte reste donc à zéro. |
| **§2.2** | Quatre chemins `file:///Users/lrb/...` dans les modèles STRIDE | ✅ Remplacés par des chemins relatifs. Le vérificateur traite tout lien `file://` comme cassé, ils ne peuvent donc pas revenir. |
| **§4.2** | `integrationTestAll` et Playwright jamais exécutés en CI | ✅ `.github/workflows/nightly.yml` lance les deux à 02:30 UTC, plus `workflow_dispatch`. Le job E2E démarre désormais le control plane, ce que le `webServer` de Playwright ne fait pas. |
| **§3.4** | Quatre yeux fondé sur le rôle et non sur l'identité | ✅ L'approbateur est comparé au demandeur enregistré sur l'événement `PENDING_APPROVAL`. Vérifié par mutation : sans le contrôle, l'auto-approbation passe avec un 200. |
| **§3.6** | Le KMS Vault se replie sur une clé locale avec un simple WARN | ✅ `kms-type=vault` sans point de terminaison ni jeton joignable refuse désormais de démarrer, au lieu de changer silencieusement la garde des clés. |

**Les cinq points 🟡 ont été corrigés dans la même session, ce qui clôt l'intégralité du §6.**

| # | Constat | Statut |
|:--:|---|---|
| **§2.3** | Parité FR/EN absente sur le corpus opérationnel | ✅ `ROTATION_AND_PURGE.fr` 37 → 202 lignes (parité), `TECHNICAL_DOCUMENTATION.fr` 212 → 518, `COMPLIANCE_AND_REGULATORY.md` 204 → 262 (la réconciliation a joué dans l'autre sens, comme l'audit l'indiquait), `GETTING_STARTED.fr` 126 → 187. |
| **§4.2** | Aucune instrumentation de couverture | ✅ Rapports XML JaCoCo, plus un plancher `jacocoTestCoverageVerification` restreint à `common.domain` (80 % instructions, 65 % branches) rattaché à `check`. Vérifié par mutation : relever le plancher fait échouer la construction sur le 0,83 mesuré. |
| **§3.7** | Système de fichiers racine des conteneurs de scan inscriptible | ✅ `withReadonlyRootfs(true)` plus un tmpfs `noexec` pour `/tmp` et `$HOME`. Validé contre les cinq images de scanner épinglées sur un démon réel, et vérifié par quatre nouveaux cas dans la campagne d'intégration conteneurs. |
| **§3.7** | Exposition anonyme de Swagger non configurable | ✅ `vectispire.security.anonymous-api-docs`, fermé par défaut. La première tentative semblait fonctionner et ne fonctionnait pas — la règle de lien profond du SPA attrapait `/v3/api-docs` en premier. |
| **§2.4** | Vocabulaire « changelog » résiduel | ✅ Remplacé par « migration » dans le README, la CI, Gradle et `application.yaml` ; `ChangelogTest` renommé `MigrationsTest`. |

**Un point mesuré plutôt que supposé.** La base de vulnérabilités de Grype pèse environ 1,9 Go et
le tmpfs de travail est de la mémoire comptée sur un plafond conteneur de 2 Go : le rootfs en
lecture seule la cassait net avec `no space left on device`. Elle dispose désormais d'un montage
inscriptible sur disque pour ce seul cache. Livré sur la foi de la relecture, chaque analyse de
dépendances aurait échoué.

---

---

## 📊 1. Synthèse & Notes

| Domaine évalué | Note / 10 | Statut | Résumé de l'évaluation |
|---|:---:|:---:|---|
| **Documentation & Architecture** | **7,5 / 10** | 🟡 **Structure excellente, intégrité dégradée** | Le modèle Bertrand Florat à 5 vues, le DSL C4, le DFD STRIDE et les 13 ADR sont bien présents et d'une qualité rare — mais **53 des 210 liens relatifs sont cassés (25 %)**, la parité bilingue est mesurablement absente sur 4 documents, et deux fichiers embarquent des chemins absolus `file:///Users/...`. |
| **Sécurité & Cryptographie** | **7,0 / 10** | 🟠 **Conception solide, trois défauts de câblage** | Argon2id, AES-256-GCM, KMS Vault, conteneurs de scan épinglés par digest et chaîne d'audit SHA-256 sont réels et bien construits. En face : **la vérification MFA est injoignable à travers la chaîne de filtres**, le limiteur de débit sur le login fait confiance à un `X-Forwarded-For` non authentifié, et le contrôle « quatre yeux » repose sur le rôle et non sur l'identité. |
| **Qualité du Code & Architecture** | **8,5 / 10** | 🟢 **Prêt pour l'entreprise** | ArchUnit impose six règles réelles, le domaine est prouvablement libre de tout framework, zéro `TODO`/`FIXME` en production, 176 classes de test, 4×14 migrations Flyway natives par dialecte. Affaibli par : aucun outillage de couverture, et les deux campagnes les plus coûteuses ne tournent jamais en CI. |
| **Conformité Réglementaire & Standards** | **8,5 / 10** | 🟢 **Certifiable** | Les catalogues de contrôles CRA, NIS 2, DORA et OWASP sont implémentés sous forme de code, avec CycloneDX 1.6, SPDX 2.3, CSAF 2.0, OpenVEX et EPSS. La chaîne de preuve est saine ; ce sont les lacunes de contrôle ci-dessus qu'un évaluateur CRA/DORA contesterait. |
| **Global** | **7,9 / 10** | 🟢 **Solide, trois points à corriger avant une release** | |

### Les trois constats qui comptent

| # | Constat | Sévérité | Preuve |
|:--:|---|:--:|---|
| **F1** | `POST /api/v1/auth/mfa/verify` porte l'annotation `@OpenToAnonymous` mais n'est **pas** en `permitAll` dans la chaîne de filtres : `anyRequest().authenticated()` répond donc **401** à l'appelant anonyme que le flux MFA exige. Tout compte ayant activé la MFA ne peut plus se connecter. | 🔴 **Critique** | [AuthController.java:171](../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/api/AuthController.java) vs [SecurityConfiguration.java:154](../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/api/security/SecurityConfiguration.java) |
| **F2** | Le limiteur de débit du login indexe ses buckets sur un en-tête `X-Forwarded-For` non validé, et son éviction ne s'exécute **que sur le chemin de rejet**. Un client unique faisant tourner cet en-tête contourne entièrement la limite *et* fait croître une `ConcurrentHashMap` non bornée. | 🟠 **Élevée** | [LoginRateLimitFilter.java:70](../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/api/security/LoginRateLimitFilter.java) |
| **F3** | Intégrité documentaire : 53 liens relatifs cassés, concentrés sur les chemins `docs/architecture/decisions/` déplacés dans les sous-arbres `en/` et `fr/`. | 🟠 **Élevée** | Vérification mécanique des 210 liens relatifs Markdown |

---

## 📚 2. Documentation & Architecture

### 2.1 Ce qui est réellement exemplaire

1. **Modèle d'architecture Bertrand Florat** — [`docs/architecture/bflorat/`](../../architecture/bflorat/README.md) porte les cinq vues autoportantes dans les deux langues, à **parité stricte ligne pour ligne** (88/88, 74/74, 52/52, 66/66, 73/73). C'est la partie la mieux tenue du corpus.
2. **Architecture-as-code C4** — [`workspace.dsl`](../../architecture/c4/workspace.dsl) modélise trois niveaux C4, avec les rendus PlantUML et PNG versionnés sous [`c4/diagrams/`](../../architecture/c4/) et un script de génération dans [`scripts/generate-c4-diagrams.sh`](../../../scripts/generate-c4-diagrams.sh).
3. **Modèle de menaces STRIDE formel** — [EN](../../architecture/security/en/STRIDE_THREAT_MODEL.en.md) / [FR](../../architecture/security/fr/STRIDE_THREAT_MODEL.fr.md), 171 lignes chacun, à parité exacte, couvrant entités, processus, magasins de données et 16 flux.
4. **13 ADR, avec une chaîne de remplacement vivante** — l'[ADR 0011 (Liquibase)](../../architecture/fr/decisions/0011-liquibase-rather-than-flyway.md) est correctement marqué *remplacé* par l'[ADR 0013 (Flyway multi-dialecte)](../../architecture/fr/decisions/0013-flyway-multi-dialect-migrations.md), dans les deux langues. Un ADR remplacé qui se prétend encore courant est la défaillance habituelle d'un registre d'ADR ; elle est ici évitée.
5. **La qualité des commentaires comme documentation d'architecture.** La prose de [`AuditChain.java`](../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/domain/audit/AuditChain.java) — dont une section explicitement intitulée *« Ce que cela ne détecte plus, et il faut le dire »* — atteint un niveau d'honnêteté intellectuelle que cet audit n'a retrouvé nulle part ailleurs dans le corpus, et qu'il considère comme le premier actif documentaire du projet.

### 2.2 Intégrité des liens — 53 liens relatifs sur 210 sont cassés (25 %)

Chaque lien Markdown relatif du dépôt a été résolu contre le système de fichiers. Les échecs se regroupent en quatre causes :

| Cause | Nombre | Exemple |
|---|:--:|---|
| `docs/architecture/decisions/` référencé à l'ancien chemin, antérieur au bilinguisme | ~30 | [`README.md`](../../../README.md) → `docs/architecture/decisions/0010-one-scan-runner.md` (désormais sous `en/`) |
| Profondeur erronée après la réorganisation `docs/en/` + `docs/fr/` | ~15 | [`docs/en/TECHNICAL_DOCUMENTATION.md`](../../en/TECHNICAL_DOCUMENTATION.md) → `../vectispire-java/...`, qui résout vers `docs/vectispire-java/...` |
| `decisions/…` référencé depuis `bflorat/` et `security/`, où aucun répertoire `decisions/` n'existe | 6 | [`04_vue_infrastructure.md`](../../architecture/bflorat/fr/04_vue_infrastructure.md) → `decisions/0013-…` |
| Chemins locaux absolus fuités dans des documents publiés | 4 | Les deux fichiers STRIDE contiennent `file:///Users/lrb/Dev/Asmolabs/vectispire/…` |

La dernière ligne est à corriger en premier : un modèle de menaces publié qui embarque le répertoire personnel de son auteur est à la fois un lien cassé et une fuite d'information.

### 2.3 La parité bilingue est affirmée mais non atteinte

L'affirmation d'une « synchronisation bilingue stricte » tient pour `bflorat/`, STRIDE, la référence d'API et `docs/architecture/{en,fr}/`. Elle ne tient **pas** pour le corpus opérationnel :

| Document | EN (lignes) | FR (lignes) | Écart |
|---|:--:|:--:|---|
| `ROTATION_AND_PURGE` | 202 | 37 | **FR 82 % plus court** — un embryon face à une procédure complète |
| `TECHNICAL_DOCUMENTATION` | 513 | 212 | **FR 59 % plus court** |
| `GETTING_STARTED` | 203 | 118 | FR 42 % plus court |
| `COMPLIANCE_AND_REGULATORY` | 204 | 263 | **EN 22 % plus court** — la divergence joue dans les deux sens |
| `01-overview` | 112 | 95 | EN en avance |

Le contenu français existant est une véritable traduction, non un remplissage automatique ([`ROTATION_AND_PURGE.fr.md`](../../fr/ROTATION_AND_PURGE.fr.md) se lit comme du français natif) — le déficit porte sur la couverture, pas sur la qualité. Pour un produit vendu sur la traçabilité réglementaire à destination d'un marché francophone, une procédure de rotation et de purge en français réduite à 18 % de son équivalent anglais est une lacune de preuve de conformité, pas un simple retard de traduction.

### 2.4 Vocabulaire Liquibase résiduel

L'[ADR 0013](../../architecture/fr/decisions/0013-flyway-multi-dialect-migrations.md) a fait passer le projet de Liquibase à Flyway, mais le mot *changelog* survit à l'endroit même qui définit la règle — [`application.yaml:14`](../../../vectispire-java/vectispire-core/src/main/resources/application.yaml) (*« The schema belongs to the changelog »*) et [`README.md:446`](../../../README.md). Cosmétique, mais c'est exactement la dérive que l'ADR 0013 existe pour empêcher.

---

## 🛡️ 3. Sécurité & Cryptographie

### 3.1 F1 — La vérification MFA est injoignable (🔴 Critique)

[`AuthController.verifyMfa`](../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/api/AuthController.java) porte l'annotation `@OpenToAnonymous` et est appelé par le SPA en [`api.service.ts:524`](../../../vectispire-angular/src/app/core/api.service.ts) sans jeton porteur — à juste titre, puisque ce jeton est précisément ce que l'appel cherche à obtenir.

Mais la chaîne de filtres de [`SecurityConfiguration.apiSecurity`](../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/api/security/SecurityConfiguration.java) met en `permitAll` `/api/v1/auth/login`, `/auth/methods` et `/auth/session/exchange` — **et pas `/auth/mfa/verify`**. La requête retombe donc sur `anyRequest().authenticated()`, et le `authenticated()` de Spring Security rejette le jeton d'authentification anonyme. L'endpoint répond **401 avant même que le contrôleur soit atteint**.

**Conséquence :** tout compte dont `mfaEnabled` est vrai est verrouillé dehors. L'étape 1 renvoie un `mfa_token` ; l'étape 2 ne peut pas être appelée.

**Pourquoi aucun test ne l'attrape.** [`RouteAuthorizationTest`](../../../vectispire-java/vectispire-core/src/test/java/com/asmolabs/vectispire/core/api/RouteAuthorizationTest.java) énumère les **annotations** `@OpenToAnonymous` et vérifie l'ensemble — `/api/v1/auth/mfa/verify` y figure ligne 104 et la campagne est verte. La seule chose qu'elle ne fait pas est d'émettre une requête non authentifiée à travers la vraie chaîne, ce qui est exactement la divergence en cause. C'est l'illustration la plus nette, dans cet audit, d'un test qui prouve qu'une règle est *énoncée* plutôt qu'*appliquée* — le mode de défaillance contre lequel `ArchitectureTest` se prémunit explicitement ailleurs dans ce même code.

À noter également : le commentaire de la campagne dit *« les trois ci-dessous sont les portes d'entrée »* alors que l'assertion en liste six — le commentaire a cessé de suivre la liste.

**Correctif :** ajouter `.requestMatchers("/api/v1/auth/mfa/verify").permitAll()`, et ajouter une sonde MockMvc vérifiant que chaque route `@OpenToAnonymous` renvoie autre chose qu'un 401 sans identifiants.

### 3.2 F2 — Le limiteur de débit du login est contournable et non borné (🟠 Élevée)

[`LoginRateLimitFilter`](../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/api/security/LoginRateLimitFilter.java) est bien placé — enregistré avant `UsernamePasswordAuthenticationFilter`, il s'exécute donc avant toute dérivation Argon2id, ce qui est la bonne conception pour une défense contre l'épuisement CPU. Trois défauts dans l'implémentation :

1. **Clé usurpable.** `resolveClientIp` renvoie le premier élément de `X-Forwarded-For` dès que l'en-tête est présent, sans aucun contrôle de proxy de confiance. Un attaquant positionne `X-Forwarded-For: <aléatoire>` à chaque requête et reçoit à chaque fois un bucket neuf de 10 jetons. La limite est inopérante face à quiconque a lu le code source — c'est-à-dire, pour un projet Apache-2.0, tout le monde.
2. **Une éviction qui ne s'exécute jamais.** `evictOldBucketsIfNecessary()` n'est appelée **qu'à l'intérieur de la branche `!probe.isConsumed()`**. Dans l'attaque ci-dessus, aucune requête n'est jamais rejetée : l'éviction n'est donc jamais atteinte et `buckets` croît sans borne — transformant le contrôle anti-DoS en vecteur d'épuisement mémoire.
3. **La remise à zéro globale comme stratégie d'éviction.** Lorsqu'elle se déclenche, `buckets.clear()` efface *toutes* les IP suivies, y compris les attaquants légitimement bridés.

**Correctif :** n'honorer `X-Forwarded-For` que depuis une liste de proxys de confiance configurée (ou déléguer à `ForwardedHeaderFilter` via `server.forward-headers-strategy`), avec repli sur `getRemoteAddr()` ; déplacer l'appel d'éviction sur le chemin d'admission ; remplacer `clear()` par un LRU borné ou un cache Caffeine à expiration.

### 3.3 Le TOTP n'est pas protégé contre la force brute (🟠 Élevée — latent derrière F1)

`verifyMfa` n'applique **aucun compteur de tentatives**, et un code erroné n'invalide **pas** le défi : `mfaChallenges.remove` ne s'exécute qu'en cas de succès. Le défi vit 300 secondes. Un attaquant détenant des identifiants valides peut donc rejouer un code à 6 chiffres sur une fenêtre de 5 minutes au rythme que le serveur supporte — et `/mfa/verify` échappe au périmètre mono-chemin du limiteur de débit. Ce risque est aujourd'hui masqué par F1 ; **corriger F1 sans corriger ceci transforme un verrouillage en contournement de MFA**, les deux doivent donc être livrés ensemble.

La map `mfaChallenges` est par ailleurs une `ConcurrentHashMap` en mémoire, non bornée, sans balayage des entrées expirées, et locale à l'instance — la connexion MFA casse derrière un répartiteur de charge sans affinité de session, dans une chaîne `STATELESS` qui n'a par ailleurs aucun besoin d'affinité.

**Correctif :** plafonner les tentatives par défi (3), détruire le défi au dernier échec, balayer à l'écriture, et étendre le limiteur de débit à tout le préfixe `/api/v1/auth/**`.

### 3.4 Le « quatre yeux » repose sur le rôle, pas sur l'identité (🟡 Moyenne)

[`IssueTriageService.resolveRequest`](../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/services/IssueTriageService.java) rétrograde `NOT_AFFECTED` en `PENDING_APPROVAL` lorsque l'acteur ne possède pas `Role.canApproveTriage`, et `canApprove` est dérivé uniquement du rôle de l'appelant en [`IssuesController.java:306`](../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/api/IssuesController.java).

Rien ne compare l'identité de l'approbateur à celle du demandeur. Un Security Champion peut lever une exemption et l'approuver dans le même appel, et un approbateur agissant seul contourne entièrement la file. Il s'agit d'une **barrière de rôle maker-checker**, qui est un vrai contrôle — mais ce n'est pas un contrôle à quatre yeux, et les évaluateurs DORA art. 9 / NIS 2 art. 21 lisent ce terme au sens littéral.

**Correctif :** refuser une approbation dont le `triagedBy` est égal à l'acteur de l'événement `PENDING_APPROVAL`, et renommer le réglage d'après ce qu'il impose réellement.

### 3.5 Les valeurs par défaut de déploiement embarquent des secrets réels (🟡 Moyenne)

[`docker-compose.yml`](../../../docker-compose.yml) fixe par défaut `ENCRYPTION_KEY` à `dGVzdC1lbmNyeXB0aW9uLWtleS0zMi1ieXRlcyEh` (base64 de `test-encryption-key-32-bytes!!`), `VECTISPIRE_BOOTSTRAP_PASSWORD` à `AdminVectispire2026!` et le mot de passe de la base à `vectispire_secure_db_pass`. Un `docker compose up` sans `.env` produit une instance dont chaque clé SSH de déploiement et chaque jeton d'intégration stockés sont déchiffrables par quiconque détient une copie de ce dépôt public. PostgreSQL est en outre publié sur le port hôte `5432`.

Par ailleurs, [`Dockerfile:76`](../../../Dockerfile) documente correctement que l'utilisateur non privilégié `vectispire` doit être ajouté au groupe propriétaire de la socket Docker via `--group-add` — mais `docker-compose.yml` monte la socket **sans** entrée `group_add:`, si bien que le fichier compose livré démarre un control plane incapable de lancer le moindre scanner.

**Correctif :** supprimer les valeurs `:-` par défaut des trois secrets et échouer immédiatement en leur absence ; lier PostgreSQL à `127.0.0.1` ; ajouter `group_add: [docker]`.

### 3.6 Le KMS échoue en mode ouvert (🟡 Moyenne)

[`EncryptionService`](../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/services/EncryptionService.java) journalise `"Vault KMS requested but missing endpoint or token. Falling back to local encryption."` puis poursuit. Un jeton Vault expiré au démarrage bascule silencieusement toutes les écritures suivantes des clés gérées par Transit vers une clé locale dérivée par scrypt — un changement de garde des clés annoncé par une seule ligne WARN. Un contrôle qui se dégrade silencieusement est un contrôle qui n'est pas audité.

**Correctif :** lorsque `kmsType=vault` est explicitement configuré, refuser de démarrer sans point de terminaison Transit joignable.

### 3.7 Ce qui est réellement bien construit

- **Le bac à sable des scanners est réel et fermé par défaut.** [`ContainerRunner.run`](../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/scanning/ContainerRunner.java) applique `withCapDrop(Capability.values())`, `no-new-privileges`, un plafond mémoire, un plafond de PID et `NetworkMode = "none"` sauf demande explicite du scanner. [`ContainerRun.of`](../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/scanning/ContainerRun.java) fait de la forme restrictive le défaut, et de `withNetwork()` / `runningAsRoot()` des dérogations délibérées. Aucune socket Docker n'est montée dans un scanner. *Précision :* le système de fichiers racine du conteneur n'est **pas** `read_only` — seuls les montages bind portent `:ro`. Ajouter `withReadonlyRootfs(true)` plus un `tmpfs` de travail fermerait la dernière brèche.
- **Les images de scanners sont épinglées par digest** — six références `sha256:` dans [`ScannerImages.java`](../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/scanning/scanners/ScannerImages.java), et la CI réutilise les mêmes digests plutôt que `:latest`.
- **L'isolation de l'agent est imposée par le graphe de modules et réaffirmée par un test.** [`AgentIsolationTest`](../../../vectispire-java/vectispire-agent/src/test/java/com/asmolabs/vectispire/agent/AgentIsolationTest.java) interdit `java.sql`, `jakarta.persistence`, `org.springframework.data`, Flyway, Liquibase et tout `core` sur le classpath de l'agent — et vérifie d'abord que l'import n'est pas vide, de sorte qu'un package renommé ne puisse pas vider la règle en silence.
- **La chaîne d'audit est honnête sur ses propres limites.** `AuditChain.verifyChain` documente qu'une suppression de feuille est indétectable et explique pourquoi ce compromis a été retenu (des écrivains concurrents forkant la chaîne produisaient de fausses alertes). Le séparateur de champ NUL et les horodatages canonisés à la milliseconde sont un durcissement correct.
- **Le SSRF est centralisé.** `ArchitectureTest.onlyTheOutboundDoorSpeaksHttpOutwards` interdit à toute classe hors de `PinnedHttpSender` / `OutboundPost` / `OutboundJson` de détenir un client HTTP, avec une correspondance sur le nom pleinement qualifié pour que les classes internes anonymes comptent — et le commentaire de la règle énonce franchement que `03-security.md` a prétendu que cette règle existait pendant tout le temps où elle n'existait pas.
- **La CSP est bien raisonnée**, `frame-ancestors 'none'`, pas d'`unsafe-eval`, l'absence de HSTS étant explicitement justifiée.

**Une exposition à peser :** `/v3/api-docs/**` et `/swagger-ui/**` sont en `permitAll`. Pour un control plane qui inventorie la surface d'attaque des autres, publier son propre catalogue complet d'endpoints à des appelants anonymes est un choix délibéré qui devrait être un réglage documenté plutôt qu'une constante.

---

## ⚙️ 4. Qualité du Code & Architecture Logicielle

### 4.1 Backend

**Spring Boot 4.1.0 / JDK 25 confirmés** ([`libs.versions.toml`](../../../vectispire-java/gradle/libs.versions.toml)), trois modules, 585 sources Java, **176 classes de test**, et **zéro `TODO`/`FIXME` dans les sources de production** — un arbre d'une propreté peu commune.

[`ArchitectureTest`](../../../vectispire-java/vectispire-core/src/test/java/com/asmolabs/vectispire/core/ArchitectureTest.java) impose six règles, pas une : la pile à six couches, la pureté du domaine (ni Spring, ni JPA, ni Hibernate, ni JDBC, ni Flyway, ni Liquibase, **ni docker-java**), le SQL confiné aux repositories, la porte HTTP sortante, la pureté des entités — et, en premier, une assertion vérifiant que des classes ont bien été importées, qui est le mode de défaillance faisant passer une campagne d'architecture à vide. Cette garde figure dans les deux campagnes d'architecture. C'est la marque de quelqu'un qui s'est déjà brûlé sur une campagne verte.

Le fichier de dépendances épingle par ailleurs `httpclient5` / `httpcore5` **au-dessus** du BOM Spring Boot pour purger trois GHSA nommés, avec la consigne de retirer la surcharge dès que le BOM rattrapera — de l'hygiène de chaîne d'approvisionnement appliquée à sa propre chaîne d'approvisionnement.

### 4.2 Les deux campagnes les plus coûteuses ne tournent jamais en CI

- **Campagne d'intégration sur quatre moteurs.** `integrationTestAll` ([`build.gradle.kts:207`](../../../vectispire-java/vectispire-core/build.gradle.kts)) se déploie sur PostgreSQL, MariaDB, MySQL et SQLite via Testcontainers, et 14 scripts Flyway natifs existent par moteur (56 fichiers). Elle n'est **pas rattachée à `check`**, et [`ci.yml`](../../../.github/workflows/ci.yml) n'exécute que `./gradlew build`. **À l'honneur du projet, le fichier CI le dit lui-même dans un commentaire intitulé *« Point 3 is not run here, deliberately, and that is a gap worth naming »***, en précisant que cette campagne a détecté cinq divergences entre moteurs pendant le portage. C'est la bonne manière de divulguer une lacune — mais une régression de portabilité part malgré tout en silence entre deux exécutions manuelles.
- **E2E Playwright.** Quatre campagnes existent (`auth`, `four-eyes-approval`, `settings-audit`, `vex-triage`) et `test:e2e` est défini — mais `playwright` n'apparaît dans aucun des deux workflows. Ces campagnes documentent une intention, elles ne constituent pas une barrière. À noter : `auth.spec.ts` ne couvre pas la MFA, ce qui est la seconde raison pour laquelle F1 est passé inaperçu.
- **Aucune instrumentation de couverture** — ni JaCoCo, ni seuil Istanbul. Avec 176 classes de test la couverture est probablement bonne ; rien ne la mesure ni ne la défend.

**Correctif :** un workflow nocturne (et non par PR) exécutant `integrationTestAll` et `playwright test`, plus JaCoCo avec un plancher sur `common.domain`, la couche dont toute l'architecture soutient qu'elle doit être exhaustivement testée.

### 4.3 Frontend

Angular 21 confirmé, workspaces npm avec un unique lockfile racine et `npm ci` en CI, `openapi-typescript` générant le client depuis `openapi.json` — la bonne façon de garder les DTO honnêtes. 15 fichiers `.spec.ts` pour 70 sources suggèrent que la couverture unitaire est la moitié la plus mince de la stratégie de test. Les paquets Angular sont déclarés en plages flottantes `^21` ; le lockfile rend les builds reproductibles, c'est donc une remarque et non un défaut.

---

## 📋 5. Conformité Réglementaire & Standards

[`ComplianceFramework`](../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/domain/compliance/ComplianceFramework.java) est un véritable catalogue de contrôles exprimé en code, non un tableau marketing : NIS 2 art. 21 (`VULN`, `SUPPLY`, `CRYPTO`, `GOV`), CRA UE art. 10–11 (`SBOM`, `LIFECYCLE`, `VULN`, `NOTIF`), DORA art. 9/11/13/16 et OWASP — évalués par `ComplianceEngine` dans la couche domaine pure, donc exhaustivement testables ([`ComplianceEngineTest`](../../../vectispire-java/vectispire-common/src/test/java/com/asmolabs/vectispire/common/domain/compliance/ComplianceEngineTest.java)). L'interopérabilité de la chaîne d'approvisionnement (CycloneDX 1.6, SPDX 2.3, CSAF 2.0, OpenVEX, EPSS, reachability) s'appuie sur des packages de domaine dédiés et des tests de routes.

Deux réserves qu'un évaluateur soulèverait :

1. **La preuve CRA art. 10 / DORA repose sur des contrôles que cet audit a trouvés non câblés.** `DORA-ART13-SECRETS` est mis à mal par le §3.5, et toute attestation « quatre yeux » l'est par le §3.4.
2. **La propriété la plus forte de la piste d'audit est sous-déclarée.** `AuditChain` ne peut pas détecter la suppression d'une feuille — dit noir sur blanc dans le code, absent de la documentation de conformité. Mieux vaut l'y énoncer aussi : un évaluateur qui le découvre seul dévalue tout le reste.

---

## 🎯 6. Recommandations Priorisées

### 🔴 Avant la prochaine release — **fait, voir §0**
1. **Mettre `/api/v1/auth/mfa/verify` en `permitAll`**, et ajouter une sonde MockMvc anonyme pour chaque route `@OpenToAnonymous` afin que l'annotation et la chaîne ne puissent plus jamais diverger *(§3.1)*.
2. **Plafonner les tentatives TOTP par défi et détruire le défi au dernier échec** — à livrer avec le point 1, jamais après *(§3.3)*.
3. **Valider `X-Forwarded-For` contre une liste de proxys de confiance, déplacer l'éviction sur le chemin d'admission, remplacer `clear()` par un LRU borné** *(§3.2)*.
4. **Retirer les valeurs par défaut d'`ENCRYPTION_KEY`, du mot de passe d'amorçage et du mot de passe de base de `docker-compose.yml` ; ajouter `group_add: [docker]` ; lier PostgreSQL à la boucle locale** *(§3.5)*.

### 🟠 Itération suivante — **fait, voir §0**
5. **Corriger les 53 liens cassés** — une réécriture unique `docs/architecture/decisions/` → `docs/architecture/{en,fr}/decisions/` plus les corrections de profondeur — et **ajouter le vérificateur de liens à la CI** pour que le compte reste à zéro *(§2.2)*.
6. **Supprimer les quatre chemins `file:///Users/lrb/...` des deux documents STRIDE** *(§2.2)*.
7. **Workflow nocturne : `integrationTestAll` + `playwright test`** *(§4.2)*.
8. **Imposer un « quatre yeux » à identités distinctes**, ou renommer le contrôle *(§3.4)*.
9. **Échouer immédiatement lorsque `kmsType=vault` ne peut joindre Transit** *(§3.6)*.

### 🟡 Arriéré — **fait, voir §0**
10. Amener `ROTATION_AND_PURGE.fr` (37 contre 202 lignes) et `TECHNICAL_DOCUMENTATION.fr` (212 contre 513) à parité ; réconcilier `COMPLIANCE_AND_REGULATORY` dans l'autre sens *(§2.3)*.
11. Ajouter JaCoCo avec un plancher de couverture sur `common.domain` *(§4.2)*.
12. Ajouter `withReadonlyRootfs(true)` + `tmpfs` de travail aux conteneurs de scan *(§3.7)*.
13. Faire de l'exposition anonyme de Swagger un réglage *(§3.7)*.
14. Remplacer le vocabulaire « changelog » résiduel par « migration » *(§2.4)*.

---

## 7. Conclusion

Vectispire est un système réellement bien architecturé. Le découpage en couches est imposé plutôt que décrit, le domaine est prouvablement pur, l'isolation des scanners est fermée par défaut, l'incapacité de l'agent à joindre la base est une propriété du graphe de modules et non une convention, et les commentaires du code tiennent un niveau d'autocritique — y compris, dans le fichier CI et dans `AuditChain`, la divulgation des lacunes du projet lui-même — que cet audit situe au-dessus de la moyenne de son industrie.

Ce que l'évaluation précédente a manqué, c'est que plusieurs de ces contrôles sont correctement *conçus* et incorrectement *câblés*. La MFA est injoignable, le limiteur de débit est contournable par en-tête, le « quatre yeux » repose sur le rôle, et un quart des liens de la documentation ne résout pas. Aucun de ces points n'est un défaut d'architecture ; tous les quatre représentent une journée de travail. Le **7,9 / 10** reflète un code dont le plafond est très haut et dont l'état actuel n'en est séparé que par quatre choses.
