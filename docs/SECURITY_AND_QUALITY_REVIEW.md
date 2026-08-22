# Rapport d'Audit & Revue d'Architecture, Qualité et Sécurité

**Projet** : Zanshin  
**Périmètre** : Backend (Spring Boot 4.1 / JDK 25), Frontend (Angular 21 / Optimus UI), Moteurs de Base de Données, Conteneurs d'Analyse, Chaîne de Déploiement (CI/CD / Supply Chain).  
**Auteur** : Architecte Sécurité, Java & Angular  
**Date** : Août 2026  

---

## 1. Résumé Exécutif & Posture Globale

Zanshin présente une **maturité architecturale et sécuritaire exceptionnelle**. Le système applique rigoureusement les principes de **Security by Design**, de **Défense en Profondeur** et de **Moindre Privilège** à l'ensemble des couches logicielles.

Les contrôles de sécurité ne reposent pas sur des conventions implicites mais sont validés et verrouillés par :
1. **Le graphe de dépendances au niveau compilation** (isolation physique des modules).
2. **Des tests d'architecture automatisés (ArchUnit)** vérifiant l'étanchéité des couches.
3. **Des suites d'intégration multi-moteurs (PostgreSQL, MariaDB, MySQL, SQLite)** testant la parité du schéma et la concurrence.
4. **Une politique CSP stricte sans compromis** sur l'exécution dynamique de scripts (`'unsafe-eval'` exclu).
5. **Une chaîne d'approvisionnement (Supply Chain) vérifiée par signature Sigstore et scans SBOM**.

```mermaid
flowchart TB
    subgraph Hostile["Périmètre Non De Confiance"]
        SRC["Code source scanné"]
        FEEDS["Flux CVE / Advisories"]
    end

    subgraph Runtime["Isolation Conteneurs (Zanshin Common)"]
        DOCKER["Scanners (Syft, Grype, Semgrep, Gitleaks)<br/>cap_drop: ALL | network: none | read-only | digest pin"]
    end

    subgraph Core["Control Plane (Spring Boot 4 / JDK 25)"]
        AUTH["Auth & Sessions (Argon2id, Bearer hash SHA-256)"]
        CIPHER["SecretCipher (AES-GCM + Row AAD Context)"]
        SSRF["OutboundUrlGuard + PinnedHttpSender (DNS Pinning)"]
        AUDIT["AuditChain (Graph Hash Integrity + Mirror)"]
        DB[(PostgreSQL / MySQL / MariaDB / SQLite)]
    end

    subgraph Agent["Remote Agent (Isolation JVM)"]
        AGENT_RUN["zanshin-agent (Sans JDBC/Hibernate, Long Polling API)"]
    end

    subgraph Front["Frontend (Angular 21)"]
        UI["Optimus UI / Signals / In-Memory Session<br/>Strict CSP: script-src 'self' (No unsafe-eval)"]
    end

    SRC --> DOCKER
    DOCKER -->|Résultats normalisés (Data only)| Core
    FEEDS --> Core
    Core <---> DB
    AGENT_RUN -->|API REST uniquement| Core
    Core -->|JSON + CSP Strict| Front
```

---

## 2. Architecture & Sécurité Backend (Java 25 / Spring Boot 4.1)

### 2.1. Isolation des Modules au Build (Compile-Time Boundary)
- **Constat** : `zanshin-agent` ne dépend que de `zanshin-common` et n'a aucune dépendance vers `zanshin-core`.
- **Bénéfice Sécurité** : L'agent déporté ne possède aucun pilote JDBC, aucun framework ORM (Hibernate/JPA) et aucune dépendance vers Spring Data sur son classpath.
- **Garantie** : Même en cas de compromission totale d'un agent distant, l'attaquant n'a aucun moyen technique d'accéder à `ENCRYPTION_KEY` ou à la base de données centrale.
- **Validation** : Règle validée par compilation et testée par `AgentIsolationTest`.

### 2.2. Cryptographie & Gestion des Secrets (`SecretCipher`, `PasswordHasher`)
- **Chiffrement Authentifié AES-256-GCM** : Toutes les clés privées SSH et tokens sensibles sont chiffrés au repos via AES-GCM.
- **Liaison au Contexte de Ligne (Associated Authenticated Data - AAD)** : Le contexte AAD intègre l'identifiant de la ligne (`ssh_key:<id>:private_key`). Cela empêche l'attaque par transplantation de ciphertext (déplacer un secret chiffré d'une ligne A vers une ligne B).
- **Hachage des Mots de Passe (Argon2id)** : Implémenté via l'API lightweight de BouncyCastle (19 MiB, 2 passes). Évite la troncature silencieuse à 72 octets inhérente à bcrypt et élimine l'utilisation de providers JCA globaux mutables.
- **Comparaisons Constant-Time** : Utilisation systématique de `Arrays.constantTimeAreEqual` pour éliminer les attaques par canal auxiliaire (timing attacks).

### 2.3. Protection contre les attaques SSRF et DNS Rebinding (`OutboundUrlGuard`, `PinnedHttpSender`)
- **Validation stricte & Typage des Politiques** : `OutboundPolicy` (`INTERNAL_REQUIRED` vs `PUBLIC_ONLY`). Interdiction formelle des plages link-local et cloud metadata (`169.254.169.254`).
- **DNS Pinning** : Le résolveur valide l'ensemble des adresses IP d'un nom d'hôte et transmet la liste vérifiée au client HTTP. Le client se connecte directement à l'adresse IP validée sans réinterroger le DNS, éliminant tout risque de DNS Rebinding / TOCTOU.
- **Non-suivi des Redirections HTTP** : Empêche l'exfiltration de code ou le pivot interne via des réponses `302 Found`.
- **Enforcement ArchUnit** : `ArchitectureTest` vérifie qu'aucun autre composant de l'application ne peut instancier de client HTTP arbitraire (`java.net.http` ou Apache HttpClient).

### 2.4. Isolation & Sandboxing des Conteneurs d'Analyse Docker
- **Moindre Privilège** : Exécution des conteneurs avec `cap_drop: ALL`, `no-new-privileges`, limites mémoire et PID strictes, montages en lecture seule (`read-only`), et coupure réseau (`network: none`) pour les scanners locaux.
- **Immutabilité des Scanners** : Toutes les images d'analyse (Syft, Grype, Semgrep, Gitleaks) sont épinglées par **digest SHA-256**.
- **Sanctuarisation de la Socket Docker** : Aucun conteneur d'analyse n'a accès à `/var/run/docker.sock`. Pour l'analyse d'images, Zanshin exporte lui-même l'archive d'image et la monte en lecture seule.

### 2.5. Contrôle d'Accès & Multi-Tenancy
- **Modèle de Visibilité** : Calcul par union (appartenance aux équipes + assignations directes de dépôts).
- **Prévention de l'Énumération** : Tout refus d'accès sur une ressource non visible renvoie un code **404 Not Found** (et non un 403), interdisant toute énumération d'identifiants.
- **Double Barrière d'Autorisation** : Filtre de sécurité Spring (`SecurityConfiguration`) couplé à des annotations fines (`@PreAuthorize`, `@RequiresAccount`, `@RequiresAdministrator`), validées de façon exhaustive par `RouteAuthorizationTest`.

### 2.6. Intégrité des Journaux d'Audit (`AuditChain`, `AuditMirror`)
- **Chaîne d'Intégrité Cryptographique** : Chaque entrée d'audit porte un hash SHA-256 dépendant de l'entrée précédente (graphe acyclique d'intégrité).
- **Miroir Externe** : Capacité d'export/miroir hors base de données pour détecter toute troncature ou suppression malveillante directe en base de données.

---

## 3. Architecture & Sécurité Frontend (Angular 21)

### 3.1. Gestion des Sessions & Atténuation XSS (`SessionStore`)
- **Stockage en Mémoire (Angular Signals)** : Le Bearer Token est maintenu dans un signal en mémoire vive et **jamais dans `localStorage` ni `sessionStorage`**.
- **Bénéfice Sécurité** : En cas de vulnérabilité XSS potentielle, le token d'authentification ne peut pas être extrait du stockage persistant du navigateur et disparaît dès la fermeture de la session de navigation.
- **Intercepteur HTTP Fonctionnel** : `authInterceptor` injecte l'en-tête `Authorization` et gère le renouvellement ou l'invalidation automatique sur code 401.

### 3.2. Content Security Policy (CSP) & Conformité des Assets
- **En-têtes HTTP de Sécurité** configurés globalement sur toutes les réponses (y compris fichiers statiques et `index.html`) :
  ```http
  default-src 'self';
  script-src 'self';
  style-src 'self' 'unsafe-inline';
  img-src 'self' data:;
  font-src 'self';
  connect-src 'self';
  object-src 'none';
  base-uri 'self';
  form-action 'self';
  frame-ancestors 'none'
  ```
- **Pas de `'unsafe-eval'`** : Build Ahead-of-Time (AOT) Angular strict.
- **Zéro Dépendance CDN Externe** : Vérification automatisée via `scripts/check-assets.mjs` dans la suite de tests frontend (`npm test`).

---

## 4. Qualité de Code, Architecture & Tests

| Domaine | Évaluation | Mécanisme de Contrôle & Enforcement |
|---|---|---|
| **Architecture Hexagonale / En Couches** | 🟢 Exemplaire | ArchUnit (`ArchitectureTest.java`) : Domaine pur, découplé de tout framework |
| **Parité Base de Données (4 moteurs)** | 🟢 Exemplaire | Liquibase unique + Testcontainers sur PostgreSQL, MySQL, MariaDB, SQLite (`SchemaParityIntegrationTest`) |
| **Déterminisme des Fingerprints** | 🟢 Exemplaire | Séparateur NUL (`\0`) évitant les collisions avec `\|` (`IssueFingerprintTest`) |
| **Supply Chain & CI/CD** | 🟢 Exemplaire | Catalogue `libs.versions.toml`, SBOM Syft, Grype scanner, Sigstore Keyless signing + auto-vérification |

---

## 5. Recommandations & Axes d'Amélioration

### 1. Frontend Angular : Ajout de Route Guards (`canActivate`)
- **Constat** : Dans `app.routes.ts`, les routes enfants de `AppLayout` ne disposent pas de gardes `canActivate: [authGuard]`.
- **Impact** : Si un utilisateur non authentifié accède directement à une URL interne (ex: `/repositories`), le composant s'initialise, lance des requêtes API qui échouent en 401, puis l'intercepteur le redirige vers `/login`.
- **Recommandation** : Ajouter des guards fonctionnels `authGuard` et `adminGuard` pour bloquer la navigation avant le montage du layout et de la vue.

### 2. Évolution vers des Cookies de Session `HttpOnly` / `SameSite=Strict`
- **Constat** : Le stockage du token en mémoire dans le frontend protège efficacement contre le vol XSS persistant mais entraîne une déconnexion au rafraîchissement complet de la page (F5).
- **Recommandation** : Implémenter en production un cookie de session émis par Spring Boot avec `HttpOnly; Secure; SameSite=Strict; Path=/api/`, combiné à un jeton CSRF de type Double Submit Cookie, pour concilier persistance fluide et sécurité maximale.

### 3. Gestion de Secret de Webhook Dédié par Destinataire
- **Constat** : Un secret HMAC partagé est actuellement utilisé pour signer les notifications webhook sortantes.
- **Recommandation** : Permettre la configuration d'un secret cryptographique distinct par canal d'équipe (`t_team_webhook.secret`) afin d'isoler hermétiquement les récepteurs.

---

## 6. Conclusion

Le projet Zanshin se distingue par une rigueur d'ingénierie et une culture de la sécurité du plus haut niveau. Les décisions architecturales clés sont documentées, justifiées et protégées contre toute régression par des mécanismes de vérification automatisés et non contournables.
