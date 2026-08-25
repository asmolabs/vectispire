# Rapport d'Audit & Revue d'Architecture, Qualité et Sécurité

**Projet** : Vectispire  
**Périmètre** : Backend (Spring Boot 4.1 / JDK 25), Frontend (Angular 21 / Optimus UI), Moteurs de Base de Données, Conteneurs d'Analyse, Chaîne de Déploiement (CI/CD / Supply Chain), Moteur de Conformité & Coffre-Fort de Preuves.  
**Auteur** : Architecte Sécurité, Java & Angular  
**Date** : Août 2026  

---

## 1. Résumé Exécutif & Posture Globale

Vectispire présente une **maturité architecturale et sécuritaire exceptionnelle**. Le système applique rigoureusement les principes de **Security by Design**, de **Défense en Profondeur** et de **Moindre Privilège** à l'ensemble des couches logicielles.

Les contrôles de sécurité ne reposent pas sur des conventions implicites mais sont validés et verrouillés par :
1. **Le graphe de dépendances au niveau compilation** (isolation physique des modules sans fuite JDBC vers l'agent).
2. **Des tests d'architecture automatisés (ArchUnit)** vérifiant l'étanchéité des couches.
3. **Des suites d'intégration multi-moteurs (PostgreSQL, MySQL, plus la fixture SQLite)** testant la parité du schéma et la concurrence.
4. **Une politique CSP stricte sans compromis** sur l'exécution dynamique de scripts (`'unsafe-eval'` exclu).
5. **Une chaîne d'approvisionnement (Supply Chain)** vérifiée par signature Sigstore keyless, verrous de dépendances Gradle (`gradle.lockfile`) et scans SBOM.
6. **Un moteur de conformité réglementaire intégré** (NIS 2, DORA, ISO 27001, PCI-DSS, EU CRA) avec coffre-fort de preuves scellé (`EvidenceVaultService`).
7. **Une gouvernance à 4 yeux & ingestion VEX amont** (`SECURITY_CHAMPION`, `VexIngestorService`, `CsafGeneratorService`) garantissant l'intégrité des dérogations et l'extinction automatique des vulnérabilités.

```mermaid
flowchart TB
    subgraph Hostile["Périmètre Non De Confiance"]
        SRC["Code source scanné"]
        FEEDS["Flux CVE / KEV / Advisories / VEX éditeurs"]
    end

    subgraph Runtime["Isolation Conteneurs (Vectispire Common)"]
        DOCKER["Scanners (Syft, Grype, Semgrep, Gitleaks)<br/>cap_drop: ALL | network: none | read-only | digest pin"]
    end

    subgraph Core["Control Plane (Spring Boot 4 / JDK 25)"]
        AUTH["Auth & Sessions (Argon2id, Bearer hash SHA-256)"]
        CIPHER["SecretCipher (AES-GCM + Row AAD Context)"]
        SSRF["OutboundUrlGuard + PinnedHttpSender (DNS Pinning)"]
        AUDIT["AuditChain (Graph Hash HMAC Integrity + Mirror)"]
        COMPLIANCE["ComplianceEngine (NIS 2, DORA, ISO 27001, PCI-DSS, EU CRA)"]
        VAULT["EvidenceVaultService (Signed ZIP / In-Toto / OpenVEX / CSAF 2.0)"]
        VEX["VexIngestorService (Cascade Suppression & 4-Eyes Triage)"]
        DB[(PostgreSQL / MySQL)]
    end

    subgraph Agent["Remote Agent (Isolation JVM)"]
        AGENT_RUN["vectispire-agent (Sans JDBC/Hibernate, Long Polling API)"]
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
- **Constat** : `vectispire-agent` ne dépend que de `vectispire-common` et n'a aucune dépendance vers `vectispire-core`.
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
- **Enforcement ArchUnit** : `ArchitectureTest` vérifie qu'aucun autre composant de l'application ne peut instancier de client HTTP arbitraire.

### 2.4. Isolation & Sandboxing des Conteneurs d'Analyse Docker
- **Moindre Privilège** : Exécution des conteneurs avec `cap_drop: ALL`, `no-new-privileges`, limites mémoire et PID strictes, montages en lecture seule (`read-only`), et coupure réseau (`network: none`) pour les scanners locaux.
- **Immutabilité des Scanners** : Toutes les images d'analyse (Syft, Grype, Semgrep, Gitleaks) sont épinglées par **digest SHA-256**.
- **Sanctuarisation de la Socket Docker** : Aucun conteneur d'analyse n'a accès à `/var/run/docker.sock`. Pour l'analyse d'images, Vectispire exporte lui-même l'archive d'image et la monte en lecture seule.

### 2.5. Moteur de Conformité & Preuves d'Audit (`ComplianceEngine`, `EvidenceVaultService`)
- **Calcul Déterministe** : Scoring continu sur 5 référentiels (NIS 2, DORA, ISO 27001, PCI-DSS, Cyber Resilience Act EU CRA) et 7 catégories d'évaluation sans heuristique opaque.
- **Principe de Non-Dilution** : Un seul contrôle critique non conforme invalide l'ensemble du référentiel.
- **Coffre-Fort de Preuves Certifiées** : Génération d'un paquet ZIP scellé avec manifest SHA-256, attestations In-Toto, déclarations OpenVEX, avis OASIS CSAF 2.0, SBOM CycloneDX/SPDX et chaîne d'audit signée.

### 2.6. Gouvernance 4-Yeux & Ingestion VEX Amont (`IssueTriageService`, `VexIngestorService`)
- **Principe des Quatre Yeux** : Les exemptions initiées par les développeurs basculent en `PENDING_APPROVAL`, conservant la Gate bloquante jusqu'à approbation explicite par un `SECURITY_CHAMPION`, `CISO` ou `ADMIN`.
- **Ingestion VEX Amont** : Suppression automatique des failles justifiées par les éditeurs tiers (`POST /api/v1/vex/ingest`) avec traçabilité d'audit intégrale.

---

## 3. Architecture & Sécurité Frontend (Angular 21)

### 3.1. Gestion des Sessions & Atténuation XSS (`SessionStore`)
- **Stockage en Mémoire (Angular Signals)** : Le Bearer Token est maintenu dans un signal en mémoire vive et **jamais dans `localStorage` ni `sessionStorage`**.
- **Bénéfice Sécurité** : En cas de vulnérabilité XSS potentielle, le token d'authentification ne peut pas être extrait du stockage persistant du navigateur et disparaît dès la fermeture de la session de navigation.
- **Intercepteur HTTP Fonctionnel** : `authInterceptor` injecte l'en-tête `Authorization` et gère le renouvellement ou l'invalidation automatique sur code 401.

### 3.2. Content Security Policy (CSP) & Conformité des Assets
- **En-têtes HTTP de Sécurité** configurés globalement sur toutes les réponses :
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

## 4. Tableau de Synthèse de la Qualité et des Contrôles

| Domaine | Évaluation | Mécanisme de Contrôle & Enforcement |
|---|---|---|
| **Architecture Hexagonale / En Couches** | 🟢 Exemplaire | ArchUnit (`ArchitectureTest.java`) : Domaine pur, découplé de tout framework |
| **Parité Base de Données (2 moteurs)** | 🟢 Exemplaire | Flyway multi-dialectes + Testcontainers sur PostgreSQL, MySQL (SQLite for tests) (`SchemaParityIntegrationTest`) |
| **Verrouillage Dépendances (Supply Chain)** | 🟢 Exemplaire | Gradle dependency locking (`gradle.lockfile`), Git pre-commit hook, SBOM Syft, Grype, Sigstore |
| **Déterminisme des Fingerprints** | 🟢 Exemplaire | Séparateur NUL (`\0`) évitant les collisions avec `\|` (`IssueFingerprintTest`) |
| **Conformité Réglementaire** | 🟢 Exemplaire | Évaluation automatisée NIS 2 / DORA / ISO 27001 / PCI-DSS + Coffre de preuves d'audit scellé |
| **Supervision Temps Réel** | 🟢 Exemplaire | Centre de contrôle des agents, suivi des scans en direct et file d'attente |

---

## 5. Recommandations Implémentées & Prochaines Évolutions

1. **Verrouillage Automatique des Dépendances au Commit** :
   - ✅ *Réalisé* : Mise en place du hook Git `.githooks/pre-commit` régénérant automatiquement les write-locks Gradle et le `package-lock.json`.
2. **Supervision Temps Réel de la File d'Analyse** :
   - ✅ *Réalisé* : Tableau de bord KPI et suivi direct des scans en cours et en attente sur `/agents`.
3. **Priorisation par Exploitabilité Réelle (FIRST.org EPSS & CISA KEV)** :
   - ✅ *Réalisé* : Modèle de calcul croisant CVSS, EPSS (probabilité & percentile 30j), Reachability et catalogue CISA KEV sur l'écran `/epss`.
4. **Persistance Sécurisée de Session (Production)** :
   - 🔄 *Évolution future* : Support optionnel de cookies de session `HttpOnly; SameSite=Strict` pour les déploiements requérant une persistance au rafraîchissement complet F5.

