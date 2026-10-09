# Auto-revue d'architecture, de qualité et de sécurité (août 2026)

**Projet** : Vectispire  
**Périmètre** : Backend (Spring Boot 4.1 / JDK 25), Frontend (Angular 22 / Optimus UI), Moteurs de Base de Données, Conteneurs d'Analyse, Chaîne de Déploiement (CI/CD / Supply Chain), Moteur de Conformité & Paquet de Preuves.  
**Rédigé par** : les mainteneurs du projet, sur leur propre code  
**Date** : août 2026  

> **Une auto-revue, pas un audit.** Personne d'extérieur au projet n'a vérifié ce qui suit, et le
> code a changé depuis. Elle est gardée comme trace de la façon dont la conception était décrite à
> l'époque ; là où elle et le code divergent, le code a raison. Déplacée ici depuis `docs/fr/` en
> octobre 2026.

---

## 1. Synthèse

La revue a examiné comment la défense en profondeur et le moindre privilège s'appliquent aux
différentes couches. Chaque propriété ci-dessous repose sur un mécanisme qui s'exécute, plutôt que
sur une convention :
1. **Le graphe de dépendances au niveau compilation** (isolation physique des modules sans fuite JDBC vers l'agent).
2. **Des tests d'architecture automatisés (ArchUnit)** vérifiant l'étanchéité des couches.
3. **Des suites d'intégration multi-moteurs (PostgreSQL, MySQL)** testant la parité du schéma et la concurrence.
4. **Une politique CSP stricte sur les scripts** — `script-src 'self'`, sans `'unsafe-inline'` ni `'unsafe-eval'` — et **assouplie sur les styles** : `style-src` garde `'unsafe-inline'`, parce que l'interface écrit encore des attributs de style. Un style injecté peut maquiller une page ; il ne peut pas s'exécuter.
5. **Une chaîne d'approvisionnement (Supply Chain)** vérifiée par signature Sigstore keyless, verrous de dépendances Gradle (`gradle.lockfile`) et scans SBOM.
6. **Une évaluation de conformité** — 24 contrôles techniques nommés d'après six référentiels (NIS 2, DORA, ISO 27001, PCI-DSS, EU CRA, SOC 2) — exportée en paquet de preuves au manifeste signé (`EvidenceVaultService`).
7. **Un triage à quatre yeux et l'import VEX amont** (`SECURITY_CHAMPION`, `VexIngestorService`, `CsafGeneratorService`) : une dérogation demandée par un développeur attend une seconde personne, et un import VEX est une décision de triage enregistrée au nom de qui le dépose.

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
        AUDIT["AuditChain (chaîne d'empreintes SHA-256 + miroir)"]
        COMPLIANCE["ComplianceEngine (NIS 2, DORA, ISO 27001, PCI-DSS, EU CRA, SOC 2)"]
        VAULT["EvidenceVaultService (Signed ZIP / In-Toto / OpenVEX / CSAF 2.0)"]
        VEX["VexIngestorService (Cascade Suppression & 4-Eyes Triage)"]
        DB[(PostgreSQL / MySQL)]
    end

    subgraph Agent["Remote Agent (Isolation JVM)"]
        AGENT_RUN["vectispire-agent (Sans JDBC/Hibernate, Long Polling API)"]
    end

    subgraph Front["Frontend (Angular 22)"]
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
- **Conséquence** : un agent compromis ne détient aucune connexion à la base et n'a aucun usage de `ENCRYPTION_KEY` ; il n'atteint le plan de contrôle que par son API.
- **Validation** : Règle validée par compilation et testée par `AgentIsolationTest`.

### 2.2. Cryptographie & Gestion des Secrets (`SecretCipher`, `PasswordHasher`)
- **Chiffrement Authentifié AES-256-GCM** : Toutes les clés privées SSH et tokens sensibles sont chiffrés au repos via AES-GCM.
- **Liaison au Contexte de Ligne (Associated Authenticated Data - AAD)** : Le contexte AAD intègre l'identifiant de la ligne (`ssh_key:<id>:private_key`). Cela empêche l'attaque par transplantation de ciphertext (déplacer un secret chiffré d'une ligne A vers une ligne B).
- **Hachage des Mots de Passe (Argon2id)** : Implémenté via l'API lightweight de BouncyCastle (19 MiB, 2 passes). Évite la troncature silencieuse à 72 octets inhérente à bcrypt et élimine l'utilisation de providers JCA globaux mutables.
- **Comparaisons Constant-Time** : `Arrays.constantTimeAreEqual` sert aux comparaisons d'authentification et d'empreintes, si bien que leur durée ne révèle pas où deux valeurs diffèrent.

### 2.3. Protection contre les attaques SSRF et DNS Rebinding (`OutboundUrlGuard`, `PinnedHttpSender`)
- **Validation stricte & Typage des Politiques** : `OutboundPolicy` (`INTERNAL_REQUIRED` vs `PUBLIC_ONLY`). Interdiction formelle des plages link-local et cloud metadata (`169.254.169.254`).
- **DNS Pinning** : Le résolveur valide l'ensemble des adresses IP d'un nom d'hôte et transmet la liste vérifiée au client HTTP. Le client se connecte directement à l'adresse IP validée sans réinterroger le DNS : l'adresse vérifiée est l'adresse contactée (pas de fenêtre de DNS rebinding).
- **Non-suivi des Redirections HTTP** : Empêche l'exfiltration de code ou le pivot interne via des réponses `302 Found`.
- **Enforcement ArchUnit** : `ArchitectureTest` vérifie qu'aucun autre composant de l'application ne peut instancier de client HTTP arbitraire.

### 2.4. Isolation & Sandboxing des Conteneurs d'Analyse Docker
- **Moindre Privilège** : Exécution des conteneurs avec `cap_drop: ALL`, `no-new-privileges`, limites mémoire et PID strictes, montages en lecture seule (`read-only`), et coupure réseau (`network: none`) pour les scanners locaux.
- **Épinglage des Scanners** : Toutes les images d'analyse (Syft, Grype, Semgrep, Gitleaks) sont épinglées par **digest SHA-256**.
- **Sanctuarisation de la Socket Docker** : Aucun conteneur d'analyse n'a accès à `/var/run/docker.sock`. Pour l'analyse d'images, Vectispire exporte lui-même l'archive d'image et la monte en lecture seule.

### 2.5. Moteur de Conformité & Preuves d'Audit (`ComplianceEngine`, `EvidenceVaultService`)
- **Notation** : 24 contrôles techniques, quatre par référentiel (NIS 2, DORA, ISO 27001, PCI-DSS, Cyber Resilience Act EU CRA, SOC 2), notés par 7 catégories d'évaluation ; la même entrée donne le même verdict. Cela prépare une évaluation, ce n'en est pas une.
- **Pas de dilution** : un seul contrôle non conforme rend le référentiel non conforme, quelle que soit la moyenne.
- **Paquets de preuves** : archive ZIP au manifeste signé, attestations In-Toto, déclarations OpenVEX, avis OASIS CSAF 2.0, SBOM CycloneDX 1.5 avec VEX intégré et journal d'audit chaîné par empreintes SHA-256 (altération détectable, sans clé — c'est le manifeste du paquet qui est signé).

### 2.6. Gouvernance 4-Yeux & Ingestion VEX Amont (`IssueTriageService`, `VexIngestorService`)
- **Principe des Quatre Yeux** : Les exemptions initiées par les développeurs basculent en `PENDING_APPROVAL`, conservant la Gate bloquante jusqu'à approbation explicite par un `SECURITY_CHAMPION`, `CISO` ou `ADMIN`.
- **Import VEX amont** : `POST /api/v1/vex/ingest` applique les déclarations `not_affected` OpenVEX ou CycloneDX d'un éditeur aux problèmes que voit la personne qui importe, comme sa décision de triage, sous le principe des quatre yeux, avec une entrée d'audit par import.

---

## 3. Architecture & Sécurité Frontend (Angular 22)

### 3.1. Gestion des Sessions & Atténuation XSS (`SessionStore`)
- **Stockage en Mémoire (Angular Signals)** : Le Bearer Token est maintenu dans un signal en mémoire vive et **jamais dans `localStorage` ni `sessionStorage`**.
- **Bénéfice Sécurité** : une faille XSS ne trouve aucun jeton dans le stockage persistant du navigateur, et le jeton disparaît avec l'onglet. (Un script exécuté dans la page peut encore utiliser la session tant qu'elle est ouverte.)
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

| Domaine | Mécanisme de Contrôle & Enforcement |
|---|---|
| **Architecture Hexagonale / En Couches** | ArchUnit (`ArchitectureTest.java`) : Domaine pur, découplé de tout framework |
| **Parité Base de Données (2 moteurs)** | Flyway multi-dialectes + Testcontainers sur PostgreSQL et MySQL (`SchemaParityIntegrationTest`) |
| **Verrouillage Dépendances (Supply Chain)** | Gradle dependency locking (`gradle.lockfile`), Git pre-commit hook, SBOM Syft, Grype, Sigstore |
| **Déterminisme des Fingerprints** | Séparateur NUL (`\0`) évitant les collisions avec `\|` (`IssueFingerprintTest`) |
| **Conformité Réglementaire** | 24 contrôles techniques sur NIS 2 / DORA / ISO 27001 / PCI-DSS / EU CRA / SOC 2, et un paquet de preuves signé |
| **Supervision Temps Réel** | Centre de contrôle des agents, suivi des scans en direct et file d'attente |

---

## 5. Recommandations Implémentées & Prochaines Évolutions

1. **Verrouillage Automatique des Dépendances au Commit** :
   - ✅ *Réalisé* : Mise en place du hook Git `.githooks/pre-commit` régénérant automatiquement les write-locks Gradle et le `package-lock.json`.
2. **Supervision Temps Réel de la File d'Analyse** :
   - ✅ *Réalisé* : Tableau de bord KPI et suivi direct des scans en cours et en attente sur `/agents`.
3. **Priorisation par Exploitabilité (FIRST.org EPSS & CISA KEV)** :
   - ✅ *Réalisé* : Modèle de calcul croisant CVSS, EPSS (probabilité & percentile 30j) et catalogue CISA KEV sur l'écran `/epss`. Il n'a pas de terme d'atteignabilité : il n'y a pas d'analyse de graphe d'appels, et le multiplicateur et la clause du palier supérieur qui lisaient la colonne toujours `UNKNOWN` ont été retirés, avec la carte et la colonne d'atteignabilité de l'écran.
4. **Persistance Sécurisée de Session (Production)** :
   - 🔄 *Évolution future* : Support optionnel de cookies de session `HttpOnly; SameSite=Strict` pour les déploiements requérant une persistance au rafraîchissement complet F5.

