# 🔍 Guide & Prompt d'Audit / Audit & Analysis Prompt Guide

Ce document contient le prompt optimisé et les instructions méthodologiques pour relancer à tout moment une analyse complète et rigoureuse de la documentation, du code source, de la sécurité et de la conformité du projet **Vectispire**.

---

## 🎯 Prompt à Copier-Coller (Français)

```text
Effectue une analyse et un audit complet et approfondi du projet Vectispire en examinant l'ensemble des axes suivants :

1. 📚 Documentation & Architecture :
   - Conformité au modèle de Dossier d'Architecture de Bertrand Florat (docs/architecture/bflorat/ : 5 vues applicative, sécurité, dimensionnement, infrastructure, développement).
   - Modélisation C4 Structurizr DSL (docs/architecture/c4/workspace.dsl) et automatisation des diagrammes.
   - Modélisation formelle des menaces STRIDE DFD (docs/architecture/security/).
   - Registre des décisions d'architecture (ADR 0001 à 0016 dans docs/architecture/{en,fr}/decisions/), et la substance de chacune : une décision sans son raisonnement ne survit pas au renversement suivant.
   - Parité et synchronisation stricte bilingue (docs/fr/ et docs/en/).

2. 🛡️ Sécurité & Cryptographie ("Security by Design") :
   - Protection anti-déni de service et rate limiting en amont (LoginRateLimitFilter avec Token-Bucket / Bucket4j).
   - Authentification et gestion des identifiants (hachage Argon2id, TOTP MFA, SCIM 2.0, OIDC).
   - Chiffrement au repos AEAD (AES-256-GCM) et gestion des clés (VaultKmsProvider).
   - Isolation et sandboxing des conteneurs scanners (cap_drop: ALL, read-only, network: none, aucun socket Docker monté dans un scanner — le plan de contrôle et l'agent en ont une, et c'est toute la raison d'être du bac à sable — plafonds mémoire/PID/CPU, fichiers de config internes imposés).
   - Isolation étanche de l'agent distant vectispire-agent (zéro JDBC, zéro ENCRYPTION_KEY, communication sortante HTTP Long-Polling uniquement).
   - Journal d'audit scellé et chaîné SHA-256 avec détection d'intégrité (t_audit_log / AuditLogService.verify).
   - Workflow d'approbation collégiale (Four-Eyes Approval).

3. ⚙️ Qualité du Code & Architecture Logicielle :
   - Backend Spring Boot 4.1 / JDK 25 (records, sealed classes, pattern matching, types immutables).
   - Isolation des couches et contrôle ArchUnit (ArchitectureTest : domain <- scanning <- persistence <- repositories <- services <- api).
   - Résilience et prévention de la perte silencieuse de données (règle ADR 0007 : Optional.empty() pour les scanners en échec, jamais de liste vide []).
   - Portabilité et migration multi-SGBD Flyway sur 2 moteurs réels (PostgreSQL, MySQL (SQLite for tests)) avec validation de schéma stricte (ddl-auto: validate).
   - Moteur d'ingestion et déduplication intelligente multi-scanners (ex: Gitleaks) avec IssueFingerprint.
   - Frontend Angular 21 et couverture de tests end-to-end Playwright (vectispire-angular/e2e/).

4. 📋 Conformité Réglementaire & Standards :
   - Moteurs d'évaluation réglementaire intégrés (ComplianceService : CRA / Cyber Resilience Act, NIS 2, DORA, OWASP Top 10).
   - Support des formats de la chaîne d'approvisionnement logicielle (CycloneDX 1.6 avec VEX intégré, CSAF 2.0, OpenVEX, EPSS, reachability — SPDX n'est pas produit, voir ADR 0016).

Génère deux rapports d'analyse détaillés avec scores sur 10 et recommandations :
- Un rapport en français dans docs/analysis/fr/YYYY-MM-DD_HH_MM_SS_audit_approfondi_code_securite_doc.fr.md
- Un rapport en anglais dans docs/analysis/en/YYYY-MM-DD_HH_MM_SS_in_depth_code_security_doc_audit.en.md
- Met à jour docs/analysis/README.md pour référencer ces nouveaux rapports.
```

---

## 🇬🇧 Copy-Paste Prompt (English)

```text
Perform a comprehensive, in-depth evaluation and security audit of the Vectispire project across the following areas:

1. 📚 Documentation & Architecture:
   - Compliance with the Bertrand Florat Architecture Model (docs/architecture/bflorat/: 5 self-contained views for application, security, dimensioning, infrastructure, and development).
   - C4 Structurizr DSL architecture-as-code modeling (docs/architecture/c4/workspace.dsl) and automated diagram generation.
   - Formal STRIDE DFD threat modeling (docs/architecture/security/).
   - Architectural Decision Records registry (ADR 0001 through 0016 in docs/architecture/{en,fr}/decisions/), and the substance of each: a decision without its reasoning does not survive the next reversal.
   - Strict bilingual parity and synchronization across French and English trees (docs/fr/ and docs/en/).

2. 🛡️ Security & Cryptography ("Security by Design"):
   - Upstream Anti-DoS and brute-force token-bucket rate limiting (LoginRateLimitFilter with Bucket4j).
   - Identity & Authentication controls (Argon2id hashing, TOTP MFA, SCIM 2.0, OIDC group sync).
   - AEAD Encryption at rest (AES-256-GCM) and Key Management (VaultKmsProvider).
   - Hardened scanner container sandboxing (cap_drop: ALL, read-only mounts, network: none, no Docker socket inside a scanner — the control plane and the agent hold one, which is the whole reason the sandbox matters — memory/PID/CPU ceilings, enforced server-side config).
   - Watertight remote agent isolation in vectispire-agent (zero JDBC drivers, zero ENCRYPTION_KEY, outbound HTTP Long-Polling only).
   - Sealed, tamper-evident SHA-256 hash-chained audit log (t_audit_log / AuditLogService.verify).
   - Dual-authorization workflow (Four-Eyes Approval).

3. ⚙️ Code Quality & Software Architecture:
   - Backend Spring Boot 4.1 / JDK 25 modern patterns (records, sealed classes, pattern matching, immutable domain).
   - Enforced architectural layering via ArchUnit (ArchitectureTest: domain <- scanning <- persistence <- repositories <- services <- api).
   - Resilience against silent data loss (ADR 0007: Optional.empty() on scanner failures, never empty list []).
   - Multi-engine Flyway migrations verified on 2 databases (PostgreSQL, MySQL (SQLite for tests)) with strict validation (ddl-auto: validate).
   - Multi-scanner ingestion and deduplication engine (e.g., Gitleaks) via IssueFingerprint.
   - Frontend Angular 21 and automated Playwright E2E test suites (vectispire-angular/e2e/).

4. 📋 Regulatory & Standards Compliance:
   - Built-in regulatory engines (ComplianceService: EU CRA / Cyber Resilience Act, NIS 2, DORA, OWASP Top 10).
   - Software supply chain interoperability (CycloneDX 1.6 with embedded VEX, CSAF 2.0, OpenVEX, EPSS, reachability — SPDX documents are not produced, see ADR 0016).

Generate two synchronized in-depth audit reports with domain scores and actionable recommendations:
- French report in docs/analysis/fr/YYYY-MM-DD_HH_MM_SS_audit_approfondi_code_securite_doc.fr.md
- English report in docs/analysis/en/YYYY-MM-DD_HH_MM_SS_in_depth_code_security_doc_audit.en.md
- Update docs/analysis/README.md to reference the generated reports.
```

---

## 📌 Structure Attendue des Livrables

Chaque analyse exécutée doit produire :
1. **Un tableau récapitulatif des notes** (sur 10) par domaine (Documentation, Sécurité, Code, Conformité).
2. **Une analyse détaillée par section** avec renvois clairs vers les fichiers de code et d'architecture.
3. **Une section de recommandations concrètes et priorisées**.
4. **La mise à jour de l'index bilingue** dans [`docs/analysis/README.md`](docs/analysis/README.md).
