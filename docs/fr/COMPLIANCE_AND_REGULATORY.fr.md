# Moteur de Calcul de la Conformité Réglementaire & Coffre-Fort de Preuves

Le sous-système de conformité réglementaire de Zanshin (`ComplianceEngine`, `ComplianceService`, `EvidenceVaultService`, `ComplianceReportPdf`) évalue automatiquement et de manière déterministe la posture de sécurité de votre organisation par rapport à cinq référentiels internationaux majeurs :

- **Directive NIS 2** (UE 2022/2555 — Gestion des risques cyber & Sécurité de la chaîne d'approvisionnement)
- **Règlement DORA** (UE 2022/2554 — Résilience opérationnelle numérique pour le secteur financier)
- **ISO/IEC 27001:2022** (Système de management de la sécurité de l'information — Contrôles de l'Annexe A)
- **PCI-DSS v4.0** (Standard de sécurité des données de l'industrie des cartes de paiement)
- **Cyber Resilience Act (EU CRA)** (Règlement européen sur la cyber-résilience des produits numériques)

---

## 1. Architecture de Conformité & Flux de Données

```mermaid
sequenceDiagram
    autonumber
    actor Auditeur as Auditeur / RSSI / SecOps
    participant UI as Interface Angular (/compliance)
    participant Ctrl as ComplianceController
    participant Svc as ComplianceService
    participant Engine as ComplianceEngine (Domaine Pur)
    participant Vault as EvidenceVaultService
    participant PDF as ComplianceReportPdf

    Auditeur->>UI: Consulter la conformité / Exporter le paquet d'audit
    UI->>Ctrl: GET /api/v1/compliance/summary
    Ctrl->>Svc: getSummary(allowedVisibility)
    Svc->>Svc: Agrégation de la posture (Gate, Scans, Issues, SLA, AuditChain)
    Svc->>Engine: evaluateAll(PostureInput)
    Engine-->>Svc: List<ComplianceEvaluation> (Scores & Contrôles)
    Svc-->>Ctrl: ComplianceSummary
    Ctrl-->>UI: Synthèse JSON & Statuts des 5 Référentiels

    opt Export Rapport PDF Exécutif
        UI->>Ctrl: GET /api/v1/compliance/export.pdf
        Ctrl->>PDF: render(Subject, Evaluations)
        PDF-->>Ctrl: Rapport PDF Exécutif byte[]
        Ctrl-->>Auditeur: zanshin-compliance-report.pdf
    end

    opt Export Paquet de Preuves Certifiées (ZIP)
        UI->>Ctrl: GET /api/v1/compliance/evidence-bundle.zip
        Ctrl->>Vault: generateEvidenceBundle(username)
        Vault-->>Ctrl: Archive ZIP scellée cryptographiquement
        Ctrl-->>Auditeur: zanshin-audit-evidence-bundle.zip
    end
```

---

## 2. Référentiels et Cartographie des Contrôles

| Référentiel | Code Contrôle | Titre du Contrôle | Catégorie d'Évaluation |
|---|---|---|---|
| **NIS 2** | `NIS2-ART21-VULN` | Traitement et remédiation des vulnérabilités | `VULNERABILITY_MANAGEMENT` |
| **NIS 2** | `NIS2-ART21-SUPPLY` | Sécurité de la chaîne d'approvisionnement & SBOM | `SUPPLY_CHAIN` |
| **NIS 2** | `NIS2-ART21-CRYPTO` | Cryptographie & Gestion des secrets | `SECRETS_MANAGEMENT` |
| **NIS 2** | `NIS2-ART21-GOV` | Gouvernance de sécurité & Blocage Gate | `GOVERNANCE` |
| **DORA** | `DORA-ART09-ICT` | Gestion des risques TIC & Tests continus | `VULNERABILITY_MANAGEMENT` |
| **DORA** | `DORA-ART11-THIRD` | Risque lié aux tiers & Gouvernance des dépendances | `SUPPLY_CHAIN` |
| **DORA** | `DORA-ART13-SECRETS` | Contrôle d'accès & Prévention des fuites de secrets | `SECRETS_MANAGEMENT` |
| **DORA** | `DORA-ART16-INCIDENT` | Piste d'audit & Rétention des preuves | `AUDIT_AND_LOGGING` |
| **ISO 27001** | `ISO-A.8.8` | Gestion des vulnérabilités techniques | `VULNERABILITY_MANAGEMENT` |
| **ISO 27001** | `ISO-A.8.28` | Pratiques de développement sécurisé | `SECURE_CODING` |
| **ISO 27001** | `ISO-A.8.9` | Sécurité des configurations & Infrastructure-as-Code | `INFRASTRUCTURE_AS_CODE` |
| **ISO 27001** | `ISO-A.5.15` | Contrôle d'accès & Protection des secrets | `SECRETS_MANAGEMENT` |
| **PCI-DSS** | `PCI-REQ-6.3` | Sécurité dans le cycle de développement logiciel | `SECURE_CODING` |
| **PCI-DSS** | `PCI-REQ-6.4` | Remédiation des vulnérabilités publiques | `VULNERABILITY_MANAGEMENT` |
| **PCI-DSS** | `PCI-REQ-6.5` | Protection contre les failles logicielles & secrets | `SECRETS_MANAGEMENT` |
| **PCI-DSS** | `PCI-REQ-10.2` | Mise en œuvre des journaux d'audit | `AUDIT_AND_LOGGING` |
| **EU CRA** | `CRA-ART11-NOTIF` | Notification ENISA / CSIRT sous 24h des failles exploitées (KEV/EPSS) | `VULNERABILITY_MANAGEMENT` |
| **EU CRA** | `CRA-ART10-SBOM` | Fourniture obligatoire d'un SBOM machine-readable | `SUPPLY_CHAIN` |
| **EU CRA** | `CRA-ART10-LIFECYCLE` | Traçabilité du support de sécurité et dates d'obsolescence (EOL) | `SUPPLY_CHAIN` |
| **EU CRA** | `CRA-ART10-VULN` | Remédiation continue et gestion des correctifs de sécurité | `VULNERABILITY_MANAGEMENT` |

---

## 3. Catégories d'Évaluation & Formules Mathématiques

### ① Gestion des Vulnérabilités (`VULNERABILITY_MANAGEMENT`)
Le score initial est de **100 points**, diminué par des pénalités cumulatives :
$$\text{Score} = \max\Big(0,\; 100 - P_{\text{critique}} - P_{\text{kev}} - P_{\text{sla}} - P_{\text{high}}\Big)$$

- **Failles Critiques ouvertes** : $-20\text{ pts}$ par faille (plafonné à $-50\text{ pts}$) :
  $$P_{\text{critique}} = \min(50,\, N_{\text{critique}} \times 20)$$
- **Vulnérabilités CISA KEV (exploitées activement)** : $-15\text{ pts}$ par faille (plafonné à $-30\text{ pts}$) :
  $$P_{\text{kev}} = \min(30,\, N_{\text{kev}} \times 15)$$
- **Dépassement d'échéance SLA (Overdue)** : $-10\text{ pts}$ par faille (plafonné à $-40\text{ pts}$) :
  $$P_{\text{sla}} = \min(40,\, N_{\text{overdue}} \times 10)$$
- **Backlog Sévérité Élevée** : Si $N_{\text{high}} > 5$, déduction forfaitaire de $-10\text{ pts}$.

---

### ② Sécurité de la Chaîne d'Approvisionnement & SBOM (`SUPPLY_CHAIN`)
Mesure le taux de cibles monitorées disposant d'un inventaire SBOM actif généré par Syft/Grype :
$$\text{Score} = \text{round}\left(\frac{N_{\text{cibles avec SBOM actif}}}{N_{\text{total cibles surveillées}}} \times 100\right)$$

---

### ③ Gestion des Secrets & Fuite d'Identifiants (`SECRETS_MANAGEMENT`)
- **0 secret détecté** : $\text{Score} = 100$, Statut = **CONFORME (`COMPLIANT`)**.
- **$\ge 1$ secret en clair** (jeton d'API, clé privée, mot de passe) :
  $$\text{Score} = \max(0,\; 100 - N_{\text{secrets}} \times 25)$$
  **Statut = NON CONFORME (`NON_COMPLIANT`) immédiat.** Tout secret non révoqué casse la conformité.

---

### ④ Pratiques de Développement Sécurisé / SAST (`SECURE_CODING`)
Évalue les anomalies de code source custom détectées par Semgrep :
- Si 0 anomalie SAST : $\text{Score} = 100$.
- Si anomalies présentes :
  $$\text{Score} = \max(20,\; 100 - N_{\text{sast}} \times 5)$$

---

### ⑤ Sécurité de l'Infrastructure-as-Code (`INFRASTRUCTURE_AS_CODE`)
Évalue les mauvaises configurations de déploiement (Terraform, Kubernetes, Dockerfile) :
- Si 0 anomalie IaC : $\text{Score} = 100$.
- Si anomalies présentes :
  $$\text{Score} = \max(30,\; 100 - N_{\text{iac}} \times 10)$$

---

### ⑥ Gouvernance de Sécurité & Politiques de Gate (`GOVERNANCE`)
Mesure le pourcentage de cibles respectant les règles bloquantes du Quality Gate :
$$\text{Score} = \text{round}\left(\frac{N_{\text{cibles passant le Gate}}}{N_{\text{total cibles}}} \times 100\right)$$

---

### ⑦ Traçabilité & Registre d'Audit Immuable (`AUDIT_AND_LOGGING`)
Vérifie l'intégrité cryptographique du chaînage HMAC-SHA256 du journal d'audit :
- **Chaîne intacte et validée** : $\text{Score} = 100$, Statut = **CONFORME (`COMPLIANT`)**.
- **Altération ou rupture détectée** : $\text{Score} = 0$, Statut = **NON CONFORME (`NON_COMPLIANT`)**.

---

## 4. Détermination des Statuts & Règle d'Étanchéité au Risque

### Seuils par Contrôle
$$\text{Statut Contrôle} = \begin{cases} 
\text{CONFORME (COMPLIANT)} & \text{si } \text{Score} \ge 90 \\
\text{PARTIEL (PARTIAL)} & \text{si } 60 \le \text{Score} < 90 \\
\text{NON CONFORME (NON\_COMPLIANT)} & \text{si } \text{Score} < 60 
\end{cases}$$

### Score Global du Référentiel
$$\text{Score Global} = \text{round}\left(\frac{1}{K} \sum_{i=1}^{K} \text{Score}(\text{Contrôle}_i)\right)$$

### Statut Global du Référentiel (Principe de Non-Dilution)
1. **NON CONFORME (`NON_COMPLIANT`)** : Dès qu'au moins **un contrôle** est non conforme ($N_{\text{non\_compliant}} > 0$) OU si le score global $< 70\%$.
2. **PARTIELLEMENT CONFORME (`PARTIAL`)** : Si aucun contrôle n'est en échec critique mais qu'au moins un contrôle est partiel ($N_{\text{partial}} > 0$) OU si le score global $< 95\%$.
3. **CONFORME (`COMPLIANT`)** : Uniquement si **100% des contrôles sont conformes** ET score global $\ge 95\%$.

---

## 5. Coffre-Fort de Preuves d'Audit (Evidence Vault)

Zanshin produit des paquets de preuves directement opposables aux auditeurs externes :

1. **Rapport PDF Exécutif (`/api/v1/compliance/export.pdf`)** :
   - Synthèse de la posture, scores par référentiel, détail des 20 contrôles et plan de remédiation priorisé.
2. **Paquet de Preuves Certifié (`/api/v1/compliance/evidence-bundle.zip`)** :
   - `manifest.json` : Empreintes SHA-256 de chaque artefact de preuve inclus.
   - `01_compliance_frameworks.json` : Évaluations continues des 5 référentiels (NIS 2, DORA, ISO 27001, PCI-DSS, EU CRA).
   - `02_immutable_audit_log.jsonl` : Journal d'audit scellé HMAC-SHA256.
   - `03_triage_and_exemptions.json` : Registre des décisions de triage et approbations 4-yeux.
   - `04_in_toto_attestation.json` : Attestations cryptographiques in-toto de conformité de build.
   - `05_openvex_advisory.json` : Avis VEX OpenVEX v0.2.0 (conformité EU CRA / EO 14028).
   - `06_csaf_2_0_vex.json` : Avis standardisé OASIS CSAF 2.0 (ANSSI / BSI / CISA).
   - `07_license_compliance.json` : Inventaire des licences et analyse de risque copyleft.

---

## 6. Interopérabilité VEX & Échange B2B (OpenVEX & CSAF 2.0)

### Ingestion VEX Amont (*Upstream Suppression Cascade*)
Zanshin permet d'ingérer automatiquement les avis VEX officiels publiés par les éditeurs tiers ou mainteneurs open-source :
- **Endpoint API** : `POST /api/v1/vex/ingest`
- **Interface Web** : Bouton `Importer VEX` sur `/compliance`.
- **Comportement** : Lorsqu'un éditeur publie une déclaration `not_affected` (ex: code vulnérable non compilé ou mitigation en ligne), Zanshin classe automatiquement les CVEs correspondantes dans le parc avec traçabilité d'audit (`origin: upstream_vex`).

### Export Standardisé OASIS CSAF 2.0
En complément d'OpenVEX, Zanshin génère des avis de sécurité au format **OASIS CSAF 2.0 (profil VEX)** :
- `GET /api/v1/csaf/scans/{scanId}/csaf.json` : Avis CSAF par scan de release.
- `GET /api/v1/csaf/aggregate.json` : Avis CSAF agrégé de l'ensemble du parc applicatif.

---

## 7. Gouvernance des Dérogations : Principe des "Quatre Yeux" (4-Eyes Workflow)

Pour satisfaire aux exigences strictes de DORA (Art. 9/13), NIS 2 et ISO 27001 (A.8.8) sur les dérogations et acceptations de risques :

1. **Rôle `SECURITY_CHAMPION`** :
   - Délégué sécurité au sein des équipes de développement (`administrative = false`, `globalSecurityScope = false`).
   - Habilité à valider et approuver les dérogations techniques (`canApproveTriage = true`).

2. **Statut `PENDING_APPROVAL` (En attente d'approbation)** :
   - Toute demande d'exemption (`not_affected` / `accepted_risk`) initiée par un développeur (`USER`) bascule automatiquement en `PENDING_APPROVAL`.
   - **Tant que la demande n'est pas approuvée, la Gate de déploiement CI/CD reste bloquante** (`isSettled() == false`).

3. **Double Validation & Piste d'Audit** :
   - L'approbation par un `SECURITY_CHAMPION`, `CISO` ou `ADMIN` consigne un événement d'audit scellé avec l'origine `"approval"`.
