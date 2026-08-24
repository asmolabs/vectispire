# Référence Complète de l'API REST Vectispire

Ce document constitue la référence officielle et exhaustive des interfaces de programmation REST exposées par le Control Plane **Vectispire** (v4.1.0).

---

## 🔒 Sécurité et Authentification

L'API Vectispire utilise trois mécanismes d'authentification selon le type d'appelant :

### 1. Jeton de Session Utilisateur (`Bearer JWT`)
* **En-tête** : `Authorization: Bearer <token>`
* **Utilisation** : Interface Web Angular, sessions d'utilisateurs interactives.
* **Obtention** : Via `POST /api/v1/auth/login` (avec support éventuel du 2FA/TOTP via `POST /api/v1/auth/mfa/verify`).

### 2. Clé d'Agent de Scan (`X-Agent-Key`)
* **En-tête** : `X-Agent-Key: <agent_key>`
* **Utilisation** : Protocoles d'agents distants distribués (`/api/v1/agent/**`).

### 3. Clé d'API Programmatique (`X-API-Key`)
* **En-tête** : `X-API-Key: <api_key>`
* **Utilisation** : Pipelines CI/CD (GitHub Actions, GitLab CI), intégrations SIEM et scripts d'automatisation.

---

## 🧭 Résumé des Endpoints

| Domaine | Méthode | Endpoint | Auth | Description |
|---|---|---|---|---|
| **Auth** | `POST` | `/api/v1/auth/login` | Public | Authentification utilisateur (identifiants / mot de passe). |
| **Auth** | `GET` | `/api/v1/auth/methods` | Public | Découverte des méthodes d'authentification (Password, SSO OIDC). |
| **Auth** | `POST` | `/api/v1/auth/session/exchange` | Public | Échange du cookie de redirection SSO contre un token de session. |
| **Auth** | `POST` | `/api/v1/auth/mfa/verify` | Public | Validation du challenge MFA / TOTP. |
| **Auth** | `POST` | `/api/v1/auth/mfa/setup` | Compte | Initialisation de la double authentification (génération du secret TOTP). |
| **Auth** | `POST` | `/api/v1/auth/mfa/enable` | Compte | Activation définitive du MFA après saisie d'un premier code. |
| **Auth** | `POST` | `/api/v1/auth/mfa/disable` | Compte | Désactivation du MFA avec validation par code. |
| **Surface d'Attaque** | `GET` | `/api/v1/attack-surface` | Compte | Synthèse globale de la surface d'attaque et routes à haut risque. |
| **Surface d'Attaque** | `DELETE` | `/api/v1/attack-surface` | Compte | Purge globale de l'inventaire des endpoints et contrats. |
| **Surface d'Attaque** | `GET` | `/api/v1/repositories/{id}/apis` | Compte | Inventaire des routes découvertes et contrats OpenAPI d'un dépôt. |
| **Surface d'Attaque** | `DELETE` | `/api/v1/repositories/{id}/apis` | Compte | Purge des endpoints et contrats d'un dépôt spécifique. |
| **Surface d'Attaque** | `GET` | `/api/v1/repositories/{id}/apis/export/openapi` | Compte | Export du schéma OpenAPI 3.0 synthétisé à partir du code source. |
| **Dépôts Git** | `GET` | `/api/v1/repositories` | Compte | Liste des dépôts surveillés avec état du dernier scan. |
| **Dépôts Git** | `POST` | `/api/v1/repositories` | Admin | Enregistrement d'un nouveau dépôt Git à analyser. |
| **Dépôts Git** | `PATCH` | `/api/v1/repositories/{id}` | Admin | Mise à jour des paramètres, branches, cron ou clés SSH d'un dépôt. |
| **Dépôts Git** | `POST` | `/api/v1/repositories/{id}/scan` | Admin | Déclenchement d'une analyse de sécurité immédiate sur le dépôt. |
| **Dépôts Git** | `DELETE` | `/api/v1/repositories/{id}` | Admin | Suppression d'un dépôt et purge en cascade de ses analyses. |
| **Scans** | `GET` | `/api/v1/scans` | Compte | Historique des analyses de sécurité avec filtres par cible. |
| **Scans** | `GET` | `/api/v1/scans/{id}` | Compte | Détail d'un scan et inventaire des constats (findings) observés. |
| **Scans** | `GET` | `/api/v1/scans/{id}/sbom` | Compte | Téléchargement du fichier SBOM (CycloneDX / SPDX) issu du scan. |
| **Vulnérabilités** | `GET` | `/api/v1/issues` | Compte | Consultation du backlog des vulnérabilités actives et résolues. |
| **Vulnérabilités** | `GET` | `/api/v1/issues/{id}` | Compte | Consultation détaillée d'une vulnérabilité et de son historique. |
| **Vulnérabilités** | `POST` | `/api/v1/issues/{id}/triage` | Lead/Admin | Décision de triage (Acceptation de risque, Faux-positif, Atténuation). |
| **Conformité** | `GET` | `/api/v1/compliance/summary` | Compte | Synthèse de conformité multi-référentiels (NIS2, ISO 27001, CRA, SOC2). |
| **Conformité** | `GET` | `/api/v1/compliance/frameworks/{fw}` | Compte | Évaluation détaillée des exigences pour un référentiel réglementaire. |
| **Conformité** | `GET` | `/api/v1/compliance/export.pdf` | Compte | Téléchargement du rapport exécutif de conformité au format PDF. |
| **Conformité** | `GET` | `/api/v1/compliance/evidence-bundle.zip` | Compte | Export du bundle d'audit scellé (preuves cryptographiques SHA-256). |
| **Scorecards** | `GET` | `/api/v1/scorecards/repositories/{id}` | Compte | Scorecard et note de posture de sécurité d'un dépôt. |
| **Scorecards** | `GET` | `/api/v1/scorecards/containers/{id}` | Compte | Scorecard et note de sécurité d'une image conteneur. |
| **Scorecards** | `GET` | `/api/v1/scorecards/global` | Compte | Scorecard global consolidé pour l'ensemble de l'organisation. |
| **Scorecards** | `GET` | `/api/v1/scorecards/repositories/{id}/badge.svg` | Public | Badge SVG dynamique pour affichage dans les fichiers README Git. |
| **Cryptographie** | `GET` | `/api/v1/crypto/public-key.pub` | Public | Clé publique ECDSA pour vérification des signatures Cosign / Sigstore. |

---

## 🛠️ Exemples d'Appels cURL

### 1. Connexion et Récupération du Jeton
```bash
curl -X POST "https://vectispire.example.com/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "MonSuperMotDePasse"}'
```

### 2. Déclenchement d'une Analyse de Dépôt
```bash
curl -X POST "https://vectispire.example.com/api/v1/repositories/1/scan" \
  -H "Authorization: Bearer <VOTRE_JWT_TOKEN>"
```

### 3. Consultation de la Surface d'Attaque
```bash
curl -X GET "https://vectispire.example.com/api/v1/attack-surface" \
  -H "Authorization: Bearer <VOTRE_JWT_TOKEN>"
```

### 4. Téléchargement du SBOM d'une Analyse
```bash
curl -X GET "https://vectispire.example.com/api/v1/scans/42/sbom" \
  -H "Authorization: Bearer <VOTRE_JWT_TOKEN>" \
  -o scan-42-sbom.json
```
