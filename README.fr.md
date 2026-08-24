# Vectispire — Plateforme de Gestion de la Posture de Sécurité Logicielle (ASPM)

Vectispire est une plateforme moderne de sécurité applicative (ASPM / SecOps) conçue en **Spring Boot 4.1 / JDK 25** pour le backend et en **Angular 21** pour le frontend.

---

### Pourquoi le nom "Vectispire" ?

Le nom **Vectispire** reflète deux principes fondamentaux de la gouvernance de la chaîne de livraison logicielle :

- **`Vectis`** *(latin pour Levier de verrouillage & Verrou de sécurité)* : La plateforme agit comme le **verrou de sécurité et le garde-fou politique** du cycle de livraison logiciel. Elle applique des Quality Gates infranchissables, signe les attestations in-toto, génère des signatures DSSE Cosign, des SBOMs déterministes, des déclarations VEX opposables (CSAF 2.0, OpenVEX, CycloneDX) et un journal d'audit scellé par cryptographie.
- **`Spire`** *(la Tour de Guet & Posture globale)* : La plateforme offre un **point de vue panoramique élevé (ASPM)** sur l'ensemble du patrimoine applicatif — cartographie multi-niveaux du graphe de dépendances, calcul du rayon d'impact (*Blast Radius*), matrice des conflits de licences copyleft, et mesure de la vitesse de remédiation (MTTR) sur tous les dépôts et parcs de conteneurs.

---

## 🚀 Fonctionnalités Principales

- **Analyse Multi-Scanners Unifiée** :
  - **SBOM & Dépendances** : Syft et Grype.
  - **Détection de Secrets** : Gitleaks.
  - **Sécurité de l'Infrastructure (IaC)** : Checkov.
  - **Analyse Statique (SAST)** : Semgrep OSS.
  - **Revue de Code IA (Optionnelle)** : Intégration locale Ollama (Llama, etc.).
- **Triage & VEX Natif** : Triage fin des vulnérabilités avec justification et date d'expiration.
- **Portabilité Multi-Base de Données** : Support complet et validé par tests de **PostgreSQL**, **MySQL**, **MariaDB** et **SQLite** via migrations **Flyway**.
- **Sécurité de Bout en Bout** :
  - Chiffrement AES-256-GCM des clés privées et secrets au repos.
  - Journal d'audit infalsifiable avec scellement cryptographique par chaîne de hachage.
  - Exécution des scanners en conteneurs éphémères durcis (`cap_drop: ALL`, `read-only`, `network: none`).
  - Architecture isolée pour les agents distants (communication HTTP long-polling sans accès direct à la base de données).

---

## 🛠️ Démarrage Rapide

### Prérequis
- Node.js LTS 24
- Java JDK 25 (ou JDK 21+)
- Docker

```bash
# Installation des dépendances
npm ci

# Lancement de l'API Backend (Port 3180)
cd vectispire-java && ./gradlew :vectispire-core:bootRun --args='--server.port=3180'

# Lancement du Frontend Angular (Port 4280)
npm --workspace @vectispire/frontend start
```

### Pages et Navigation

| Route | Description |
|---|---|
| `/dashboard` | Vue d'ensemble de la posture et métriques globales |
| `/repositories` | Dépôts Git suivis, historique des analyses, détails des findings |
| `/security` | Verdicts des politiques de sécurité (Gate) par cible |
| `/quality` | Vulnérabilités de qualité de code SAST groupées par règle |
| `/issues` | Backlog global des vulnérabilités et interface de triage VEX |
| `/containers` | Images de conteneurs analysées |
| `/ssh-keys` | Gestion des clés SSH chiffrées pour le clonage de dépôts privés |
| `/api-keys` | Clés d'API programmatiques (hachage Argon2id) |
| `/agents` | Gestion des agents d'analyse distribués |
| `/settings` | Paramètres généraux, exclusions de licences, intégrations |
| `/users` | Gestion des comptes utilisateurs et rôles RBAC |
| `/teams` | Gestion des équipes et contrôle de visibilité |
| `/audit-log` | Journal d'audit sécurisé des actions sensibles |
| `/history` | Historique détaillé et exports PDF / CSV / SARIF / OpenVEX |

---

## 📚 Documentation

- [Guide de Démarrage](docs/fr/GETTING_STARTED.fr.md) (`docs/en/GETTING_STARTED.md` en anglais)
- [Documentation Technique](docs/fr/TECHNICAL_DOCUMENTATION.fr.md) (`docs/en/TECHNICAL_DOCUMENTATION.md` en anglais)
- [Rotation des Secrets et Purge](docs/fr/ROTATION_AND_PURGE.fr.md) (`docs/en/ROTATION_AND_PURGE.md` en anglais)
- [Registre des Décisions d'Architecture (ADR)](docs/architecture/decisions/)
