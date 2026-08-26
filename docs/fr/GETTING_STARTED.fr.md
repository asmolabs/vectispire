# Guide de Démarrage Rapide — Vectispire

Ce guide décrit l'installation, la configuration et le lancement de Vectispire en local ou en production.

---

## 1. Prérequis

- **Java** : JDK 25 (ou compatible JDK 21+ avec Gradle).
- **Node.js** : Node LTS 24 (Angular 21 refuse Node 25).
- **Docker** : Nécessaire pour l'exécution des conteneurs d'analyse (Syft, Grype, Semgrep, Gitleaks).
- **Base de données** : PostgreSQL (recommandé en production), MySQL, MariaDB ou SQLite (développement/embarqué).

---

## 2. Installation des dépendances

```bash
# Dépendances frontend
npm ci

# Compilation backend et vérification
cd vectispire-java && ./gradlew build
```

---

## 3. Configuration des Variables d'Environnement

Créez un fichier `.env` ou exportez les variables suivantes :

```bash
# Clé de chiffrement AES-256 (32 octets encodés en base64)
export ENCRYPTION_KEY=$(openssl rand -base64 32)

# Base de données (par défaut PostgreSQL ou SQLite)
export VECTISPIRE_DB_URL=jdbc:postgresql://localhost:5432/vectispire
export VECTISPIRE_DB_USER=vectispire
export VECTISPIRE_DB_PASSWORD=secret

# Identifiants de démarrage (SUPERUSER initial)
export VECTISPIRE_BOOTSTRAP_USERNAME=admin
export VECTISPIRE_BOOTSTRAP_PASSWORD=SuperSecretPassword123!
```

---

## 4. Gestion du Schéma & Migrations (Flyway)

Le schéma est géré par **Flyway** (`src/main/resources/db/migration/{vendor}/`).
- À chaque démarrage, Flyway applique automatiquement les migrations SQL natives nécessaires.
- Hibernate est configuré en mode `ddl-auto: validate` pour garantir que les entités correspondent strictement au schéma.

---

## 5. Lancement de l'Application

```bash
# Lancement de l'API Backend (Port 3180 pour le proxy Angular de développement)
cd vectispire-java && ./gradlew :vectispire-core:bootRun --args='--server.port=3180'

# Lancement de l'Interface Angular (Port 4280)
npm --workspace @vectispire/frontend start
```

Accédez ensuite à l'interface sur `http://localhost:4280` (le proxy redirige `/api` vers `http://localhost:3180`).
Connectez-vous avec l'utilisateur `admin` et changez le mot de passe initial.

---

## 6. Analyse de Sécurité assistée par IA (Optionnel)

Vectispire permet d'activer une revue de code assistée par LLM local via [Ollama](https://ollama.com) :
```bash
export VECTISPIRE_AI_REVIEW_ENABLED=true
export VECTISPIRE_AI_REVIEW_URL=http://localhost:11434
export VECTISPIRE_AI_REVIEW_MODEL=llama3.2
```

---

## 7. Déploiement Conteneurisé avec Docker & Docker Compose

Pour exécuter la suite complète (Base PostgreSQL + Control Plane Vectispire + Agent optionnel) en une seule commande :

```bash
# Copier et ajuster les variables d'environnement
cp .env.example .env

# Lancer la stack (PostgreSQL + Vectispire Control Plane sur http://localhost:3180)
docker compose up -d

# Lancer avec un agent distant déporté (profile with-agent)
docker compose --profile with-agent up -d
```

**Construction des images Docker personnalisées :**
```bash
# Image Control Plane (Backend + Frontend intégré)
npm run docker:build          # ou docker build -t vectispire:latest .

# Image Agent distant déporté
npm run docker:build:agent    # ou docker build -f Dockerfile.agent -t vectispire-agent:latest .
```

---

## 8. Documentation des APIs REST

- **Référence Complète** : Consultez la [Documentation de référence des APIs REST](api/rest_api_reference.md) pour les détails sur l'authentification (`Bearer JWT`, `X-API-Key`, `X-Agent-Key`) et la liste de toutes les routes.
- **Swagger UI en Mode Développement** :
  Par défaut, Swagger UI est désactivé en production. Vous pouvez l'activer en environnement local avec :
  ```bash
  export VECTISPIRE_SWAGGER_UI_ENABLED=true
  export VECTISPIRE_API_DOCS_ENABLED=true
  ```
  Accédez ensuite à `http://localhost:3180/swagger-ui.html`.

---

## 9. Guides d'Intégration

- [Intégration CI/CD & Outil CLI (`vectispire-cli`)](CI_CD_INTEGRATION.fr.md) — Blocage des builds par Quality Gate (GitLab CI, GitHub Actions, Bitbucket, Jenkins).
- [Ticketing Bidirectionnel](TICKETING_INTEGRATION.fr.md) — Synchronisation automatique des issues avec Jira, GitLab, GitHub et ServiceNow.
- [Alertes et Notifications](NOTIFICATIONS_INTEGRATION.fr.md) — Intégration en temps réel avec Discord, Slack et Microsoft Teams.
- [Visualiseur de Chemins d'Attaque](ATTACK_PATH_VISUALIZER.fr.md) — Corrélation des scénarios d'exploitation (Ingress &rarr; API &rarr; RCE &rarr; Secret/DB).

