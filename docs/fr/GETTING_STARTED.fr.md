# Guide de Démarrage Rapide — Zanshin

Ce guide décrit l'installation, la configuration et le lancement de Zanshin en local ou en production.

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
cd zanshin-java && ./gradlew build
```

---

## 3. Configuration des Variables d'Environnement

Créez un fichier `.env` ou exportez les variables suivantes :

```bash
# Clé de chiffrement AES-256 (32 octets encodés en base64)
export ZANSHIN_ENCRYPTION_KEY=$(openssl rand -base64 32)

# Base de données (par défaut PostgreSQL ou SQLite)
export ZANSHIN_DB_URL=jdbc:postgresql://localhost:5432/zanshin
export ZANSHIN_DB_USER=zanshin
export ZANSHIN_DB_PASSWORD=secret

# Identifiants de démarrage (SUPERUSER initial)
export ZANSHIN_BOOTSTRAP_USERNAME=admin
export ZANSHIN_BOOTSTRAP_PASSWORD=SuperSecretPassword123!
```

---

## 4. Gestion du Schéma & Migrations (Flyway)

Le schéma est géré par **Flyway** (`src/main/resources/db/migration/{vendor}/`).
- À chaque démarrage, Flyway applique automatiquement les migrations SQL natives nécessaires.
- Hibernate est configuré en mode `ddl-auto: validate` pour garantir que les entités correspondent strictement au schéma.

---

## 5. Lancement de l'Application

```bash
# Lancement de l'API Backend (Port 8000)
cd zanshin-java && ./gradlew :zanshin-core:bootRun

# Lancement de l'Interface Angular (Port 4200)
npm --workspace @zanshin/frontend start
```

Accédez ensuite à l'interface sur `http://localhost:4200`.
Connectez-vous avec l'utilisateur `admin` et changez le mot de passe initial.

---

## 6. Analyse de Sécurité assistée par IA (Optionnel)

Zanshin permet d'activer une revue de code assistée par LLM local via [Ollama](https://ollama.com) :
```bash
export ZANSHIN_AI_REVIEW_ENABLED=true
export ZANSHIN_AI_REVIEW_URL=http://localhost:11434
export ZANSHIN_AI_REVIEW_MODEL=llama3.2
```
