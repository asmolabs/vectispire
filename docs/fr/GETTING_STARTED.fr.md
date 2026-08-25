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

## 8. Exécuter les tests

```bash
cd vectispire-java && ./gradlew build              # campagnes unitaires, d'architecture et HTTP
cd vectispire-java && ./gradlew integrationTest    # démarre PostgreSQL via testcontainers
```

Les campagnes d'intégration démarrent leur propre base et **ne s'esquivent pas** quand elle
manque : une exécution sans Docker échoue bruyamment plutôt que de rendre un vert n'ayant rien
vérifié.


## 9. Vérifier une release

Chaque release porte quatre fichiers : le jar, son SBOM, et un paquet Sigstore pour chacun.
Vérifiez avant de lancer quoi que ce soit — un outil de sécurité pris sur parole est une
contradiction.

```bash
cosign verify-blob \
  --bundle vectispire-1.0.0.jar.cosign.bundle \
  --certificate-identity "https://github.com/Asmo1973/Vectispire/.github/workflows/release.yml@refs/tags/v1.0.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  vectispire-1.0.0.jar
```

**Chaque partie de cette commande épingle quelque chose, et en retirer une seule rend l'essentiel
de ce pour quoi la signature existait.**

- `--certificate-identity` nomme le **fichier de workflow et le tag**, pas le dépôt. Ne
  correspondre qu'au dépôt accepterait une signature forgée par n'importe quel workflow que
  quiconque peut y ajouter, y compris un workflow ajouté dans une pull request.
- `--certificate-oidc-issuer` dit que l'identité vient du service de jetons de GitHub. Sans lui,
  une chaîne d'identité qui *ressemble* simplement à celle ci-dessus suffit.
- Le `--bundle` porte ensemble le certificat et la signature, donc il n'y a pas de second fichier
  à perdre ni d'étape à laquelle un certificat non vérifié serait substitué.

Remplacez le tag aux deux endroits pour vérifier une autre version : l'identité est par tag par
conception, de sorte qu'un paquet d'une release ne vérifie pas le fichier d'une autre.

Il n'y a **aucune clé de signature** — Sigstore sans clé signe avec l'identité OIDC du workflow
lui-même. C'est la propriété qui mérite d'être comprise : il n'existe aucune clé sous la garde de
quiconque, à voler, à faire tourner ou à justifier, et ce qu'une signature atteste est « ce
workflow, dans ce dépôt, sur ce tag ». Un secret de dépôt volé ne peut pas en produire une. Une
modification de `release.yml` lui-même le peut, et c'est pourquoi l'identité qu'un vérificateur
épingle inclut son chemin.

La même commande avec les noms de fichiers du SBOM vérifie le SBOM. Cela vaut la peine : un SBOM
est ce que quelqu'un donne à manger à son propre scanner, et un SBOM non signé est une liste de
dépendances que n'importe qui peut réécrire avant que vous ne la lisiez.

## 10. Dépannage

- **`docker.errors.DockerException` / permission refusée sur la socket Docker** : l'utilisateur qui exécute Vectispire a besoin d'un accès à la socket Docker (`/var/run/docker.sock` sous Linux/macOS avec Docker Desktop). Sous Linux, ajoutez l'utilisateur au groupe `docker` ou exécutez avec des privilèges suffisants.
- **La première analyse est lente** : le backend `docker` tire les images `anchore/syft`, `anchore/grype`, `zricethezav/gitleaks`, `bridgecrew/checkov` et `semgrep/semgrep` à la demande la première fois que chacune sert — les analyses suivantes réutilisent les images en cache.
- **« Identifiants incorrects ou compte inactif » à la connexion** : soit les identifiants sont faux, soit le drapeau `is_active` du compte est à `false` — vérifiez via `/users` (nécessite un administrateur existant) ou interrogez directement la table `user`.
- **`ENCRYPTION_KEY` a changé et le déchiffrement des clés SSH échoue** : listez l'ancienne clé dans `VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS` (séparées par des virgules). Les valeurs existantes se déchiffrent alors de nouveau, et passent à la nouvelle clé à mesure qu'elles sont ré-enregistrées — la page **Clés SSH** marque les lignes qui dépendent encore de l'ancienne.
- **Une clé SSH affiche « Illisible » après une mise à niveau** : aucune clé configurée ne la lit, très probablement parce qu'elle est antérieure à toute `ENCRYPTION_KEY` et a été chiffrée avec la valeur par défaut qui était livrée dans ce dépôt. Cette valeur par défaut a été retirée. Sa moitié privée est publique : remplacez la paire de clés chez votre fournisseur git plutôt que d'essayer de la récupérer ; [`ROTATION_AND_PURGE.fr.md`](ROTATION_AND_PURGE.fr.md) donne la procédure.
- **La liste déroulante des modèles de revue IA n'affiche que les deux suggestions** : Ollama n'est pas joignable à l'URL configurée — vérifiez qu'il tourne (`ollama list` en natif, `docker ps` en conteneur) et que l'URL et le port correspondent, puis cliquez sur « Rafraîchir la liste » sur la page Réglages.
- **La revue IA fonctionne mais paraît lente** : attendu si Ollama tourne dans Docker sur un Mac Apple Silicon (pas de passage GPU/Metal — inférence sur CPU seul). Passez à une installation native pour l'accélération GPU, ou utilisez le modèle plus léger `gemma4:e4b-it-qat`.

## 11. Documentation des APIs REST

- **Référence Complète** : Consultez la [Documentation de référence des APIs REST](api/rest_api_reference.md) pour les détails sur l'authentification (`Bearer JWT`, `X-API-Key`, `X-Agent-Key`) et la liste de toutes les routes.
- **Swagger UI en Mode Développement** :
  Par défaut, Swagger UI est désactivé en production. Vous pouvez l'activer en environnement local avec :
  ```bash
  export VECTISPIRE_SWAGGER_UI_ENABLED=true
  export VECTISPIRE_API_DOCS_ENABLED=true
  ```
  Accédez ensuite à `http://localhost:3180/swagger-ui.html`.

---

## 12. Guides d'Intégration

- [Intégration CI/CD & Outil CLI (`vectispire-cli`)](CI_CD_INTEGRATION.fr.md) — Blocage des builds par Quality Gate (GitLab CI, GitHub Actions, Bitbucket, Jenkins).
- [Ticketing Bidirectionnel](TICKETING_INTEGRATION.fr.md) — Synchronisation automatique des issues avec Jira, GitLab, GitHub et ServiceNow.
- [Alertes et Notifications](NOTIFICATIONS_INTEGRATION.fr.md) — Intégration en temps réel avec Discord, Slack et Microsoft Teams.

