# Guide de Démarrage Rapide — Vectispire

Ce guide décrit l'installation, la configuration et le lancement de Vectispire en local ou en production.

---

## 1. Prérequis

- **Java** : JDK 25 (ou compatible JDK 21+ avec Gradle).
- **Node.js** : Node LTS 24 (Angular 21 refuse Node 25).
- **Docker** : Nécessaire pour l'exécution des conteneurs d'analyse (Syft, Grype, Semgrep, Gitleaks).
- **Base de données** : MySQL (défaut) ou PostgreSQL. SQLite est la fixture des tests et ne démarre pas l'application packagée — voir la [décision 0014](../architecture/fr/decisions/0014-two-engines-and-a-test-fixture.md).

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

# Base de données (MySQL par défaut ; l'URL choisit le moteur)
export VECTISPIRE_DB_URL=jdbc:postgresql://localhost:5432/vectispire
export VECTISPIRE_DB_USER=vectispire
export VECTISPIRE_DB_PASSWORD=secret

# Identifiants de démarrage (SUPERUSER initial)
export VECTISPIRE_BOOTSTRAP_USERNAME=admin
export VECTISPIRE_BOOTSTRAP_PASSWORD=SuperSecretPassword123!

# Personnalisation de marque (White-labeling dans le header, rapports & exports)
export VECTISPIRE_BRAND_NAME=Vectispire
export VECTISPIRE_GITLAB_URL=https://github.com/asmolabs/vectispire
```

---

## 4. Base de données

MySQL 8 par défaut — le moteur que livre `docker-compose.yml` et celui vers lequel pointe
`VECTISPIRE_DB_URL` quand rien ne la surcharge. PostgreSQL est l'autre moteur supporté ; le moteur
est lu depuis l'URL et il n'existe aucun réglage de dialecte séparé.

```bash
docker run -d --name vectispire-db -p 3306:3306 \
  -e MYSQL_ROOT_PASSWORD=root -e MYSQL_DATABASE=vectispire \
  -e MYSQL_USER=vectispire -e MYSQL_PASSWORD=vectispire \
  mysql:8
```

Pour PostgreSQL à la place, pointez `VECTISPIRE_DB_URL` dessus — rien d'autre ne change :

```bash
docker run -d --name vectispire-db -p 5432:5432 \
  -e POSTGRES_USER=vectispire -e POSTGRES_PASSWORD=vectispire -e POSTGRES_DB=vectispire \
  postgres:16-alpine
# VECTISPIRE_DB_URL=jdbc:postgresql://localhost:5432/vectispire
```

Le schéma appartient aux **migrations Flyway**, appliquées au démarrage :

```bash
# Flyway applique les migrations au démarrage — il n'y a aucune commande séparée à lancer.
# Un nouveau changement est un nouveau script dans vectispire-core/src/main/resources/db/migration/<dialecte>/.
```

`ddl-auto` vaut `validate`, délibérément : un schéma synthétisé depuis les entités n'est pas
celui que la production recevra, et tester contre lui laisserait passer une migration fautive.

Il n'existe aucune page d'auto-inscription : le premier compte vient donc des variables
d'amorçage — définissez-les avant le premier démarrage et le SUPERUSER est créé tant que la
table des utilisateurs est vide :

```bash
VECTISPIRE_BOOTSTRAP_USERNAME=admin
VECTISPIRE_BOOTSTRAP_PASSWORD=<au moins 8 caractères>
```

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

## 6. Optionnel : revue de code par IA (Ollama)

Une option supplémentaire, désactivée par défaut : un LLM local, exécuté via [Ollama](https://ollama.com), qui relit le code source avec une invite « architecte sécurité », en complément léger de Grype/gitleaks/checkov — pas en remplacement. Activée, elle tourne automatiquement sur les analyses de dépôts ; son résultat narratif et ses constats normalisés (sévérité/titre/fichier) apparaissent dans la boîte de détail de l'analyse. Voir la documentation de `AiReviewService` et le §4 de [`TECHNICAL_DOCUMENTATION.fr.md`](TECHNICAL_DOCUMENTATION.fr.md) pour le câblage.

Ollama s'exécute en natif ou dans Docker — Vectispire lui parle en HTTP simple dans les deux cas (`ai_review_ollama_url`, par défaut `http://localhost:11434`), et le choix ne concerne que la façon dont Ollama lui-même tourne. Il n'y a délibérément aucun réglage pour cela : l'endroit où Ollama tourne ne change rien à la manière dont Vectispire l'appelle.

**Installation native (recommandée, en particulier sur Mac Apple Silicon)** — voir [ollama.com/download](https://ollama.com/download). Donne l'accélération GPU complète : Metal sur Apple Silicon, CUDA/ROCm sous Linux avec les bons pilotes.

```bash
ollama pull gemma4:12b-it-qat   # ~7,2 Go, ~9-10 Go de RAM/VRAM — défaut recommandé
ollama pull gemma4:e4b-it-qat   # ~6,1 Go, plus léger et plus rapide, qualité de revue moindre
```

**Docker** — plus simple à reproduire d'une machine à l'autre, mais sur **Mac Apple Silicon, Docker Desktop n'a aucun passage GPU/Metal** : le conteneur tourne donc sur CPU seul et l'inférence est nettement plus lente que l'application native. Sous Linux avec un GPU NVIDIA (+ nvidia-container-toolkit), l'accélération GPU reste possible dans le conteneur.

```bash
docker run -d --name ollama -p 11434:11434 -v ollama:/root/.ollama ollama/ollama
docker exec -it vectispire-ollama ollama pull gemma4:12b-it-qat
docker exec -it vectispire-ollama ollama pull gemma4:e4b-it-qat   # facultatif, alternative plus légère
```

(Ajouter `--gpus all` pour le passage NVIDIA sous Linux.)

Ensuite, depuis la page **Réglages** de Vectispire, section « Revue de code par IA » : activez la fonctionnalité, renseignez l'URL d'Ollama (par défaut `http://localhost:11434`, inchangée qu'Ollama tourne en natif ou en conteneur puisque celui-ci publie le même port sur l'hôte), et choisissez un modèle dans la liste — celle-ci est lue en direct depuis le `/api/tags` d'Ollama (ce que vous avez réellement tiré y apparaît), et non codée en dur. Si Ollama n'est pas encore joignable, la liste se rabat sur les deux modèles ci-dessus présentés comme suggestions plutôt que de rester vide.

**La configuration est en base, pas dans l'environnement.** Cette section a longtemps décrit trois
variables `VECTISPIRE_AI_REVIEW_*` qui n'existent nulle part dans le code : les suivre ne faisait
rien. Les réglages réels sont `ai_review_enabled`, `ai_review_ollama_url` et `ai_review_model`,
posés depuis l'interface — de sorte qu'un changement est audité et n'exige pas un redémarrage.

---

## 7. Déploiement Conteneurisé avec Docker & Docker Compose

> **Note de structure.** La version anglaise traite ce sujet en sous-section 5.1 plutôt qu'en
> section propre ; les deux documents couvrent le même contenu, la numérotation seule diffère à
> partir d'ici. Consigné pour qu'un écart de plan ne se lise pas comme une dérive de traduction.

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
cd vectispire-java && ./gradlew integrationTest    # démarre MySQL via testcontainers (-Pdialect= pour les autres)
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
  --certificate-identity "https://github.com/asmolabs/vectispire/.github/workflows/release.yml@refs/tags/v1.0.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  vectispire-1.0.0.jar
```

**Chaque partie de cette commande épingle quelque chose, et en retirer une seule rend l'essentiel
de ce pour quoi la signature existait.**

- `--certificate-identity` nomme le **fichier de workflow et le tag**, pas le dépôt. Ne
  correspondre qu'au dépôt accepterait une signature forgée par n'importe quel workflow que
  quiconque peut y ajouter, y compris un workflow ajouté dans une pull request.
- `--certificate-oidc-issuer` dit que l'identité vient du service de jetons OIDC de GitHub. Sans
  lui, une chaîne d'identité qui *ressemble* simplement à celle ci-dessus suffit.
- Le `--bundle` porte ensemble le certificat et la signature, donc il n'y a pas de second fichier
  à perdre ni d'étape à laquelle un certificat non vérifié serait substitué.

Remplacez le tag aux deux endroits pour vérifier une autre version : l'identité est par tag par
conception, de sorte qu'un paquet d'une release ne vérifie pas le fichier d'une autre.

**Vérifiez le SBOM de la même façon.** Il est signé par la même exécution, avec la même identité,
et c'est le fichier que vous lisez pour décider si un avis vous concerne — une liste de composants
non signée est une liste que n'importe qui peut réécrire :

```bash
cosign verify-blob \
  --bundle vectispire-1.0.0.cdx.json.cosign.bundle \
  --certificate-identity "https://github.com/asmolabs/vectispire/.github/workflows/release.yml@refs/tags/v1.0.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  vectispire-1.0.0.cdx.json
```

**Les releases signées avant le 27 août 2026 portent une autre identité.** Le projet est passé de
GitLab à GitHub, et l'identité du certificat nomme la forge, le dépôt et le fichier de workflow :
elle a donc changé avec la bascule. Pour un tag antérieur, vérifiez avec l'ancien couple :

```
  --certificate-identity "https://gitlab.com/asmolabs_be/vectispire//.gitlab-ci.yml@refs/tags/<tag>"
  --certificate-oidc-issuer https://gitlab.com
```

Qu'une identité ne soit pas portable d'une forge à l'autre est la propriété qui fonctionne, non un
défaut : une signature affirme *quel workflow dans quel dépôt* a produit le fichier, et cela a
changé.

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
- [Visualiseur de Chemins d'Attaque](ATTACK_PATH_VISUALIZER.fr.md) — Corrélation des scénarios d'exploitation (Ingress &rarr; API &rarr; RCE &rarr; Secret/DB).

