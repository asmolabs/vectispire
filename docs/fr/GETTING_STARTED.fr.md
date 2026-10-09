# Guide de Démarrage Rapide — Vectispire

Ce document couvre tout ce qu'il faut pour faire tourner Vectispire en local : prérequis, installation, configuration de l'environnement et démarrage de l'application. Pour les fonctionnalités, voir [`README.fr.md`](../../README.fr.md) ; pour l'architecture et le schéma de base de données, voir [`TECHNICAL_DOCUMENTATION.fr.md`](TECHNICAL_DOCUMENTATION.fr.md).

## 1. Prérequis

| Prérequis | Pourquoi |
|---|---|
| **JDK 25** | La chaîne d'outils Gradle de `vectispire-java/` demande la 25 ; nécessaire seulement pour construire ou lancer depuis les sources. |
| **Node 24 (LTS)** | Épinglé par `.nvmrc`. Angular 22 refuse Node 25. |
| **Docker**, démarré et joignable | Vectispire exécute Syft, Grype, gitleaks, checkov et Semgrep comme conteneurs éphémères à travers un démon Docker — dans la composition livrée, à travers un `docker-socket-proxy`, jamais la socket elle-même. C'est aussi ce qui démarre MySQL en développement et pour les campagnes de tests. |
| **MySQL 8** (défaut) **ou PostgreSQL** | Les deux sont pris en charge et exercés par la campagne d'intégration ; MySQL est ce vers quoi pointe `VECTISPIRE_DB_URL` quand elle n'est pas définie, et ce que livre `docker-compose.yml`. SQLite n'est pas pris en charge et ne fait plus partie de la construction ([ADR 0034](../architecture/fr/decisions/0034-mysql-replaces-the-sqlite-fixture.md)). En développement, un conteneur suffit. |
| **Git** | Pour cloner ce dépôt, et utilisé par Vectispire lui-même pour cloner ce qu'il analyse. |

## 2. Installation

```bash
git clone <url-de-ce-depot>
cd vectispire
npm ci                                  # l'interface ; respecte le fichier de verrouillage
cd vectispire-java && ./gradlew build   # le plan de contrôle : compilation, campagnes unitaires, d'architecture et HTTP (Docker requis)
```

`npm` ne couvre que l'interface. Le plan de contrôle est une construction Gradle dans
`vectispire-java/` et ne partage avec elle que le contrat HTTP.

## 3. Configuration

La plupart des réglages d'exécution — enrichissement, fin de vie, rétention, notifications,
licences, tracker, revue par modèle — sont en base et se modifient depuis la page **Paramètres**
une fois l'application lancée. Un réglage n'y apparaît qu'à partir du moment où un service le lit
réellement.

Les variables d'environnement qui comptent avant le premier démarrage :

| Variable | Défaut |
|---|---|
| `VECTISPIRE_DB_URL` | `jdbc:mysql://localhost:3306/vectispire` — une URL **JDBC** ; pour PostgreSQL, `jdbc:postgresql://localhost:5432/vectispire` |
| `VECTISPIRE_DB_USER` / `VECTISPIRE_DB_PASSWORD` | `vectispire` / vide |
| `ENCRYPTION_KEY` | *aucune* — l'enregistrement d'un secret est refusé tant qu'elle n'est pas définie. En production, préférez `ENCRYPTION_KEY_FILE` |
| `ENCRYPTION_KEY_FILE` | *aucune* — le chemin d'un fichier contenant la clé à la place, ce que monte un secret Docker ou Kubernetes. Tient la valeur hors de `/proc/<pid>/environ`, de `docker inspect` et des journaux d'un orchestrateur. La définir *en même temps que* `ENCRYPTION_KEY` est refusé ; un chemin qui ne se résout pas arrête l'application plutôt que de la démarrer sans clé |
| `VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS` | *aucune* — d'anciennes clés séparées par des virgules, essayées pour le déchiffrement seulement |
| `VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS_FILE` | *aucune* — la même liste depuis un fichier, séparée par des virgules ou des retours à la ligne, pour qu'une rotation n'ait pas à remettre l'ancienne clé dans l'environnement |
| `VECTISPIRE_PASSWORD_LOGIN` | `true`. `false` délègue entièrement l'authentification au fournisseur d'identité — le second facteur est alors celui du royaume. Ignorée, bruyamment, quand aucun `VECTISPIRE_OIDC_ISSUER` n'est défini : elle ne laisserait aucun moyen d'entrer |
| `VECTISPIRE_AUDIT_MIRROR` | *aucune* — un chemin où chaque entrée d'audit est ajoutée comme une ligne JSON, hors de la base qu'elle surveille. Désactivé, le journal n'a qu'un exemplaire, et l'écran de vérification le dit |
| `VECTISPIRE_BRAND_NAME` | `Vectispire` — nom de l'entreprise ou de l'instance affiché dans l'en-tête, les rapports (PDF) et les exports (SARIF, VEX, CSAF) |
| `VECTISPIRE_GITLAB_URL` | `https://github.com/asmolabs/vectispire` — URL du dépôt amont affichée à côté de la mention « Powered by Vectispire » du pied de page. Le nom de la variable précède le passage à GitHub et est conservé parce qu'il fait partie de la réponse publique de personnalisation |

## 4. Base de données

MySQL 8 par défaut — le moteur que livre `docker-compose.yml` et celui vers lequel pointe
`VECTISPIRE_DB_URL` quand rien ne la surcharge. PostgreSQL est l'autre moteur supporté ; le moteur
est lu depuis l'URL et il n'existe aucun réglage de dialecte séparé.

```bash
docker run -d --name vectispire-db -p 127.0.0.1:3306:3306 \
  -e MYSQL_ROOT_PASSWORD=root -e MYSQL_DATABASE=vectispire \
  -e MYSQL_USER=vectispire -e MYSQL_PASSWORD=vectispire \
  mysql:8
```

Pour PostgreSQL à la place, pointez `VECTISPIRE_DB_URL` dessus — rien d'autre ne change :

```bash
docker run -d --name vectispire-db -p 127.0.0.1:5432:5432 \
  -e POSTGRES_USER=vectispire -e POSTGRES_PASSWORD=vectispire -e POSTGRES_DB=vectispire \
  postgres:16-alpine
# VECTISPIRE_DB_URL=jdbc:postgresql://localhost:5432/vectispire
```

Les deux se lient à `127.0.0.1`, pas à toutes les interfaces : `-p 3306:3306` publie le port sur
toutes les adresses de l'hôte — Docker écrit en outre ses propres règles de pare-feu, si bien qu'un
pare-feu de l'hôte ne l'arrête pas forcément — et ce sont des mots de passe de développement.
Vectispire, lancé sur la même machine, joint `localhost` dans les deux cas.

Le schéma appartient aux **migrations Flyway**, appliquées au démarrage :

```bash
# Flyway applique les migrations au démarrage — il n'y a aucune commande séparée à lancer.
# Un nouveau changement est un nouveau script : une fois dans vectispire-core/src/main/resources/db/migration/common/
# avec les placeholders de type quand seuls les types de colonne diffèrent, ou une fois par dialecte
# dans db/migration/<dialecte>/ quand la structure diverge (ADR 0027).
```

`ddl-auto` vaut `validate`, délibérément : un schéma synthétisé depuis les entités n'est pas
celui que la production recevra, et tester contre lui laisserait passer une migration fautive.

Il n'existe aucune page d'auto-inscription : le premier compte vient donc des variables
d'amorçage — définissez-les avant le premier démarrage et le SUPERUSER est créé tant que la
table des utilisateurs est vide :

```bash
VECTISPIRE_BOOTSTRAP_USERNAME=admin
VECTISPIRE_BOOTSTRAP_PASSWORD=<au moins 12 caractères>
```

## 5. Lancement de l'application

```bash
# Flyway met le schéma à jour au démarrage ; rien à lancer à la main.
cd vectispire-java && ./gradlew :vectispire-core:bootRun --args='--server.port=3180'   # API sur http://localhost:3180 (pour le proxy de développement Angular)
npm --workspace @vectispire/frontend start                                         # interface sur http://localhost:4280 (redirige /api vers 3180)
```

Le premier démarrage crée un SUPERUSER depuis `VECTISPIRE_BOOTSTRAP_USERNAME` et
`VECTISPIRE_BOOTSTRAP_PASSWORD` quand la table des utilisateurs est vide. Dès qu'un compte existe,
les deux variables sont ignorées. Ouvrez `http://localhost:4280`, connectez-vous avec ce compte et
changez son mot de passe.

### 5.1 Déploiement avec Docker Compose (tout-en-un)

La pile complète (MySQL + plan de contrôle + agent distant optionnel) se lance en une commande :

```bash
# 1. Copier et ajuster les variables d'environnement
cp .env.example .env

# 2. Lancer MySQL + le plan de contrôle Vectispire sur http://localhost:3180
docker compose up -d

# 3. Optionnel : lancer avec un agent distant dédié
docker compose --profile with-agent up -d
```

**Construire les images de conteneur :**
```bash
npm run docker:build          # ou docker build -t vectispire:latest .
npm run docker:build:agent    # ou docker build -f Dockerfile.agent -t vectispire-agent:latest .
```

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
docker run -d --name vectispire-ollama -p 127.0.0.1:11434:11434 -v ollama:/root/.ollama ollama/ollama
docker exec -it vectispire-ollama ollama pull gemma4:12b-it-qat
docker exec -it vectispire-ollama ollama pull gemma4:e4b-it-qat   # facultatif, alternative plus légère
```

`127.0.0.1` là encore, et pour une raison plus forte : l'API d'Ollama n'a **aucune
authentification**. Publiée sur toutes les interfaces, quiconque joint l'hôte peut y faire tourner
des modèles, en tirer de nouveaux et supprimer les vôtres.

(Ajouter `--gpus all` pour le passage NVIDIA sous Linux.)

Ensuite, depuis l'onglet **Paramètres → IA** de Vectispire, dans la carte **Revue IA** : activez la revue, renseignez l'URL d'Ollama (par défaut `http://localhost:11434`, inchangée qu'Ollama tourne en natif ou dans le conteneur ci-dessus, puisque celui-ci publie le même port sur la boucle locale de l'hôte), et nommez le modèle. **Tester la connexion** dit si Ollama répond à cette URL et si le modèle fait partie de ceux qu'il détient — lus en direct depuis le `/api/tags` d'Ollama, de sorte que ce que vous avez réellement tiré est ce qui compte.

**La configuration est en base, pas dans l'environnement.** Cette section a longtemps décrit trois
variables `VECTISPIRE_AI_REVIEW_*` qui n'existent nulle part dans le code : les définir ne faisait
rien. Les réglages réels sont `ai_review_enabled`, `ai_review_ollama_url` et `ai_review_model`,
posés depuis l'interface — de sorte qu'un changement est audité et n'exige pas un redémarrage.

## 7. Exécuter les tests

```bash
cd vectispire-java && ./gradlew build              # campagnes unitaires, d'architecture et HTTP
cd vectispire-java && ./gradlew integrationTest    # démarre MySQL via testcontainers (-Pdialect= pour les autres)
```

Les campagnes d'intégration démarrent leur propre base et **ne s'esquivent pas** quand elle
manque : une exécution sans Docker échoue bruyamment plutôt que de rendre un vert n'ayant rien
vérifié.

## 8. Vérifier une release

Chaque release porte le jar et son SBOM, le script de barrière CI `vectispire-gate.sh` et — à
partir de la version qui suit la 0.10.0 — la CLI `vectispire-cli.sh` ([Intégration CI/CD](CI_CD_INTEGRATION.fr.md#-obtenir-la-cli)),
chacun avec un paquet Sigstore vérifié de la même façon, et des images de conteneur signées — deux
jusqu'à la 0.10.0, trois à partir de la version qui la suit (voir plus bas). Vérifiez avant de lancer quoi que ce soit — un outil de sécurité pris sur parole est une
contradiction.

```bash
cosign verify-blob \
  --bundle vectispire-0.10.0.jar.cosign.bundle \
  --certificate-identity "https://github.com/asmolabs/vectispire/.github/workflows/release.yml@refs/tags/v0.10.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  vectispire-0.10.0.jar
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
  --bundle vectispire-0.10.0.cdx.json.cosign.bundle \
  --certificate-identity "https://github.com/asmolabs/vectispire/.github/workflows/release.yml@refs/tags/v0.10.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  vectispire-0.10.0.cdx.json
```

### Exécuter depuis les images publiées

Une release publie aussi ses images de conteneur, de sorte que rien n'a besoin d'être compilé
pour exécuter ce logiciel — le plan de contrôle et l'agent :

```bash
docker pull ghcr.io/asmolabs/vectispire:0.10.0
docker pull ghcr.io/asmolabs/vectispire-agent:0.10.0
```

À partir de la version qui suit la 0.10.0, une troisième est publiée à côté,
`ghcr.io/asmolabs/vectispire-report-demo` — le [plugin de rapport](../../docs-site/administration/report-plugins.fr.md)
de démonstration, signé, attesté et vérifié de la même façon. La 0.10.0 ne la porte pas.

**Vérifiez-les avant de les exécuter, et vérifiez par empreinte.** Un tag est un pointeur mutable :
signer `:0.10.0` ne dit rien de ce vers quoi `:0.10.0` pointera la semaine prochaine — c'est la
raison même pour laquelle chaque action de ce dépôt est épinglée par SHA :

```bash
DIGEST=$(docker buildx imagetools inspect ghcr.io/asmolabs/vectispire:0.10.0 \
           --format '{{.Manifest.Digest}}')

cosign verify \
  --certificate-identity "https://github.com/asmolabs/vectispire/.github/workflows/release.yml@refs/tags/v0.10.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "ghcr.io/asmolabs/vectispire@${DIGEST}"
```

Chaque image porte un SBOM CycloneDX sous forme d'attestation signée, et non de fichier posé à
côté — une liste de composants que n'importe qui peut remplacer ne prouve rien :

```bash
cosign verify-attestation --type cyclonedx \
  --certificate-identity "https://github.com/asmolabs/vectispire/.github/workflows/release.yml@refs/tags/v0.10.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "ghcr.io/asmolabs/vectispire@${DIGEST}" | jq -r '.payload' | base64 -d | jq '.predicate.components | length'
```

**Épinglez l'empreinte dans ce qui l'exécute.** `image: ghcr.io/asmolabs/vectispire@sha256:…` dans
un fichier compose ou un manifeste, c'est le déploiement qui correspond à ce que vous avez
vérifié ; `:latest`, c'est un déploiement qui change sous vos pieds sans diff.

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

### Vérifier la provenance de construction

Une signature dit *quel workflow* a produit un fichier. Chaque release postérieure à v0.9.0 porte
aussi une attestation de [provenance de construction SLSA](https://slsa.dev/spec/v1.0/provenance),
pour le jar et pour chaque image, qui dit *comment* : le dépôt, le **commit** vers lequel
pointait le tag au moment de la release, le workflow et l'exécuteur. Un tag peut être déplacé
après coup ; le commit consigné dans la provenance ne le peut pas, et c'est lui qu'il faut
extraire pour lire ou reconstruire le code qui a été livré.

La CLI de GitHub la vérifie, sans fichier à télécharger à côté de l'artefact :

```bash
gh attestation verify vectispire-<version>.jar \
  --repo asmolabs/vectispire \
  --signer-workflow asmolabs/vectispire/.github/workflows/release.yml \
  --source-ref refs/tags/v<version>

gh attestation verify oci://ghcr.io/asmolabs/vectispire@sha256:<empreinte> \
  --repo asmolabs/vectispire \
  --signer-workflow asmolabs/vectispire/.github/workflows/release.yml \
  --source-ref refs/tags/v<version>
```

L'image est désignée **par empreinte** — celle qu'indiquent les notes de release, ou celle que
renvoie `docker buildx imagetools inspect ghcr.io/asmolabs/vectispire:<version> --format '{{.Manifest.Digest}}'`
— pour la même raison que la signature. L'image de l'agent se vérifie de la même façon sous
`ghcr.io/asmolabs/vectispire-agent`, et celle du plugin de rapport de démonstration sous
`ghcr.io/asmolabs/vectispire-report-demo`.

`--repo` seul est la commande que GitHub documente, et elle ne suffit pas : elle accepte une
attestation produite par *n'importe quel* workflow du dépôt, sur n'importe quelle branche.
`--signer-workflow` la restreint au workflow de release et `--source-ref` au tag que vous
vouliez installer — les deux choses que `--certificate-identity` épingle dans les commandes
`cosign` ci-dessus. Ajoutez `--format json` pour lire la déclaration elle-même ; le commit se
trouve sous `buildDefinition.resolvedDependencies`.

La provenance s'ajoute à la signature et ne la remplace pas : v0.9.0 et les releases qui l'ont
précédée ont une signature et pas de provenance, et les commandes `cosign` ci-dessus restent le contrôle
que toutes les releases permettent.

## 9. Dépannage

- **Chaque étape d'une analyse échoue sur une erreur du client Docker** — `Connection refused`, ou `Permission denied` sur `/var/run/docker.sock` — et l'analyse se termine *en échec*, son détail listant chaque étape avec cette raison : le plan de contrôle ne joint aucun démon. Avec la composition livrée, cela ne devrait pas arriver — aucun conteneur Vectispire ne monte le socket, un `docker-socket-proxy` s'en charge, et `DOCKER_HOST` pointe dessus. Hors compose, directement contre un démon, l'utilisateur a bien besoin d'un accès à `/var/run/docker.sock` (sous Linux/macOS avec Docker Desktop) ; sous Linux, ajoutez-le au groupe `docker`.
- **La première analyse est lente** : le backend `docker` tire les images `anchore/syft`, `anchore/grype`, `zricethezav/gitleaks`, `bridgecrew/checkov` et `semgrep/semgrep` à la demande la première fois que chacune sert — les analyses suivantes réutilisent les images en cache.
- **« Identifiants invalides. » à la connexion** : soit les identifiants sont faux, soit le compte est désactivé — vérifiez sur la page **Utilisateurs** (nécessite un administrateur existant) ou interrogez directement la table `t_user`.
- **`ENCRYPTION_KEY` a changé et le déchiffrement des clés SSH échoue** : listez l'ancienne clé dans `VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS` (séparées par des virgules). Les valeurs existantes se déchiffrent alors de nouveau, et passent à la nouvelle clé à mesure qu'elles sont ré-enregistrées — la page **Clés SSH** marque les lignes qui dépendent encore de l'ancienne.
- **Une clé SSH affiche « Illisible » après une mise à niveau** : aucune clé configurée ne la lit, très probablement parce qu'elle est antérieure à toute `ENCRYPTION_KEY` et a été chiffrée avec la valeur par défaut qui était livrée dans ce dépôt. Cette valeur par défaut a été retirée. Sa moitié privée est publique : remplacez la paire de clés chez votre fournisseur git plutôt que d'essayer de la récupérer ; enregistrez la nouvelle depuis la page *Clés SSH* une fois `ENCRYPTION_KEY` définie. La [note d'incident d'août 2026](../analysis/fr/2026-08-06_incident_exposition_identifiants.fr.md) dit comment cette valeur par défaut est devenue publique.
- **« Tester la connexion » ne reçoit aucune réponse d'Ollama** : Ollama n'est pas joignable à l'URL configurée — vérifiez qu'il tourne (`ollama list` en natif, `docker ps` en conteneur) et que l'URL et le port correspondent, puis testez de nouveau depuis **Paramètres → IA**. S'il répond mais dit que le modèle n'est pas disponible, tirez ce modèle ou corrigez son nom.
- **La revue IA fonctionne mais paraît lente** : attendu si Ollama tourne dans Docker sur un Mac Apple Silicon (pas de passage GPU/Metal — inférence sur CPU seul). Passez à une installation native pour l'accélération GPU, ou utilisez le modèle plus léger `gemma4:e4b-it-qat`.

## 10. Documentation des APIs REST

- **Référence REST** : Consultez la [Documentation de référence des APIs REST](api/rest_api_reference.md) pour les schémas d'authentification — un jeton de session opaque, une clé d'agent ou une clé d'API d'intégration, chacun en `Authorization: Bearer`, avec `X-API-Key` accepté pour une clé —, une sélection commentée des routes et des exemples `curl`. Le contrat complet est le document OpenAPI, [`vectispire-angular/openapi.json`](../../vectispire-angular/openapi.json).
- **Swagger UI en Mode Développement** :
  Par défaut, Swagger UI est désactivé en production. Vous pouvez l'activer en environnement local avec :
  ```bash
  export VECTISPIRE_SWAGGER_UI_ENABLED=true
  export VECTISPIRE_API_DOCS_ENABLED=true
  ```
  Accédez ensuite à `http://localhost:3180/swagger-ui.html`.

---

## 11. Guides d'intégration

- [Intégration CI/CD & Outil CLI (`vectispire-cli`)](CI_CD_INTEGRATION.fr.md) — Blocage des builds par Quality Gate (GitLab CI, GitHub Actions, Bitbucket, Jenkins).
- [Ticketing Bidirectionnel](TICKETING_INTEGRATION.fr.md) — Synchronisation automatique des issues avec Jira, GitLab, GitHub et ServiceNow.
- [Alertes et Notifications](NOTIFICATIONS_INTEGRATION.fr.md) — Intégration en temps réel avec Discord, Slack et Microsoft Teams.
- [Visualiseur de Chemins d'Attaque](ATTACK_PATH_VISUALIZER.fr.md) — Corrélation des scénarios d'exploitation (Ingress &rarr; API &rarr; RCE &rarr; Secret/DB).

