# Guide d'Intégration CI/CD & Outil CLI Vectispire (`vectispire-cli`)

Ce guide explique comment intégrer **Vectispire** au cœur de vos pipelines d'intégration continue (GitLab CI, GitHub Actions, Bitbucket, Jenkins) pour appliquer des **Quality Gates de sécurité bloquantes**, déclencher des analyses automatiques à chaque commit/Merge Request et exporter les artefacts de conformité (SBOM, SARIF).

---

## 🚀 Présentation de l'Outil `vectispire-cli`

`vectispire-cli` est un script shell universel et portable (compatible POSIX, Alpine, Debian, Ubuntu, macOS) conçu pour être exécuté dans n'importe quel conteneur CI/CD sans dépendances lourdes.

### Commandes Principales :
* `scan` : Déclenche une analyse de sécurité sur un dépôt ou un conteneur et attend optionnellement sa finalisation (`--wait`).
* `gate` : Évalue la politique de Quality Gate configurée dans Vectispire et termine avec le code de sortie `0` (Succès) ou `1` (Échec / Blocage du build).
* `sbom` : Télécharge le SBOM brut, dans le format JSON natif de Syft.
* `coverage` : Envoie le rapport de couverture JaCoCo, Cobertura ou lcov d'un dépôt (`--format` est obligatoire, jamais deviné).
* `test-report` : Envoie le rapport JUnit d'un dépôt — un fichier XML, ou un zip de plusieurs.

`coverage` et `test-report` demandent une clé détenant `report_import` dont la source est déclarée pour ce type ; voir [Importer des rapports de couverture et de tests](../../docs-site/administration/plugins.fr.md#importer-des-rapports-de-couverture-et-de-tests). Ils ne sont pas dans le script `v0.9.0` qu'épinglent les extraits ci-dessous.

La CLI appelle `curl -f` : sur un refus (`403` mauvaise portée, `404` dépôt hors de la restriction de la clé, `409` scan déjà en file) `scan`, `gate` et `sbom` sortent avec le code `22` de curl et n'affichent rien de la réponse du serveur. Les exemples commentés d'[Exemples CI](../../docs-site/integrations/ci-examples.fr.md) — GitLab CI avec le modèle livré, Jenkins, et SonarQube par une source déclarée — utilisent un script qui affiche le document de problème, et disent quelle clé chaque job demande.

---

## 🔒 Variables Secrètes Requises dans votre CI/CD

Configurez les variables suivantes dans les paramètres de votre projet CI/CD (ex: *GitLab > Settings > CI/CD > Variables* ou *GitHub > Settings > Secrets and variables > Actions*) :

| Variable | Description | Exemple |
|---|---|---|
| `VECTISPIRE_URL` | URL publique ou interne de votre instance Vectispire | `https://vectispire.monentreprise.fr` |
| `VECTISPIRE_API_KEY` | Clé d'API de portée `scan`, plus `read` pour `scan --wait` (qui interroge le scan), limitée au dépôt que le pipeline contrôle | *(Clé générée depuis la page Clés API)* |

---

## 🛠️ Snippets d'Intégration par Plateforme

### 1. 🦊 GitLab CI (`.gitlab-ci.yml`)

```yaml
stages:
  - test
  - security-gate

vectispire-security-gate:
  stage: security-gate
  image: alpine:latest
  variables:
    VECTISPIRE_URL: "https://vectispire.example.com"
    VECTISPIRE_REPO_ID: "1"
  before_script:
    - apk add --no-cache curl jq
  script:
    - curl -s -f -L "https://raw.githubusercontent.com/asmolabs/vectispire/v0.9.0/scripts/vectispire-cli.sh" -o vectispire-cli.sh
    - chmod +x vectispire-cli.sh
    # 1. Déclenche le scan et attend sa fin
    - ./vectispire-cli.sh scan --url "$VECTISPIRE_URL" --repo-id "$VECTISPIRE_REPO_ID" --wait
    # 2. Évalue la Gate (Bloque le pipeline si une sévérité CRITICAL ou HIGH non triée est présente)
    - ./vectispire-cli.sh gate --url "$VECTISPIRE_URL" --repo-id "$VECTISPIRE_REPO_ID" --fail-on HIGH
  rules:
    - if: '$CI_COMMIT_BRANCH == "main" || $CI_PIPELINE_SOURCE == "merge_request_event"'
```

---

### 2. 🐙 GitHub Actions (`.github/workflows/vectispire.yml`)

```yaml
name: Vectispire Security Gate
on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security-gate:
    name: Vectispire ASPM Quality Gate
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Trigger Scan & Enforce Security Gate
        env:
          VECTISPIRE_URL: ${{ secrets.VECTISPIRE_URL }}
          VECTISPIRE_API_KEY: ${{ secrets.VECTISPIRE_API_KEY }}
          VECTISPIRE_REPO_ID: "1"
        run: |
          curl -s -f -L https://raw.githubusercontent.com/asmolabs/vectispire/v0.9.0/scripts/vectispire-cli.sh -o vectispire-cli.sh
          chmod +x vectispire-cli.sh
          ./vectispire-cli.sh scan --url "$VECTISPIRE_URL" --repo-id "$VECTISPIRE_REPO_ID" --wait
          ./vectispire-cli.sh gate --url "$VECTISPIRE_URL" --repo-id "$VECTISPIRE_REPO_ID" --fail-on HIGH
```

---

### 3. 🪣 Bitbucket Pipelines (`bitbucket-pipelines.yml`)

```yaml
image: alpine:latest

pipelines:
  default:
    - step:
        name: Vectispire Security Gate
        script:
          - apk add --no-cache curl jq
          - curl -s -f -L https://raw.githubusercontent.com/asmolabs/vectispire/v0.9.0/scripts/vectispire-cli.sh -o vectispire-cli.sh
          - chmod +x vectispire-cli.sh
          - ./vectispire-cli.sh scan --url "$VECTISPIRE_URL" --repo-id 1 --wait
          - ./vectispire-cli.sh gate --url "$VECTISPIRE_URL" --repo-id 1 --fail-on HIGH
```

---

### 4. 👨‍✈️ Jenkinsfile (Pipeline Script)

```groovy
pipeline {
    agent any
    environment {
        VECTISPIRE_URL = 'https://vectispire.example.com'
        VECTISPIRE_API_KEY = credentials('vectispire-api-key')
        VECTISPIRE_REPO_ID = '1'
    }
    stages {
        stage('Security Gate') {
            steps {
                sh '''
                    curl -s -f -L https://raw.githubusercontent.com/asmolabs/vectispire/v0.9.0/scripts/vectispire-cli.sh -o vectispire-cli.sh
                    chmod +x vectispire-cli.sh
                    ./vectispire-cli.sh scan --url "$VECTISPIRE_URL" --repo-id "$VECTISPIRE_REPO_ID" --wait
                    ./vectispire-cli.sh gate --url "$VECTISPIRE_URL" --repo-id "$VECTISPIRE_REPO_ID" --fail-on HIGH
                '''
            }
        }
    }
}
```

---

## 📦 Construire l'Image de la CLI

Aucune image de la CLI n'est publiée : la release construit le plan de contrôle et l'agent, rien d'autre. [`Dockerfile.cli`](../../Dockerfile.cli) en construit une — Alpine avec `curl` et `jq`, sous un utilisateur non root, `vectispire-cli` comme point d'entrée — à pousser dans votre propre registre :

```bash
docker build -f Dockerfile.cli -t <your-registry>/vectispire-cli:<tag> .
```

```yaml
# Exemple GitLab CI avec image dédiée
vectispire-gate:
  image:
    name: <your-registry>/vectispire-cli:<tag>
    entrypoint: [""]   # GitLab lance le script du job par un shell, pas par la CLI
  script:
    - vectispire-cli scan --repo-id 1 --wait
    - vectispire-cli gate --repo-id 1 --fail-on HIGH
```
