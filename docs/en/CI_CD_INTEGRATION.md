# CI/CD Integration & Vectispire CLI Guide (`vectispire-cli`)

This guide explains how to integrate **Vectispire** into your continuous integration pipelines (GitLab CI, GitHub Actions, Bitbucket Pipelines, Jenkins) to enforce **blocking Security Quality Gates**, trigger scans on every commit, and download compliance artifacts (SBOM, SARIF).

---

## 🚀 Overview of `vectispire-cli`

`vectispire-cli` is a portable, lightweight shell automation runner (compatible with POSIX sh, Alpine, Debian, Ubuntu, macOS) designed to run inside any CI/CD container without heavyweight dependencies.

### Core Commands:
* `scan` : Enqueue a security scan on a repository or container and optionally wait for completion (`--wait`).
* `gate` : Evaluate the active Security Quality Gate policy and exit with code `0` (PASS) or `1` (FAIL / break build).
* `sbom` : Download the raw Software Bill of Materials, in Syft's native JSON.

---

## 🔒 Required Secret Variables in your CI/CD Settings

Configure these environment variables in your CI/CD project settings (e.g. *GitLab > Settings > CI/CD > Variables* or *GitHub > Settings > Secrets and variables > Actions*):

| Variable | Description | Example |
|---|---|---|
| `VECTISPIRE_URL` | Public or internal URL of your Vectispire instance | `https://vectispire.mycorp.internal` |
| `VECTISPIRE_API_KEY` | Programmatic API key with `scans:write` and `gate:read` scopes | *(Generated from the API Keys page)* |

---

## 🛠️ Pipeline Snippets

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
    - curl -s -f -L "${VECTISPIRE_URL}/scripts/vectispire-cli.sh" -o vectispire-cli.sh || curl -s -f -L "https://raw.githubusercontent.com/asmolabs/vectispire/main/scripts/vectispire-cli.sh" -o vectispire-cli.sh
    - chmod +x vectispire-cli.sh
    # 1. Enqueue scan and wait for completion
    - ./vectispire-cli.sh scan --url "$VECTISPIRE_URL" --api-key "$VECTISPIRE_API_KEY" --repo-id "$VECTISPIRE_REPO_ID" --wait
    # 2. Check Security Gate (Fails build if unmitigated CRITICAL or HIGH issues exist)
    - ./vectispire-cli.sh gate --url "$VECTISPIRE_URL" --api-key "$VECTISPIRE_API_KEY" --repo-id "$VECTISPIRE_REPO_ID" --fail-on HIGH
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
          curl -s -f -L https://raw.githubusercontent.com/asmolabs/vectispire/main/scripts/vectispire-cli.sh -o vectispire-cli.sh
          chmod +x vectispire-cli.sh
          ./vectispire-cli.sh scan --url "$VECTISPIRE_URL" --api-key "$VECTISPIRE_API_KEY" --repo-id "$VECTISPIRE_REPO_ID" --wait
          ./vectispire-cli.sh gate --url "$VECTISPIRE_URL" --api-key "$VECTISPIRE_API_KEY" --repo-id "$VECTISPIRE_REPO_ID" --fail-on HIGH
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
          - curl -s -f -L https://raw.githubusercontent.com/asmolabs/vectispire/main/scripts/vectispire-cli.sh -o vectispire-cli.sh
          - chmod +x vectispire-cli.sh
          - ./vectispire-cli.sh scan --url "$VECTISPIRE_URL" --api-key "$VECTISPIRE_API_KEY" --repo-id 1 --wait
          - ./vectispire-cli.sh gate --url "$VECTISPIRE_URL" --api-key "$VECTISPIRE_API_KEY" --repo-id 1 --fail-on HIGH
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
                    curl -s -f -L https://raw.githubusercontent.com/asmolabs/vectispire/main/scripts/vectispire-cli.sh -o vectispire-cli.sh
                    chmod +x vectispire-cli.sh
                    ./vectispire-cli.sh scan --url "$VECTISPIRE_URL" --api-key "$VECTISPIRE_API_KEY" --repo-id "$VECTISPIRE_REPO_ID" --wait
                    ./vectispire-cli.sh gate --url "$VECTISPIRE_URL" --api-key "$VECTISPIRE_API_KEY" --repo-id "$VECTISPIRE_REPO_ID" --fail-on HIGH
                '''
            }
        }
    }
}
```

---

## 📦 Using the Pre-built Docker Image

An official container image `vectispire/cli:latest` is available to execute `vectispire-cli` directly in container-native CI platforms:

```yaml
vectispire-gate:
  image: vectispire/cli:latest
  script:
    - vectispire-cli scan --repo-id 1 --wait
    - vectispire-cli gate --repo-id 1 --fail-on HIGH
```
