# CI/CD Integration & Vectispire CLI Guide (`vectispire-cli`)

This guide explains how to integrate **Vectispire** into your continuous integration pipelines (GitLab CI, GitHub Actions, Bitbucket Pipelines, Jenkins) to enforce **blocking Security Quality Gates**, trigger scans on every commit, and download compliance artifacts (SBOM, SARIF).

---

## 🚀 Overview of `vectispire-cli`

`vectispire-cli` is a portable, lightweight shell automation runner (compatible with POSIX sh, Alpine, Debian, Ubuntu, macOS) designed to run inside any CI/CD container without heavyweight dependencies.

### Core Commands:
* `scan` : Enqueue a security scan on a repository or container and optionally wait for completion (`--wait`).
* `gate` : Evaluate the active Security Quality Gate policy and exit with code `0` (PASS), `1` (FAIL / break build) or `2` (the gate could not be asked).
* `status` : Show the status of a scan (`--scan-id`), or of a target's latest scan.
* `sbom` : Download the raw Software Bill of Materials, in Syft's native JSON; with `--repo-id`, of the latest **completed** scan. For CycloneDX with VEX, use the export route `GET /api/v1/cyclonedx/scans/{id}/cyclonedx-vex.json` (scope `export`).
* `coverage` : Send a JaCoCo, Cobertura or lcov coverage report for a repository (`--format` is required, never guessed).
* `test-report` : Send a JUnit report — one XML file, or a zip of them — for a repository.

`coverage` and `test-report` take a key holding `report_import` whose source is declared for that kind; see [Importing coverage and test reports](../../docs-site/administration/plugins.md#importing-coverage-and-test-reports).

Every command exits `0` when done, `1` only for a red verdict, and `2` when there is no answer to trust: a refusal — the server's `detail` is printed, *This API key lacks the read scope.* — an unreachable control plane, a scan that failed or timed out. `scan` adopts the scan already waiting on a `409` rather than failing. That is from 0.10.0: the `v0.9.0` script called `curl -f`, exited with curl's code `22` on every refusal and printed nothing of the answer. The worked examples in [CI examples](../../docs-site/integrations/ci-examples.md) — GitLab CI with the shipped template, Jenkins, and SonarQube through a declared source — use a script that prints the problem document instead, and say which key each job needs.

---

## 🔒 Required Secret Variables in your CI/CD Settings

Configure these environment variables in your CI/CD project settings (e.g. *GitLab > Settings > CI/CD > Variables* or *GitHub > Settings > Secrets and variables > Actions*):

| Variable | Description | Example |
|---|---|---|
| `VECTISPIRE_URL` | Public or internal URL of your Vectispire instance | `https://vectispire.mycorp.internal` |
| `VECTISPIRE_API_KEY` | API key with the `scan` scope, plus `read` for `scan --wait` (which polls the scan), restricted to the repository the pipeline gates | *(Generated from the API Keys page)* |

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
    - curl -s -f -L "https://raw.githubusercontent.com/asmolabs/vectispire/v0.10.0/scripts/vectispire-cli.sh" -o vectispire-cli.sh
    - chmod +x vectispire-cli.sh
    # 1. Enqueue scan and wait for completion
    - ./vectispire-cli.sh scan --url "$VECTISPIRE_URL" --repo-id "$VECTISPIRE_REPO_ID" --wait
    # 2. Check Security Gate (Fails build if unmitigated CRITICAL or HIGH issues exist)
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
          curl -s -f -L https://raw.githubusercontent.com/asmolabs/vectispire/v0.10.0/scripts/vectispire-cli.sh -o vectispire-cli.sh
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
          - curl -s -f -L https://raw.githubusercontent.com/asmolabs/vectispire/v0.10.0/scripts/vectispire-cli.sh -o vectispire-cli.sh
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
                    curl -s -f -L https://raw.githubusercontent.com/asmolabs/vectispire/v0.10.0/scripts/vectispire-cli.sh -o vectispire-cli.sh
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

## 📦 Building the CLI Image

No CLI image is published: the release builds the control plane and the agent, nothing else. [`Dockerfile.cli`](../../Dockerfile.cli) builds one — Alpine with `curl` and `jq`, running as a non-root user, `vectispire-cli` as its entrypoint — to push to your own registry:

```bash
docker build -f Dockerfile.cli -t <your-registry>/vectispire-cli:<tag> .
```

```yaml
vectispire-gate:
  image:
    name: <your-registry>/vectispire-cli:<tag>
    entrypoint: [""]   # GitLab runs the job's script through a shell, not through the CLI
  script:
    - vectispire-cli scan --repo-id 1 --wait
    - vectispire-cli gate --repo-id 1 --fail-on HIGH
```
