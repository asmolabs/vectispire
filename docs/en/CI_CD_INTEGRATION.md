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
* `build-sbom` : Send the build's CycloneDX JSON SBOM for a repository (`cyclonedx-maven-plugin`'s `makeAggregateBom`, the Gradle CycloneDX plugin); it completes the scanner's inventory — the versions a BOM manages, the libraries pulled in transitively.

`coverage`, `test-report` and `build-sbom` take a key holding `report_import` whose source is declared for that kind (`coverage`, `test_report`, `sbom`); see [Importing coverage and test reports](../../docs-site/administration/plugins.md#importing-coverage-and-test-reports) and [Importing a build's SBOM](../../docs-site/administration/plugins.md#importing-a-builds-sbom).

Every command exits `0` when done, `1` only for a red verdict, and `2` when there is no answer to trust: a refusal — the server's `detail` is printed, *This API key lacks the read scope.* — an unreachable control plane, a scan that failed or timed out. `scan` adopts the scan already waiting on a `409` rather than failing. That is from 0.10.0: the `v0.9.0` script called `curl -f`, exited with curl's code `22` on every refusal and printed nothing of the answer. The worked examples in [CI examples](../../docs-site/integrations/ci-examples.md) — GitLab CI with the shipped template, Jenkins, and SonarQube through a declared source — use a script that prints the problem document instead, and say which key each job needs.

---

## 🔒 Required Secret Variables in your CI/CD Settings

Configure these environment variables in your CI/CD project settings (e.g. *GitLab > Settings > CI/CD > Variables* or *GitHub > Settings > Secrets and variables > Actions*):

| Variable | Description | Example |
|---|---|---|
| `VECTISPIRE_URL` | Public or internal URL of your Vectispire instance | `https://vectispire.mycorp.internal` |
| `VECTISPIRE_API_KEY` | API key with the `scan` scope, plus `read` for `scan --wait` (which polls the scan), restricted to the repository the pipeline gates | *(Generated from the API Keys page)* |

---

## 🔏 Getting the CLI

The CLI is a **release asset**, signed like the jar: `vectispire-cli.sh` and its Sigstore bundle
`vectispire-cli.sh.cosign.bundle`, from the release after 0.10.0 on — 0.10.0 and earlier do not carry
it. The snippets below download it, compare its SHA-256 with the one the pipeline pins, and only then
run it. Never pipe it into `sh`, where the bytes execute as they arrive and nothing can be checked
first. Until 0.10.0 these snippets fetched `scripts/vectispire-cli.sh` from the repository's raw URL
at the tag and ran it unchecked: a file outside the release, unsigned, compared with nothing.

Two values pin it:

| Variable | Value |
|---|---|
| `VECTISPIRE_CLI_VERSION` | the release tag, `<tag>` |
| `VECTISPIRE_CLI_SHA256` | the CLI's SHA-256, printed in that release's notes |

The **CI/CD** dialog of the *Repositories* page fills both in, for the version the server runs, and
its *CLI* tab carries the signature check. To take the digest from the signature rather than from the
release notes, verify the file once:

```bash
curl -fsSLO https://github.com/asmolabs/vectispire/releases/download/<tag>/vectispire-cli.sh
curl -fsSLO https://github.com/asmolabs/vectispire/releases/download/<tag>/vectispire-cli.sh.cosign.bundle
cosign verify-blob \
  --bundle vectispire-cli.sh.cosign.bundle \
  --certificate-identity "https://github.com/asmolabs/vectispire/.github/workflows/release.yml@refs/tags/<tag>" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  vectispire-cli.sh
sha256sum vectispire-cli.sh    # macOS: shasum -a 256 vectispire-cli.sh
```

The identity names the workflow file and the tag — replace the tag in both places — and the issuer
says it came from GitHub's token service; [Getting started §8](GETTING_STARTED.md#8-verifying-a-release)
says what each flag pins. From then on the digest pins the file in every run: `sha256sum -c` fails the
job on any other bytes, so a pipeline that moves to another tag without moving the digest stops rather
than running a script nobody checked.

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
    VECTISPIRE_CLI_VERSION: "<tag>"
    VECTISPIRE_CLI_SHA256: "<sha256 from the release notes>"
  before_script:
    - apk add --no-cache curl jq
  script:
    # The release's CLI, run only at the digest pinned above
    - curl -fsSL -o vectispire-cli.sh "https://github.com/asmolabs/vectispire/releases/download/$VECTISPIRE_CLI_VERSION/vectispire-cli.sh"
    - echo "$VECTISPIRE_CLI_SHA256  vectispire-cli.sh" | sha256sum -c -
    - chmod +x vectispire-cli.sh
    # 1. Enqueue scan and wait for completion
    - ./vectispire-cli.sh scan --url "$VECTISPIRE_URL" --repo-id "$VECTISPIRE_REPO_ID" --wait
    # 2. Check Security Gate (Fails build if unmitigated CRITICAL or HIGH issues exist)
    - ./vectispire-cli.sh gate --url "$VECTISPIRE_URL" --repo-id "$VECTISPIRE_REPO_ID" --fail-on HIGH
  rules:
    - if: '$CI_COMMIT_BRANCH == "main" || $CI_PIPELINE_SOURCE == "merge_request_event"'
```

**Sending the build's SBOM (Maven, `org.example`).** The scanner reads a Maven tree's poms, so a
version a parent's BOM manages comes out as `UNKNOWN` and a library pulled in transitively is not
listed; the build resolved both. This job writes the aggregate CycloneDX SBOM of every module and sends
it with the **reports** key — `report_import`, declared as a source delivering `sbom`, never the gate's
key:

```yaml
vectispire-build-sbom:
  stage: test
  image: maven:3.9-eclipse-temurin-21
  variables:
    VECTISPIRE_URL: "https://vectispire.example.com"
    VECTISPIRE_REPO_ID: "1"
    VECTISPIRE_CLI_VERSION: "<tag>"
    VECTISPIRE_CLI_SHA256: "<sha256 from the release notes>"
  script:
    # org.example:ledger-service and its modules, resolved as the build packages them
    - mvn -B org.cyclonedx:cyclonedx-maven-plugin:2.9.1:makeAggregateBom -DoutputFormat=json
    - curl -fsSL -o vectispire-cli.sh "https://github.com/asmolabs/vectispire/releases/download/$VECTISPIRE_CLI_VERSION/vectispire-cli.sh"
    - echo "$VECTISPIRE_CLI_SHA256  vectispire-cli.sh" | sha256sum -c -
    - chmod +x vectispire-cli.sh
    - ./vectispire-cli.sh build-sbom --url "$VECTISPIRE_URL" --api-key "$VECTISPIRE_REPORT_KEY"
        --repo-id "$VECTISPIRE_REPO_ID" --file target/bom.json --commit "$CI_COMMIT_SHA" --branch "$CI_COMMIT_REF_NAME"
  rules:
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
```

The answer names the scan it completed (`completedScanId`), or `null` before the repository's first
completed scan, which the SBOM then completes; see
[Importing a build's SBOM](../../docs-site/administration/plugins.md#importing-a-builds-sbom) for the
rule and the refusals.

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
          VECTISPIRE_CLI_VERSION: "<tag>"
          VECTISPIRE_CLI_SHA256: "<sha256 from the release notes>"
        run: |
          # The release's CLI, run only at the digest pinned above
          curl -fsSL -o vectispire-cli.sh "https://github.com/asmolabs/vectispire/releases/download/$VECTISPIRE_CLI_VERSION/vectispire-cli.sh"
          echo "$VECTISPIRE_CLI_SHA256  vectispire-cli.sh" | sha256sum -c -
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
          # The release's CLI, run only at the digest its release notes print
          - curl -fsSL -o vectispire-cli.sh "https://github.com/asmolabs/vectispire/releases/download/<tag>/vectispire-cli.sh"
          - echo "<sha256 from the release notes>  vectispire-cli.sh" | sha256sum -c -
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
        VECTISPIRE_CLI_VERSION = '<tag>'
        VECTISPIRE_CLI_SHA256 = '<sha256 from the release notes>'
    }
    stages {
        stage('Security Gate') {
            steps {
                sh '''
                    # The release's CLI, run only at the digest pinned above
                    curl -fsSL -o vectispire-cli.sh "https://github.com/asmolabs/vectispire/releases/download/$VECTISPIRE_CLI_VERSION/vectispire-cli.sh"
                    echo "$VECTISPIRE_CLI_SHA256  vectispire-cli.sh" | sha256sum -c -
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
