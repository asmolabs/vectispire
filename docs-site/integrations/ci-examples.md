# CI examples

Three worked pipelines, each with the key it needs and nothing more:

1. [**GitLab CI**](#gitlab-ci) — scan a repository, wait for the result, fail the pipeline on the
   gate's verdict with the shipped template, and send JaCoCo coverage and JUnit results;
2. [**Jenkins**](#jenkins) — the same in a declarative pipeline, the verdict as the stage result;
3. [**SonarQube**](#sonarqube) — export SonarQube's issues as SARIF and import them through a
   declared source, so that a checklist rule scoped on `import:quality-server/SonarQube` measures
   them.

What the gate decides and how its policy is stored is on [CI policy gate](ci-gate.md); this page
is about wiring it. **Replace every `<…>` before running anything**: each one is a value only you
know, and a command left with one fails rather than guessing.

## Three keys, not one {#three-keys}

Issue keys on [API keys](../administration/api-keys.md). One key per job, because each job does
one thing and a key that leaks should give away that one thing:

| Key | Scopes | Restricted to | Declared as a source | Used by |
|---|---|---|---|---|
| **CI gate** | `scan`, `read` | the repository the pipeline builds | no | the scan and the gate |
| **Reports** | `report_import` | the repository | yes, delivering `coverage` and `test_report` | the coverage and JUnit upload |
| **SonarQube** | `sarif_import` | the repository — or none, when the source covers a project of several repositories | yes, delivering `sarif` from the tool `SonarQube` | the SARIF upload |

**Why `read` on the gate key.** Triggering a scan and asking for a verdict take `scan`; waiting
for the scan reads `GET /api/v1/scans/{id}`, which is a `read` route. Without `read` the wait is
refused with `403` — *This API key lacks the read scope.* A pipeline that only asks for a verdict
on a scan run by the schedule needs `scan` alone.

**Why restricted.** A merge-request pipeline runs the job definition of the branch that was
pushed, so anyone who can push a branch can change the job to print the variable. Masking hides a
secret from the log, not from a modified job. A key restricted to one repository that leaks queues
and reads that repository's scans; an unrestricted one acts with everything its account sees,
across the estate. A restriction narrows the account's visibility and never widens it, and
deleting the repository revokes the keys restricted to it.

**Who issues the gate key.** A key acts for the account that issued it and never does more than
that account could: triggering a scan is an administrator's act, and a verdict is *recorded*, so
the account must be one that writes — an auditor's or a platform governor's key is refused on the
gate. Every scan the key triggers is in the [audit log](../administration/audit-log.md) as
`alice (API key ci-payments)`.

**Why separate keys for reports and SARIF.** One key is one declared source, and a key that
deposits a coverage figure should not be able to deposit findings, which open and resolve issues
(see [Importing coverage and test reports](../administration/plugins.md#importing-coverage-and-test-reports)).

## Trigger a scan and wait for it {#scan-and-wait}

Neither shipped script queues a scan: [`ci/vectispire-gate.sh`](https://github.com/asmolabs/vectispire/blob/main/ci/vectispire-gate.sh)
asks for a verdict about the backlog *as it stands*. Gating without scanning first answers about
the last scan, whenever that was. Both examples below commit this script to the repository as
`ci/vectispire-scan.sh`; it needs `curl` and `jq`.

```sh
#!/bin/sh
# Queue a Vectispire scan of one repository and wait until it has finished.
#   exit 0 — the scan completed: a verdict asked now describes it
#   exit 2 — no verdict can be trusted: the scan was refused, failed, or is still running
set -eu

: "${VECTISPIRE_URL:?set VECTISPIRE_URL to the control plane}"
: "${VECTISPIRE_TOKEN:?set VECTISPIRE_TOKEN to the CI key (scopes scan and read)}"
: "${VECTISPIRE_REPOSITORY_ID:?set VECTISPIRE_REPOSITORY_ID to the repository id}"

api="${VECTISPIRE_URL%/}/api/v1"
auth="Authorization: Bearer $VECTISPIRE_TOKEN"
timeout="${VECTISPIRE_SCAN_TIMEOUT:-1800}"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# A GET that shows the server's refusal: `curl -f` would print the status and drop the
# problem document, whose `detail` names the missing scope.
get() {
    code=$(curl -sS -o "$2" -w '%{http_code}' -H "$auth" "$1") || code=000
    if [ "$code" != 200 ]; then
        echo "vectispire: GET $1 answered HTTP $code" >&2
        if [ -s "$2" ]; then cat "$2" >&2; echo >&2; fi
        exit 2
    fi
}

status=$(curl -sS -o "$work/queued.json" -w '%{http_code}' -X POST \
    -H "$auth" -H 'Content-Type: application/json' --data '{}' \
    "$api/repositories/$VECTISPIRE_REPOSITORY_ID/scan") || status=000

case "$status" in
    200)
        scan_id=$(jq -r '.id' "$work/queued.json") ;;
    409)
        # A scan of this repository is already waiting: wait for that one rather than fail.
        get "$api/scans?repo_id=$VECTISPIRE_REPOSITORY_ID&limit=1" "$work/latest.json"
        scan_id=$(jq -r '.[0].id' "$work/latest.json") ;;
    *)
        echo "vectispire: the scan was refused (HTTP $status)" >&2
        if [ -s "$work/queued.json" ]; then cat "$work/queued.json" >&2; echo >&2; fi
        exit 2 ;;
esac

echo "vectispire: waiting for scan $scan_id"
deadline=$(( $(date +%s) + timeout ))
while :; do
    get "$api/scans/$scan_id" "$work/scan.json"
    state=$(jq -r '.scan.status' "$work/scan.json")
    case "$state" in
        completed)
            echo "vectispire: scan $scan_id completed"
            exit 0 ;;
        failed)
            echo "vectispire: scan $scan_id failed: $(jq -r '.scan.error // "no detail"' "$work/scan.json")" >&2
            exit 2 ;;
    esac
    if [ "$(date +%s)" -ge "$deadline" ]; then
        echo "vectispire: scan $scan_id is still $state after ${timeout}s" >&2
        exit 2
    fi
    sleep 10
done
```

Its exit codes follow the gate script's: `2` is "could not decide", never "passed". A scan
moves through `pending`, `scanning`, then `completed` or `failed`; a failed scan is not something to
gate on, since the verdict would describe the scan before it.

!!! warning "The scan reads the branch configured on the repository, not the pipeline's commit"
    Vectispire clones the repository itself, at the branch set on
    [Repositories](../guide/repositories.md), when a worker takes the scan. On a feature branch's
    pipeline the verdict still describes the configured branch. Both examples therefore scan and
    gate only on the branch Vectispire is configured for.

The [repository's CLI](https://github.com/asmolabs/vectispire/blob/main/scripts/vectispire-cli.sh)
does the same with `scan --repo-id <id> --wait`, reading the key from `VECTISPIRE_API_KEY`: it adopts
the scan already waiting on a `409`, prints the server's `detail` on a refusal and exits with the
same three codes. That is from the release after 0.9.0; the CLI tagged `v0.9.0` called `curl -f`,
exited with curl's code `22` on every refusal and printed nothing of the answer.

## 1. GitLab CI {#gitlab-ci}

### Keys and variables

On **Settings → CI/CD → Variables**:

| Variable | Value | Flags |
|---|---|---|
| `VECTISPIRE_URL` | `https://<vectispire-host>` | — |
| `VECTISPIRE_TOKEN` | the **CI gate** key (`scan`, `read`, restricted to the repository) | **Masked**; **Protected** when only protected branches gate |
| `VECTISPIRE_REPORT_KEY` | the **Reports** key (`report_import`, declared source) | **Masked**; Protected likewise |

A protected variable is not given to pipelines of unprotected branches: there the scripts stop on
*set VECTISPIRE_TOKEN…* rather than sending a request. That is the intended trade — the key is out
of reach of whoever can push a branch.

The reports key is declared once by the platform governor, on **Administration → Declared sources**
(`kinds` `coverage` and `test_report`, scope the repository or its project); see
[Importing coverage and test reports](../administration/plugins.md#importing-coverage-and-test-reports).

### `.gitlab-ci.yml`

```yaml
include:
  # Pinned: a template read from a moving branch changes your pipeline without a commit of yours.
  - remote: 'https://raw.githubusercontent.com/asmolabs/vectispire/<tag>/ci/gitlab/vectispire-gate.gitlab-ci.yml'

stages: [test, vectispire]

variables:
  # The repository's id in Vectispire, read by the three jobs below.
  VECTISPIRE_REPOSITORY_ID: "<repository-id>"
  # The tag of the include above: the template downloads that release's gate script.
  VECTISPIRE_GATE_VERSION: "<tag>"

# Your own test job; what matters is that it keeps the two reports as artifacts.
unit-tests:
  stage: test
  image: maven:3.9-eclipse-temurin-21
  script:
    - mvn -B verify          # with jacoco-maven-plugin's `report` goal bound to the build
  artifacts:
    paths:
      - target/site/jacoco/jacoco.xml
      - target/surefire-reports/

vectispire-reports:
  stage: vectispire
  image: alpine:3.22
  needs: [unit-tests]
  before_script:
    - apk add --no-cache curl zip
  script:
    - |
      set -eu
      api="${VECTISPIRE_URL%/}/api/v1/repositories/$VECTISPIRE_REPOSITORY_ID"
      curl --fail-with-body -sS -X POST "$api/coverage-imports" \
        --url-query "format=jacoco" \
        --url-query "commit=$CI_COMMIT_SHA" --url-query "branch=$CI_COMMIT_REF_NAME" \
        -H "Authorization: Bearer $VECTISPIRE_REPORT_KEY" -H "Content-Type: application/xml" \
        --data-binary @target/site/jacoco/jacoco.xml
      (cd target/surefire-reports && zip -q ../surefire-reports.zip TEST-*.xml)
      curl --fail-with-body -sS -X POST "$api/test-report-imports" \
        --url-query "commit=$CI_COMMIT_SHA" --url-query "branch=$CI_COMMIT_REF_NAME" \
        -H "Authorization: Bearer $VECTISPIRE_REPORT_KEY" -H "Content-Type: application/zip" \
        --data-binary @target/surefire-reports.zip

vectispire-scan:
  stage: vectispire
  image: alpine:3.22
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH   # the branch Vectispire scans
  before_script:
    - apk add --no-cache curl jq
  script:
    - sh ci/vectispire-scan.sh

vectispire-gate:
  extends: .vectispire-gate
  stage: vectispire
  needs: [vectispire-scan]
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

`<tag>` is a release after 0.9.0. The template tagged `v0.9.0` cannot be included as it is: it runs
`ci/vectispire-gate.sh` from your checkout, where there is no such file, ships
`allow_failure: true`, and declares `VECTISPIRE_REPOSITORY_ID: ""` on its job, which hides a global
value.

What each piece is for:

- **`--url-query`** (curl 7.87 or later; `alpine:3.22` has it) percent-encodes the branch, which may
  carry characters a query string cannot. `commit` must be a hexadecimal commit name; both are
  kept as the pipeline states them, verified against nothing.
- **The test report is zipped** because Surefire writes one file per test class; a single JUnit XML
  file is sent as `application/xml` instead. With Gradle, the files are
  `build/reports/jacoco/test/jacocoTestReport.xml` and `build/test-results/test/TEST-*.xml`.
- **The gate job** downloads the release's `vectispire-gate.sh`, checks its SHA-256 against the
  digest the template carries, and runs it only if they match: a script that is not the one
  released beside the template stops the job, as does a `VECTISPIRE_GATE_VERSION` naming another
  release whose script differs. The script then exits `0` when the gate passed, `1` when it failed
  and `2` when it could not be asked; `1` and `2` fail the pipeline.
- **Advisory, on purpose.** `VECTISPIRE_GATE_MODE: advisory` turns a red verdict into exit `3`,
  which the template's `allow_failure` accepts: the job shows as a warning, the pipeline passes, and
  the verdict is recorded all the same. `VECTISPIRE_ON_ERROR: warn` does the same for an unreachable
  control plane, letting the build through ungated. Both default to blocking.
- **Keep a copy instead of `include: remote`** if your GitLab cannot reach GitHub: commit the
  template into your project and use `include: local`, and point `VECTISPIRE_GATE_SCRIPT_URL` at a
  copy of the release's `vectispire-gate.sh` on a server you can reach. The digest check still
  applies, so the copy runs only if it is the released file.

The verdict is in the job log: the policy applied, its version and threshold, the number of issues
considered, then one line per violation with its severity, identifier, package, the reason and the
fixed versions when there are any. The verdict is also recorded, on the **Verdict register**
screen: every call writes one, so ask once per pipeline, not in a loop.

### When it is refused {#when-it-is-refused}

| Seen in the log | Cause | What to do |
|---|---|---|
| `set VECTISPIRE_TOKEN…` | the variable is protected and the branch is not | expected on unprotected branches; gate the protected ones |
| `set VECTISPIRE_GATE_VERSION…` | the gate job does not know which release's script to fetch | set it to the tag of the `include` |
| `…is not the one this template was released with` | the downloaded script's SHA-256 is not the template's: the include and `VECTISPIRE_GATE_VERSION` name different releases, or `VECTISPIRE_GATE_SCRIPT_URL` serves another file | the same tag in both places; nothing runs until they agree |
| `HTTP 401` | no key, or one unknown, revoked or expired, or its account deactivated | issue a new key; the answer never says which |
| `HTTP 403` *This API key lacks the scan scope.* — or *read* | the key is missing a scope | issue one with `scan` and `read` |
| `HTTP 403` *This credential is not allowed to call this route.* | the key's account may not do this: not an administrator for the scan; an auditor or a platform governor for the gate | issue the key from an administrator's account |
| `HTTP 404` | the repository id is wrong, **or outside the key's restriction** — the same answer, on purpose | check the id against the key's target |
| `HTTP 400` *Unknown severity* | a typo in `VECTISPIRE_FAIL_ON_SEVERITY` | `critical`, `high`, `medium`, `low` or `none` |
| `HTTP 429` | the key's request budget per minute is spent | wait `Retry-After`; a loop is polling too fast |
| reports: `403` | the reports key holds no `report_import`, or no enabled source is declared for it, or not for this kind | have the governor declare it with `coverage` and `test_report` |
| reports: `404` | the repository is outside the key's restriction or the source's scope | match the id, the key and the source |
| reports: `400` | the format is not one of `jacoco`, `cobertura`, `lcov`, the body does not read as it, it counts no line or no test, or the commit is not hexadecimal | an empty report is refused, never recorded as zero |
| reports: `413` | above `VECTISPIRE_MAX_BODY_COVERAGE_IMPORT` (16 MB) or `VECTISPIRE_MAX_BODY_TEST_REPORT_IMPORT` (32 MB) | have the operator raise the ceiling — a report split in two would be two reports, the second taken as the newest |

Every refusal is a [problem document](../reference/errors.md): `application/problem+json`, with
`detail` written for the person reading the log. None of these refusals carries a
`urn:vectispire:problem:` type — that is reserved for conflicts a screen must tell apart — so a
script decides on the status and shows the `detail`.

## 2. Jenkins {#jenkins}

### Credentials

In the **Credentials** of the folder that holds the job — not the global store, so that only the
jobs in that folder can bind them — add two credentials of kind **Secret text**:

| ID | Secret |
|---|---|
| `vectispire-ci-gate` | the **CI gate** key (`scan`, `read`, restricted to the repository) |
| `vectispire-reports` | the **Reports** key (`report_import`, declared source) |

`withCredentials` binds a secret for the steps inside it only, and Jenkins masks its value in the
console. Keep every `sh` script that uses one in **single quotes**: the shell expands
`$VECTISPIRE_TOKEN` at run time, whereas a Groovy `"…${…}"` string would write the secret into the
command line Jenkins records — it warns about exactly that. And no `set -x`.

The same caveat as GitLab applies to multibranch pipelines: a branch's `Jenkinsfile` is what runs,
so whoever can push a branch can bind the credential. The restriction is what bounds that.

### `Jenkinsfile`

```groovy
pipeline {
    // An agent with sh, curl, jq and zip.
    agent { label '<agent-label>' }

    environment {
        VECTISPIRE_URL           = 'https://<vectispire-host>'
        VECTISPIRE_REPOSITORY_ID = '<repository-id>'
    }

    stages {
        stage('Build and test') {
            steps {
                sh 'mvn -B verify'
            }
            post {
                always {
                    junit 'target/surefire-reports/TEST-*.xml'
                }
            }
        }

        stage('Vectispire reports') {
            steps {
                withCredentials([string(credentialsId: 'vectispire-reports', variable: 'VECTISPIRE_REPORT_KEY')]) {
                    // GIT_COMMIT comes from the checkout, BRANCH_NAME from a multibranch pipeline:
                    // drop the branch query elsewhere.
                    sh '''
                        set -eu
                        api="${VECTISPIRE_URL%/}/api/v1/repositories/$VECTISPIRE_REPOSITORY_ID"
                        curl --fail-with-body -sS -X POST "$api/coverage-imports" \
                          --url-query "format=jacoco" \
                          --url-query "commit=$GIT_COMMIT" --url-query "branch=$BRANCH_NAME" \
                          -H "Authorization: Bearer $VECTISPIRE_REPORT_KEY" -H "Content-Type: application/xml" \
                          --data-binary @target/site/jacoco/jacoco.xml
                        (cd target/surefire-reports && zip -q ../surefire-reports.zip TEST-*.xml)
                        curl --fail-with-body -sS -X POST "$api/test-report-imports" \
                          --url-query "commit=$GIT_COMMIT" --url-query "branch=$BRANCH_NAME" \
                          -H "Authorization: Bearer $VECTISPIRE_REPORT_KEY" -H "Content-Type: application/zip" \
                          --data-binary @target/surefire-reports.zip
                    '''
                }
            }
        }

        stage('Vectispire scan') {
            when { branch '<configured-branch>' }   // the branch Vectispire scans
            steps {
                withCredentials([string(credentialsId: 'vectispire-ci-gate', variable: 'VECTISPIRE_TOKEN')]) {
                    sh 'sh ci/vectispire-scan.sh'
                }
            }
        }

        stage('Vectispire gate') {
            when { branch '<configured-branch>' }
            environment {
                // The release's gate script and its digest: the VECTISPIRE_GATE_SHA256 of
                // ci/gitlab/vectispire-gate.gitlab-ci.yml at the same tag.
                VECTISPIRE_GATE_VERSION = '<tag>'
                VECTISPIRE_GATE_SHA256  = '<sha256>'
            }
            steps {
                sh '''
                    curl -fsSL -o vectispire-gate.sh \
                      "https://github.com/asmolabs/vectispire/releases/download/$VECTISPIRE_GATE_VERSION/vectispire-gate.sh"
                    echo "$VECTISPIRE_GATE_SHA256  vectispire-gate.sh" | sha256sum -c -
                '''
                withCredentials([string(credentialsId: 'vectispire-ci-gate', variable: 'VECTISPIRE_TOKEN')]) {
                    script {
                        int verdict = sh(returnStatus: true,
                                         script: 'sh vectispire-gate.sh --repository "$VECTISPIRE_REPOSITORY_ID"')
                        if (verdict == 1) {
                            error('Vectispire gate failed: the violations are listed above.')
                        }
                        if (verdict != 0) {
                            // 2: the gate could not be asked. Blocking is the default; use
                            // unstable(...) instead to let the build through, visibly ungated.
                            error("Vectispire gate could not be asked (exit ${verdict}).")
                        }
                    }
                }
            }
        }
    }
}
```

- **`returnStatus: true`** keeps the gate's three exit codes apart, so that "your code fails the
  policy" and "Vectispire did not answer" end as two different messages — and, if you choose, two
  different stage results.
- **`when { branch … }`** works in a multibranch pipeline. In a single-branch job, leave the `when`
  out and point the job at the branch Vectispire scans.
- The `curl` flags `--url-query` and `--fail-with-body` need curl 7.87 or later on the agent.
- **The gate script is checked before it runs**, against the digest the GitLab template at the same
  tag pins; `sha256sum -c` fails the stage on any other file. The release also carries a Sigstore
  bundle for it, verified as the jar is — see [CI policy gate](ci-gate.md#the-short-version).
  `vectispire-gate.sh` is a release asset from the release after 0.9.0.

The refusals are the ones in the [GitLab table](#when-it-is-refused): the scripts print the status
and the server's `detail` in the console.

## 3. SonarQube {#sonarqube}

SonarQube does not write SARIF itself. The job below reads its Web API, writes one SARIF run whose
tool is `SonarQube`, and uploads it through a declared source named `quality-server`. A checklist
line bound to the scope `import:quality-server/SonarQube` then measures those issues.

**Only from inside the organisation**: SonarQube on your premises, the job on your own runner. A
declared source is the platform's statement that this producer is internal; see
[Importing SARIF from an internal tool](../administration/plugins.md#importing-sarif-from-an-internal-tool).

### 1. The key and the source

1. On **API keys**, an administrator issues a key with **`sarif_import`** alone. Restrict it to the
   repository when the source feeds one repository.
   A key restriction names one target only, so a source covering a project of several repositories
   uses an unrestricted key, and **the source's scope** is then what confines it to that project.
2. On **Administration → Declared sources**, the platform governor declares the source:
   slug **`quality-server`**, delivering **SARIF**, tool **`SonarQube`**, the key above, and the
   project or the repository. The same call as a script — the route takes the governor's session,
   never a key:

```bash
curl --fail-with-body -X POST "https://<vectispire-host>/api/v1/sarif-sources" \
  -H "Authorization: Bearer $GOVERNOR_SESSION" -H "Content-Type: application/json" \
  -d '{"slug": "quality-server", "name": "SonarQube on premises", "api_key_id": "<key-id>",
       "repository_id": <repository-id>, "kinds": ["sarif"], "tools": ["SonarQube"]}'
```

**The slug and the tool name are part of every imported issue's identity**, as
`import:quality-server/sonarqube` beside the rule and the path. Rename either later and every
imported issue is resolved and opened again under the new name, with its triage left behind.
Choose them once. Rotating the key keeps the slug: declare the same slug again with the new key.

### 2. The converter

Commit this as `ci/sonarqube-to-sarif.sh`. It needs `curl` and `jq`, and a SonarQube token of a
technical account with **Browse** permission on the project, in `SONAR_TOKEN`.

```sh
#!/bin/sh
# Export a SonarQube project's unresolved issues as one SARIF 2.1.0 run named "SonarQube".
#   usage: sonarqube-to-sarif.sh <sonarqube-project-key> <output.sarif>
# Any failure exits non-zero and writes no report: an empty `results` would tell Vectispire
# "SonarQube found nothing" and resolve every issue it imported.
set -eu

: "${SONAR_HOST_URL:?set SONAR_HOST_URL to the SonarQube server}"
: "${SONAR_TOKEN:?set SONAR_TOKEN to a token allowed to browse the project}"
project="$1"
output="$2"
sonar="${SONAR_HOST_URL%/}"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

version=$(curl -fsS -u "$SONAR_TOKEN:" "$sonar/api/server/version")

page=1
: > "$work/issues.jsonl"
while :; do
    curl -fsS -u "$SONAR_TOKEN:" -o "$work/page.json" --get "$sonar/api/issues/search" \
        --data-urlencode "componentKeys=$project" \
        --data "resolved=false" --data "ps=500" --data "p=$page"
    total=$(jq -r '.paging.total' "$work/page.json")
    # The Web API serves at most 10,000 issues per query. Sending the first 10,000 would
    # resolve the others in Vectispire, so refuse instead.
    if [ "$total" -gt 10000 ]; then
        echo "sonarqube-to-sarif: $total issues, past the 10,000 the Web API can page through" >&2
        exit 1
    fi
    jq -c '.issues[]' "$work/page.json" >> "$work/issues.jsonl"
    [ $(( page * 500 )) -lt "$total" ] || break
    page=$(( page + 1 ))
done

jq -s --arg version "$version" '{
  version: "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  runs: [{
    tool: { driver: { name: "SonarQube", version: $version } },
    results: map({
      ruleId: .rule,
      message: { text: .message },
      properties: { "security-severity":
        ({ BLOCKER: "9.5", CRITICAL: "8.0", MAJOR: "5.5", MINOR: "2.0", INFO: "1.0" }[.severity // ""] // "5.5") },
      locations: (if (.component | contains(":")) then [{
        physicalLocation: ({ artifactLocation: { uri: (.component | sub("^[^:]*:"; "")) } }
          + (if .line then { region: { startLine: .line } } else {} end))
      }] else [] end)
    })
  }]
}' "$work/issues.jsonl" > "$work/report.sarif"
mv "$work/report.sarif" "$output"
echo "sonarqube-to-sarif: $(jq '.runs[0].results | length' "$output") issue(s) written to $output"
```

What it decides, and why:

- **Unresolved issues only** (`resolved=false`). An issue closed in SonarQube — fixed, *won't fix*,
  *false positive* — is then absent from the next report, and Vectispire resolves it: SonarQube
  stays where its triage is done. Every report replaces the previous one for that tool on that
  repository and touches nothing else.
- **Severity through `security-severity`**, the score Vectispire reads first: `BLOCKER` becomes
  critical, `CRITICAL` high, `MAJOR` medium, `MINOR` and `INFO` low. An issue without a severity —
  recent SonarQube versions describe impacts instead — is read as medium; adapt the mapping if your
  server does that for every issue.
- **The path** is SonarQube's component key minus its `projectKey:` prefix, which is relative to the
  analysis base directory. Vectispire refuses absolute paths and wants them relative to the
  repository root: if `sonar.projectBaseDir` is a subdirectory, prefix it. An issue on the project
  itself has no location.
- **Every issue type is exported.** To measure only vulnerabilities and bugs, narrow the query with
  the Web API's own filters; `/web_api/api/issues/search` on your server lists the parameters its
  version accepts.

### 3. The job

After the analysis — and after SonarQube has *processed* it: the scanner returns before the server
has computed the issues, so run it with `-Dsonar.qualitygate.wait=true`, or the export reads the
previous analysis. In Jenkins, a stage of the pipeline above — it reuses `VECTISPIRE_URL` and
`VECTISPIRE_REPOSITORY_ID` — with two more **Secret text** credentials, `sonarqube-browse-token`
and `vectispire-sonarqube` (the `sarif_import` key):

```groovy
stage('SonarQube to Vectispire') {
    environment {
        SONAR_HOST_URL = 'https://<sonarqube-host>'
    }
    steps {
        withCredentials([string(credentialsId: 'sonarqube-browse-token', variable: 'SONAR_TOKEN'),
                         string(credentialsId: 'vectispire-sonarqube', variable: 'VECTISPIRE_SARIF_KEY')]) {
            sh '''
                set -eu
                sh ci/sonarqube-to-sarif.sh "<sonarqube-project-key>" sonarqube.sarif
                curl --fail-with-body -sS -X POST \
                  "${VECTISPIRE_URL%/}/api/v1/repositories/$VECTISPIRE_REPOSITORY_ID/sarif-imports" \
                  -H "Authorization: Bearer $VECTISPIRE_SARIF_KEY" \
                  -H "Content-Type: application/sarif+json" \
                  --data-binary @sonarqube.sarif
            '''
        }
    }
}
```

In GitLab CI it is the same two commands in a job, with `SONAR_TOKEN` and `VECTISPIRE_SARIF_KEY`
as masked variables. The answer (`201`) counts the results and the issues created, resolved and
reopened, with the SHA-256 of the document — keep it in the job log to match an import to its run.

### 4. The checklist rule

On **Administration → Checklist templates**, on a draft, bind the line that asks for static
analysis to a `findings_threshold` rule — see
[measured lines](../administration/checklist-templates.md#measured-lines-the-rule-a-line-is-bound-to):

```json
{"kind": "findings_threshold", "maxAgeDays": 7,
 "scopes": ["import:quality-server/SonarQube"],
 "thresholds": {"critical": {"maxOpen": 0}, "high": {"maxOpen": 0}}}
```

The scope is stored lowercase, `import:quality-server/sonarqube`, as the issues are keyed. Two
consequences to plan for:

- **`maxAgeDays` is a schedule.** The line passes only if an import of that scope arrived within
  the age, on every repository of the project. A job that runs only when somebody pushes reads
  `stale` on a quiet repository: schedule it as well, nightly for instance (`cron('H 2 * * *')`
  in Jenkins' `triggers`).
- **A slug names one source, and a source one project or repository.** The rule measures where
  `quality-server` delivers. Another project fed by another source has another slug, and this
  scope reads `never_examined` there.

Imported issues do not fail the [CI gate](ci-gate.md) unless the gate policy includes them
(`include_plugins`), and they are not counted in the security figures: a third-party tool's
"critical" does not break a build nobody warned. The checklist measures them; the gate, by default,
does not.

### When it is refused {#sonarqube-refusals}

| Status | Cause |
|---|---|
| `403` | not an integration key, a key no **enabled** source is declared for, or a tool the source does not declare — the driver name must be `SonarQube`, compared without regard to case |
| `404` | a repository outside the key's restriction or the source's scope, answered as if it did not exist |
| `400` | not SARIF 2.1.0, a location absolute or outside the repository, a result with no rule, a run without `results` or marked failed |
| `413` | above `VECTISPIRE_MAX_BODY_SARIF_IMPORT` (32 MB). Do not split the report: each upload replaces the tool's previous one on that repository, so the second half would resolve the first. Narrow the query, or have the operator raise the ceiling |

A refused import is audited and sent to the SIEM as `VECTI-SEC-023`; an accepted one is kept with
its document hash, and listed under **Imports** on the repository's row in
[Repositories](../guide/repositories.md).
