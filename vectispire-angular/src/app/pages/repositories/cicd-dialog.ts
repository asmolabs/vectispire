import { NgClass } from '@angular/common';
import { ChangeDetectionStrategy, Component, computed, inject } from '@angular/core';
import { ButtonModule } from '@openng/optimus-ui/button';
import { DialogModule } from '@openng/optimus-ui/dialog';
import type { MonitoredRepository } from '../../core/api.models';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { CLI_SCRIPT_SHA256, CLI_SCRIPT_URL, CLI_SIGNER } from './repository-model';
import { RepositoriesPage } from './repositories-page';

/**
 * The pipeline snippets for one repository — GitLab, GitHub, Bitbucket, Jenkins and the CLI — each
 * running the release's CLI only at the digest it shipped with. The snippet shown is computed from the
 * repository and the tab, not built again on every pass.
 */
@Component({
    selector: 'app-cicd-dialog',
    imports: [NgClass, ButtonModule, DialogModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './cicd-dialog.html'
})
export class CicdDialog {
    protected readonly page = inject(RepositoriesPage);

    protected readonly snippet = computed(() =>
        this.getCicdSnippet(this.page.cicdActiveTab(), this.page.selectedCicdRepo())
    );

    copySnippet(code: string): void {
        void navigator.clipboard.writeText(code).then(() => {
            this.page.cicdCopied.set(true);
            setTimeout(() => this.page.cicdCopied.set(false), 3000);
        });
    }

    getCicdSnippet(
        type: 'gitlab' | 'github' | 'bitbucket' | 'jenkins' | 'cli',
        repo: MonitoredRepository | null
    ): string {
        const repoId = repo?.id ?? 1;
        const origin = window.location.origin;

        switch (type) {
            case 'gitlab':
                return `# .gitlab-ci.yml
stages:
  - test
  - security-gate

vectispire-scan:
  stage: security-gate
  image: alpine:3.22
  variables:
    VECTISPIRE_URL: "${origin}"
    # VECTISPIRE_API_KEY in Settings > CI/CD > Variables (Masked & Protected): scopes scan and read,
    # restricted to this repository. Exit 1 is a red verdict, 2 a refusal or an unreachable server.
  before_script:
    - apk add --no-cache curl jq
  script:
    # The release's CLI, run only at the digest it shipped with; its cosign bundle is beside it (CLI tab).
    - curl -fsSL -o vectispire-cli.sh ${CLI_SCRIPT_URL}
    - echo "${CLI_SCRIPT_SHA256}  vectispire-cli.sh" | sha256sum -c -
    - chmod +x vectispire-cli.sh
    - ./vectispire-cli.sh scan --url "$VECTISPIRE_URL" --repo-id ${repoId} --wait
    - ./vectispire-cli.sh gate --url "$VECTISPIRE_URL" --repo-id ${repoId} --fail-on high
  rules:
    - if: '$CI_COMMIT_BRANCH == "main" || $CI_PIPELINE_SOURCE == "merge_request_event"'`;

            case 'github':
                return `# .github/workflows/vectispire.yml
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
      - name: Trigger Scan & Enforce Security Gate
        env:
          VECTISPIRE_URL: "${origin}"
          VECTISPIRE_API_KEY: \${{ secrets.VECTISPIRE_API_KEY }}
        run: |
          # The release's CLI, run only at the digest it shipped with; its cosign bundle is beside it (CLI tab).
          curl -fsSL -o vectispire-cli.sh ${CLI_SCRIPT_URL}
          echo "${CLI_SCRIPT_SHA256}  vectispire-cli.sh" | sha256sum -c -
          chmod +x vectispire-cli.sh
          ./vectispire-cli.sh scan --url "$VECTISPIRE_URL" --repo-id ${repoId} --wait
          ./vectispire-cli.sh gate --url "$VECTISPIRE_URL" --repo-id ${repoId} --fail-on high`;

            case 'bitbucket':
                return `# bitbucket-pipelines.yml
image: alpine:3.22

pipelines:
  default:
    - step:
        name: Vectispire Security Gate
        script:
          - apk add --no-cache curl jq
          # The release's CLI, run only at the digest it shipped with; its cosign bundle is beside it (CLI tab).
          - curl -fsSL -o vectispire-cli.sh ${CLI_SCRIPT_URL}
          - echo "${CLI_SCRIPT_SHA256}  vectispire-cli.sh" | sha256sum -c -
          - chmod +x vectispire-cli.sh
          - ./vectispire-cli.sh scan --url "${origin}" --repo-id ${repoId} --wait
          - ./vectispire-cli.sh gate --url "${origin}" --repo-id ${repoId} --fail-on high`;

            case 'jenkins':
                return `// Jenkinsfile
pipeline {
    agent any
    environment {
        VECTISPIRE_URL = '${origin}'
        VECTISPIRE_API_KEY = credentials('vectispire-api-key')
    }
    stages {
        stage('Security Gate') {
            steps {
                sh '''
                    # The release's CLI, run only at the digest it shipped with; its cosign bundle is beside it (CLI tab).
                    curl -fsSL -o vectispire-cli.sh ${CLI_SCRIPT_URL}
                    echo "${CLI_SCRIPT_SHA256}  vectispire-cli.sh" | sha256sum -c -
                    chmod +x vectispire-cli.sh
                    ./vectispire-cli.sh scan --url "$VECTISPIRE_URL" --repo-id ${repoId} --wait
                    ./vectispire-cli.sh gate --url "$VECTISPIRE_URL" --repo-id ${repoId} --fail-on high
                '''
            }
        }
    }
}`;

            case 'cli':
                return `# Direct CLI execution
export VECTISPIRE_URL="${origin}"
export VECTISPIRE_API_KEY="<YOUR_API_KEY>"   # scopes scan and read, restricted to this repository

# 0. Download the release's CLI and its Sigstore bundle, verify, and only then run it —
#    never piped into sh, where the bytes execute as they arrive and nothing can be checked first
curl -fsSLO ${CLI_SCRIPT_URL}
curl -fsSLO ${CLI_SCRIPT_URL}.cosign.bundle
cosign verify-blob \\
  --bundle vectispire-cli.sh.cosign.bundle \\
  --certificate-identity "${CLI_SIGNER}" \\
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \\
  vectispire-cli.sh
#    and the digest the pipeline tabs pin, which is all a runner without cosign checks
echo "${CLI_SCRIPT_SHA256}  vectispire-cli.sh" | sha256sum -c -
chmod +x vectispire-cli.sh

# 1. Trigger security scan and wait for completion
./vectispire-cli.sh scan --repo-id ${repoId} --wait

# 2. Check Security Quality Gate
./vectispire-cli.sh gate --repo-id ${repoId} --fail-on high

# 3. Download the SBOM of the latest completed scan, in Syft's native JSON
#    (for CycloneDX with VEX: GET /api/v1/cyclonedx/scans/<scan-id>/cyclonedx-vex.json, scope export)
./vectispire-cli.sh sbom --repo-id ${repoId} --output ./vectispire-sbom.syft.json`;
        }
    }
}
