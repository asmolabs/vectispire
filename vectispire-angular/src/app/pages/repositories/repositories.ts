import { CommonModule } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { DataViewModule } from '@openng/optimus-ui/dataview';
import { TagModule } from '@openng/optimus-ui/tag';
import { messageOf } from '../../core/api-error';
import { ApiService } from '../../core/api.service';
import type { MonitoredRepository, SecurityScorecard } from '../../core/api.models';
import { SessionStore } from '../../core/session.store';
import { LastScanTag } from '../../shared/last-scan';
import { ScheduleFields, scheduleLabel } from '../../shared/schedule-fields';

import { TranslatePipe } from '../../core/i18n/translate.pipe';

@Component({
    selector: 'app-repositories',
    standalone: true,
    imports: [CommonModule, FormsModule, RouterLink, ButtonModule, CardModule, DialogModule, InputTextModule, MessageModule, DataViewModule, TagModule, LastScanTag, ScheduleFields, TranslatePipe],
    templateUrl: './repositories.html'
})
export class Repositories {
    private readonly api = inject(ApiService);
    private readonly session = inject(SessionStore);

    readonly repositories = signal<MonitoredRepository[]>([]);
    readonly loading = signal(true);
    readonly saving = signal(false);
    readonly error = signal<string | null>(null);
    readonly formError = signal<string | null>(null);
    readonly formVisible = signal(false);
    readonly deleteVisible = signal(false);
    readonly pendingDelete = signal<MonitoredRepository | null>(null);
    readonly scorecardVisible = signal(false);
    readonly selectedScorecard = signal<SecurityScorecard | null>(null);
    readonly copied = signal(false);
    readonly cicdVisible = signal(false);
    readonly selectedCicdRepo = signal<MonitoredRepository | null>(null);
    readonly cicdActiveTab = signal<'gitlab' | 'github' | 'bitbucket' | 'jenkins' | 'cli'>('gitlab');
    readonly cicdCopied = signal(false);
    /** La ligne dont le scan est en cours de mise en file. */
    readonly busy = signal<number | null>(null);
    readonly scanningAll = signal(false);
    readonly notice = signal<string | null>(null);
    readonly isAdmin = this.session.isAdmin;

    form = {
        url: '',
        branch: 'main',
        name: '',
        subPath: '',
        requiredAgentLabel: '',
        scanIntervalMinutes: null as number | null,
        scanCron: '',
        tier: 'TIER_2_BUSINESS_OPERATIONAL' as string
    };

    /** Exposed to the template: the list says what each target's schedule is, because a
     *  target nobody rescans looks monitored until somebody reads the date of its last scan. */
    readonly scheduleLabel = scheduleLabel;

    /** The row being edited, or null when the dialog is adding one. */
    readonly editing = signal<MonitoredRepository | null>(null);

    constructor() {
        this.reload();
    }

    reload(): void {
        this.loading.set(true);
        this.api.repositories().subscribe({
            next: (repositories) => {
                this.repositories.set(repositories);
                this.error.set(null);
                this.loading.set(false);
            },
            error: () => {
                this.error.set('Could not load the repository list.');
                this.loading.set(false);
            }
        });
    }

    /**
     * Queues a scan. **It does not run it**: a worker will claim it.
     *
     * The screen says so, because the wait that follows is not an ordinary button's — without
     * that sentence, the absence of an immediate change reads as a failure.
     */
    triggerScan(repository: MonitoredRepository): void {
        this.busy.set(repository.id);
        this.notice.set(null);
        this.error.set(null);
        this.api.triggerRepositoryScan(repository.id).subscribe({
            next: () => {
                this.busy.set(null);
                this.notice.set(`Scan queued for ${repository.displayName}. It will start as soon as a worker is available.`);
                this.reload();
            },
            error: (response) => {
                this.busy.set(null);
                // The server knows why — "a scan is already queued", most of the time.
                this.error.set(messageOf(response, 'Could not queue this scan.'));
            }
        });
    }

    triggerScanAll(): void {
        const repos = this.repositories();
        if (repos.length === 0) return;

        this.scanningAll.set(true);
        this.notice.set(null);
        this.error.set(null);

        const requests = repos.map((r) => this.api.triggerRepositoryScan(r.id));
        import('rxjs').then(({ forkJoin }) => {
            forkJoin(requests).subscribe({
                next: (results) => {
                    this.scanningAll.set(false);
                    this.notice.set(`Scan planifié pour ${results.length} dépôts. Les workers vont démarrer les analyses.`);
                    this.reload();
                },
                error: (response) => {
                    this.scanningAll.set(false);
                    this.error.set(messageOf(response, 'Impossible de lancer le scan de tous les dépôts.'));
                }
            });
        });
    }

    openForm(repository?: MonitoredRepository): void {
        this.editing.set(repository ?? null);
        this.form = repository
            ? {
                  url: repository.url,
                  branch: repository.branch,
                  name: repository.name ?? '',
                  subPath: repository.subPath ?? '',
                  requiredAgentLabel: repository.requiredAgentLabel ?? '',
                  scanIntervalMinutes: repository.scanIntervalMinutes,
                  scanCron: repository.scanCron ?? '',
                  tier: repository.tier ?? 'TIER_2_BUSINESS_OPERATIONAL'
              }
            : { url: '', branch: 'main', name: '', subPath: '', requiredAgentLabel: '', scanIntervalMinutes: null, scanCron: '', tier: 'TIER_2_BUSINESS_OPERATIONAL' };
        this.formError.set(null);
        this.formVisible.set(true);
    }

    submit(): void {
        const editing = this.editing();
        // **Empty string and not `undefined` when editing.** On the create path an absent field
        // means "no value"; on the update path the server reads absent as "leave alone", so a
        // field the operator cleared has to be sent as empty or the clearing is silently
        // dropped — the form would show it gone and the next scan would disagree.
        const blank = editing ? '' : undefined;
        const body = {
            url: this.form.url.trim(),
            branch: this.form.branch.trim() || 'main',
            name: this.form.name.trim() || blank,
            subPath: this.form.subPath.trim() || blank,
            required_agent_label: this.form.requiredAgentLabel.trim() || blank,
            tier: this.form.tier as any,
            // **Zero, not `undefined`, when the field was cleared on the update path.** The server
            // reads absent as "leave alone", so `undefined` would keep the old interval while the
            // form showed nothing — the operator would think they had switched the schedule off
            // and the scans would carry on. Zero is what `Schedules` reads as "manual only".
            scanIntervalMinutes: this.form.scanIntervalMinutes ?? (editing ? 0 : undefined),
            // Always sent, empty included: the empty string is the only value the update path
            // distinguishes from "leave alone", so it is the only way to remove an expression.
            scanCron: this.form.scanCron.trim()
        };

        this.saving.set(true);
        const call = editing ? this.api.updateRepository(editing.id, body) : this.api.createRepository(body);
        call.subscribe({
            next: () => {
                this.saving.set(false);
                this.formVisible.set(false);
                this.editing.set(null);
                this.reload();
            },
            error: (response) => {
                this.saving.set(false);
                // The server's message is the one that knows *why* — scheme refused, host
                // missing. Replacing it with a generic "error" would lose that.
                this.formError.set(messageOf(response, editing ? 'Could not save this repository.' : 'Could not add this repository.'));
            }
        });
    }

    askDelete(repository: MonitoredRepository): void {
        this.pendingDelete.set(repository);
        this.deleteVisible.set(true);
    }

    confirmDelete(): void {
        const repository = this.pendingDelete();
        if (!repository) return;
        this.saving.set(true);
        this.api.deleteRepository(repository.id).subscribe({
            next: () => {
                this.saving.set(false);
                this.deleteVisible.set(false);
                this.reload();
            },
            error: () => {
                this.saving.set(false);
                this.deleteVisible.set(false);
                this.error.set('The deletion failed.');
            }
        });
    }

    openScorecard(repository: MonitoredRepository): void {
        this.api.getRepositoryScorecard(repository.id).subscribe({
            next: (card) => {
                this.selectedScorecard.set(card);
                this.copied.set(false);
                this.scorecardVisible.set(true);
            },
            error: () => this.error.set('Failed to load scorecard for this repository.')
        });
    }

    openCicd(repository: MonitoredRepository): void {
        this.selectedCicdRepo.set(repository);
        this.cicdCopied.set(false);
        this.cicdVisible.set(true);
    }

    copySnippet(code: string): void {
        navigator.clipboard.writeText(code).then(() => {
            this.cicdCopied.set(true);
            setTimeout(() => this.cicdCopied.set(false), 3000);
        });
    }

    getCicdSnippet(type: 'gitlab' | 'github' | 'bitbucket' | 'jenkins' | 'cli', repo: MonitoredRepository | null): string {
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
  image: alpine:latest
  variables:
    VECTISPIRE_URL: "${origin}"
    # Configure VECTISPIRE_API_KEY in Settings > CI/CD > Variables (Masked & Protected)
  before_script:
    - apk add --no-cache curl jq
  script:
    - curl -s -f -L https://raw.githubusercontent.com/asmolabs/vectispire/main/scripts/vectispire-cli.sh -o vectispire-cli.sh
    - chmod +x vectispire-cli.sh
    - ./vectispire-cli.sh scan --url "$VECTISPIRE_URL" --api-key "$VECTISPIRE_API_KEY" --repo-id ${repoId} --wait
    - ./vectispire-cli.sh gate --url "$VECTISPIRE_URL" --api-key "$VECTISPIRE_API_KEY" --repo-id ${repoId} --fail-on HIGH
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
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Trigger Scan & Enforce Security Gate
        env:
          VECTISPIRE_URL: "${origin}"
          VECTISPIRE_API_KEY: \${{ secrets.VECTISPIRE_API_KEY }}
        run: |
          curl -s -f -L https://raw.githubusercontent.com/asmolabs/vectispire/main/scripts/vectispire-cli.sh -o vectispire-cli.sh
          chmod +x vectispire-cli.sh
          ./vectispire-cli.sh scan --url "$VECTISPIRE_URL" --api-key "$VECTISPIRE_API_KEY" --repo-id ${repoId} --wait
          ./vectispire-cli.sh gate --url "$VECTISPIRE_URL" --api-key "$VECTISPIRE_API_KEY" --repo-id ${repoId} --fail-on HIGH`;

            case 'bitbucket':
                return `# bitbucket-pipelines.yml
image: alpine:latest

pipelines:
  default:
    - step:
        name: Vectispire Security Gate
        script:
          - apk add --no-cache curl jq
          - curl -s -f -L https://raw.githubusercontent.com/asmolabs/vectispire/main/scripts/vectispire-cli.sh -o vectispire-cli.sh
          - chmod +x vectispire-cli.sh
          - ./vectispire-cli.sh scan --url "${origin}" --api-key "$VECTISPIRE_API_KEY" --repo-id ${repoId} --wait
          - ./vectispire-cli.sh gate --url "${origin}" --api-key "$VECTISPIRE_API_KEY" --repo-id ${repoId} --fail-on HIGH`;

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
                    curl -s -f -L https://raw.githubusercontent.com/asmolabs/vectispire/main/scripts/vectispire-cli.sh -o vectispire-cli.sh
                    chmod +x vectispire-cli.sh
                    ./vectispire-cli.sh scan --url "\$VECTISPIRE_URL" --api-key "\$VECTISPIRE_API_KEY" --repo-id ${repoId} --wait
                    ./vectispire-cli.sh gate --url "\$VECTISPIRE_URL" --api-key "\$VECTISPIRE_API_KEY" --repo-id ${repoId} --fail-on HIGH
                '''
            }
        }
    }
}`;

            case 'cli':
                return `# Direct CLI execution
export VECTISPIRE_URL="${origin}"
export VECTISPIRE_API_KEY="<YOUR_API_KEY>"

# 1. Trigger security scan and wait for completion
./scripts/vectispire-cli.sh scan --repo-id ${repoId} --wait

# 2. Check Security Quality Gate
./scripts/vectispire-cli.sh gate --repo-id ${repoId} --fail-on HIGH

# 3. Download CycloneDX / SPDX SBOM artifact
./scripts/vectispire-cli.sh sbom --repo-id ${repoId} --output ./vectispire-sbom.json`;
        }
    }

    copyBadgeMarkdown(repoId: number): void {
        const markdown = `[![Vectispire Security](${window.location.origin}/api/v1/scorecards/repositories/${repoId}/badge.svg)](${window.location.origin}/repositories)`;
        navigator.clipboard.writeText(markdown).then(() => {
            this.copied.set(true);
            setTimeout(() => this.copied.set(false), 3000);
        });
    }

    gradeSeverity(grade?: string): 'success' | 'warn' | 'danger' | 'secondary' {
        switch (grade) {
            case 'A_PLUS':
            case 'A': return 'success';
            case 'B':
            case 'C': return 'warn';
            case 'D':
            case 'F': return 'danger';
            default: return 'secondary';
        }
    }
}
