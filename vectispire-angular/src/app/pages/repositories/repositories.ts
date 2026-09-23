import { CommonModule } from '@angular/common';
import { AssetTier } from '@/app/core/api.models';
import { I18nService } from '../../core/i18n/i18n.service';
import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { DataViewModule } from '@openng/optimus-ui/dataview';
import { SelectModule } from '@openng/optimus-ui/select';
import { TagModule } from '@openng/optimus-ui/tag';
import { messageOf } from '../../core/api-error';
import { ApiService } from '../../core/api.service';
import type { BadgeState, MonitoredRepository, SecurityScorecard, SshKeySummary } from '../../core/api.models';
import { SessionStore } from '../../core/session.store';
import { LastScanTag } from '../../shared/last-scan';
import { ScheduleFields, scheduleLabel } from '../../shared/schedule-fields';

import { RuleCoverageBanner } from '@/app/shared/rule-coverage-banner';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { anyScanRunning, pollWhile } from '@/app/core/poll-while';
import { version as RELEASE } from '../../../../package.json';

/**
 * The CLI the pipeline snippets download, <b>pinned to this build's release tag</b>.
 *
 * <p>The snippets fetched the script from {@code main} — whatever that branch held on the day a
 * pipeline ran — and piped the API key into it. Pinned to the tag, a pipeline runs the script this
 * Vectispire was released with, and a change to {@code main} reaches nobody's CI unannounced. The
 * key travels in the environment the CLI already reads, not as an argument, where {@code ps} and a
 * {@code set -x} log would show it; the images and the actions are pinned as this repository's own
 * workflows are.
 */
const CLI_SCRIPT_URL = `https://raw.githubusercontent.com/asmolabs/vectispire/v${RELEASE}/scripts/vectispire-cli.sh`;

@Component({
    selector: 'app-repositories',
    standalone: true,
    imports: [CommonModule, FormsModule, RouterLink, ButtonModule, CardModule, DialogModule, InputTextModule, MessageModule, DataViewModule, SelectModule, TagModule, LastScanTag, ScheduleFields, TranslatePipe, RuleCoverageBanner],
    templateUrl: './repositories.html'
})
export class Repositories {
    private readonly i18n = inject(I18nService);
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

    /**
     * The badge state of the repository whose scorecard is open, or null while it loads.
     *
     * **Loaded per repository rather than derived from its id.** The screen used to build the
     * badge URL out of the id and show it unconditionally, which is also how anybody could read
     * any repository's grade by counting from one. A badge now exists only if somebody published
     * it, so this screen has to ask.
     */
    readonly badge = signal<BadgeState | null>(null);
    readonly badgeBusy = signal(false);
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
        // The empty string is "no key", and it is a value the server acts on rather than one it
        // ignores — see the comment on the payload in `submit`.
        sshKeyId: '',
        tier: 'TIER_2_BUSINESS_OPERATIONAL' as string
    };

    /**
     * The deployment keys this form can attach.
     *
     * <p>Loaded once, next to the repository list. The choice belongs on this screen because the
     * key is a property of the target: a repository with none falls back to the host's own SSH,
     * which fails on a private repository with "requires authentication" — an error that asks for
     * exactly this field.
     */
    readonly sshKeys = signal<SshKeySummary[]>([]);

    /** `null` is not offered as an option value: the server distinguishes "" from absent. */
    readonly sshKeyOptions = computed(() => [
        { label: this.i18n.t('repositories.no_key_host_ssh'), value: '' },
        ...this.sshKeys().map((key) => ({ label: key.name, value: key.id }))
    ]);

    /** Exposed to the template: the list says what each target's schedule is, because a
     *  target nobody rescans looks monitored until somebody reads the date of its last scan. */
    /** Bound rather than referenced: the label is translated, so it needs the service — and it
     *  reads `translations()` so the row redraws when the reader changes language. */
    readonly scheduleLabel = (target: { scanIntervalMinutes: number | null; scanCron: string | null }) => {
        this.i18n.translations();
        return scheduleLabel(target, this.i18n);
    };

    /** The row being edited, or null when the dialog is adding one. */
    readonly editing = signal<MonitoredRepository | null>(null);

    /**
     * **A scan that has been launched must be seen to progress.** This screen announced "queued"
     * and then stopped moving: the button looked to have no effect, when the work was waiting for a
     * worker. The timer runs only while a scan in this list is unsettled, and stops by itself when
     * the last one has finished — an idle estate costs nothing.
     */
    private readonly scanInFlight = computed(() =>
        anyScanRunning(this.repositories().map((row) => row.lastScan)));

    constructor() {
        pollWhile(this.scanInFlight, () => this.reload());
        this.reload();
        // A failure here leaves the list empty rather than blocking the form: the operator can
        // still edit everything else, and "no key" stays selectable.
        this.api.sshKeys().subscribe({ next: (keys) => this.sshKeys.set(keys) });
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
                this.error.set(this.i18n.t('repositories.error_load'));
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
                this.notice.set(this.i18n.t('repositories.scan_queued', { name: repository.displayName }));
                this.reload();
            },
            error: (response) => {
                this.busy.set(null);
                // The server knows why — "a scan is already queued", most of the time.
                this.error.set(messageOf(response, this.i18n.t('repositories.error_scan')));
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
                    this.notice.set(this.i18n.t('repositories.scan_all_queued', { count: results.length }));
                    this.reload();
                },
                error: (response) => {
                    this.scanningAll.set(false);
                    this.error.set(messageOf(response, this.i18n.t('repositories.error_scan_all')));
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
                  sshKeyId: repository.sshKeyId ?? '',
                  tier: repository.tier ?? 'TIER_2_BUSINESS_OPERATIONAL'
              }
            : { url: '', branch: 'main', name: '', subPath: '', requiredAgentLabel: '', scanIntervalMinutes: null, scanCron: '', sshKeyId: '', tier: 'TIER_2_BUSINESS_OPERATIONAL' };
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
            tier: this.form.tier as AssetTier,
            // **Zero, not `undefined`, when the field was cleared on the update path.** The server
            // reads absent as "leave alone", so `undefined` would keep the old interval while the
            // form showed nothing — the operator would think they had switched the schedule off
            // and the scans would carry on. Zero is what `Schedules` reads as "manual only".
            scanIntervalMinutes: this.form.scanIntervalMinutes ?? (editing ? 0 : undefined),
            // Always sent, empty included: the empty string is the only value the update path
            // distinguishes from "leave alone", so it is the only way to remove an expression.
            scanCron: this.form.scanCron.trim(),
            // Same rule, same reason. Sending `undefined` when the operator picked "no key" would
            // leave the old key attached while this form showed none — and the next clone would
            // use a credential the screen says is gone.
            sshKeyId: this.form.sshKeyId
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
                this.formError.set(messageOf(response, this.i18n.t(editing ? 'repositories.error_save' : 'repositories.error_add')));
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
                this.error.set(this.i18n.t('repositories.error_delete'));
            }
        });
    }

    openScorecard(repository: MonitoredRepository): void {
        this.api.getRepositoryScorecard(repository.id).subscribe({
            next: (card) => {
                this.selectedScorecard.set(card);
                this.copied.set(false);
                this.badge.set(null);
                this.scorecardVisible.set(true);
                // Separate call, and it may legitimately fail for a reader without write access;
                // a badge panel that cannot load must not take the scorecard down with it.
                this.api.getRepositoryBadge(repository.id).subscribe({
                    next: (state) => this.badge.set(state),
                    error: () => this.badge.set({ published: false, token: null, url: null })
                });
            },
            error: () => this.error.set(this.i18n.t('repositories.error_scorecard'))
        });
    }

    publishBadge(repoId: number): void {
        this.badgeBusy.set(true);
        this.api.publishRepositoryBadge(repoId).subscribe({
            next: (state) => {
                this.badge.set(state);
                this.badgeBusy.set(false);
            },
            error: () => {
                this.badgeBusy.set(false);
                this.error.set(this.i18n.t('repositories.badge_publish_failed'));
            }
        });
    }

    revokeBadge(repoId: number): void {
        this.badgeBusy.set(true);
        this.api.revokeRepositoryBadge(repoId).subscribe({
            next: (state) => {
                this.badge.set(state);
                this.copied.set(false);
                this.badgeBusy.set(false);
            },
            error: () => {
                this.badgeBusy.set(false);
                this.error.set(this.i18n.t('repositories.badge_revoke_failed'));
            }
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
  image: alpine:3.22
  variables:
    VECTISPIRE_URL: "${origin}"
    # Configure VECTISPIRE_API_KEY in Settings > CI/CD > Variables (Masked & Protected)
  before_script:
    - apk add --no-cache curl jq
  script:
    - curl -s -f -L ${CLI_SCRIPT_URL} -o vectispire-cli.sh
    - chmod +x vectispire-cli.sh
    - ./vectispire-cli.sh scan --url "$VECTISPIRE_URL" --repo-id ${repoId} --wait
    - ./vectispire-cli.sh gate --url "$VECTISPIRE_URL" --repo-id ${repoId} --fail-on HIGH
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
          curl -s -f -L ${CLI_SCRIPT_URL} -o vectispire-cli.sh
          chmod +x vectispire-cli.sh
          ./vectispire-cli.sh scan --url "$VECTISPIRE_URL" --repo-id ${repoId} --wait
          ./vectispire-cli.sh gate --url "$VECTISPIRE_URL" --repo-id ${repoId} --fail-on HIGH`;

            case 'bitbucket':
                return `# bitbucket-pipelines.yml
image: alpine:3.22

pipelines:
  default:
    - step:
        name: Vectispire Security Gate
        script:
          - apk add --no-cache curl jq
          - curl -s -f -L ${CLI_SCRIPT_URL} -o vectispire-cli.sh
          - chmod +x vectispire-cli.sh
          - ./vectispire-cli.sh scan --url "${origin}" --repo-id ${repoId} --wait
          - ./vectispire-cli.sh gate --url "${origin}" --repo-id ${repoId} --fail-on HIGH`;

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
                    curl -s -f -L ${CLI_SCRIPT_URL} -o vectispire-cli.sh
                    chmod +x vectispire-cli.sh
                    ./vectispire-cli.sh scan --url "$VECTISPIRE_URL" --repo-id ${repoId} --wait
                    ./vectispire-cli.sh gate --url "$VECTISPIRE_URL" --repo-id ${repoId} --fail-on HIGH
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

    copyBadgeMarkdown(): void {
        const url = this.badge()?.url;
        if (!url) {
            return;
        }
        const markdown = `[![Vectispire Security](${window.location.origin}${url})](${window.location.origin}/repositories)`;
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
