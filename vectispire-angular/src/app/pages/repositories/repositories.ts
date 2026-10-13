import { NgClass } from '@angular/common';
import { AssetTier } from '@/app/core/api.models';
import { I18nService } from '../../core/i18n/i18n.service';
import { Component, computed, inject, signal, ChangeDetectionStrategy } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { DataViewModule } from '@openng/optimus-ui/dataview';
import { SelectModule } from '@openng/optimus-ui/select';
import { messageOf } from '../../core/api-error';
import { TargetsApi } from '../../core/api/targets.api';
import { ScansApi } from '../../core/api/scans.api';
import { ScorecardsApi } from '../../core/api/scorecards.api';
import type {
    BadgeState,
    GitTokenSummary,
    MonitoredRepository,
    SecurityScorecard,
    SshKeySummary
} from '../../core/api.models';
import { SessionStore } from '../../core/session.store';
import { LastScanTag } from '../../shared/last-scan';
import { ScorecardView } from '../../shared/scorecard';
import { DetectedLanguages } from '../../shared/detected-languages';
import { SettingsApi } from '../../core/api/settings.api';
import { ScheduleFields, scheduleLabel, type ScheduleInForce } from '../../shared/schedule-fields';
import { ReportImports } from '../../shared/report-imports';
import { SarifImports } from '../../shared/sarif-imports';

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
/** How a repository authenticates its clone. At most one credential: the server refuses both. */
export type CredentialKind = 'none' | 'ssh' | 'https';

/**
 * The transport a URL names, as far as the credential choice cares.
 *
 * `unknown` is an empty or unfinished URL: every choice stays offered rather than hiding one the
 * operator is about to need. The scp form `git@host:path` is SSH although it carries no scheme.
 */
export function urlTransport(url: string): 'https' | 'ssh' | 'unknown' {
    const value = url.trim().toLowerCase();
    if (value.startsWith('https://')) return 'https';
    if (value.startsWith('ssh://') || value.startsWith('git://') || /^[^\s/:@]+@[^\s/:]+:/.test(value)) return 'ssh';
    return 'unknown';
}

/** The host of an https:// URL, lowercased, or null while it does not parse. */
export function httpsHost(url: string): string | null {
    if (urlTransport(url) !== 'https') return null;
    try {
        return new URL(url.trim()).hostname.toLowerCase() || null;
    } catch {
        return null;
    }
}

/**
 * Whether an https:// URL carries a secret in its user-info (`https://user:token@host/…`).
 *
 * Only a hint: the server is what refuses a new one. It exists so that the operator learns the
 * alternative — a managed token — before the refusal, not only from it.
 */
export function urlCarriesSecret(url: string): boolean {
    if (urlTransport(url) !== 'https') return false;
    try {
        return new URL(url.trim()).password !== '';
    } catch {
        return false;
    }
}

/**
 * The CLI the snippets download: the `vectispire-cli.sh` asset of the release this interface is,
 * run only at the digest that release shipped.
 *
 * <p>The snippets used to fetch `scripts/vectispire-cli.sh` from the raw URL at the tag and run it
 * unchecked — a file nobody had signed, whose bytes were whatever the forge served that day. The
 * release now publishes the script with a Sigstore bundle, as it does the gate script, and every
 * snippet compares its SHA-256 with the one below before executing it. The interface and the asset
 * come from the same tag, so this is the digest of `scripts/vectispire-cli.sh` in this tree;
 * `ci/check-cli-pin.sh` fails the push and the release when the two drift apart.
 */
const CLI_SCRIPT_URL = `https://github.com/asmolabs/vectispire/releases/download/v${RELEASE}/vectispire-cli.sh`;
const CLI_SCRIPT_SHA256 = '0397ab0375e60e4a9793e85a3aa95e2a61f1dec906df2522ab8011b29cce359a';
/** The identity the release workflow signs with — per tag, naming the workflow file, never the repository alone. */
const CLI_SIGNER = `https://github.com/asmolabs/vectispire/.github/workflows/release.yml@refs/tags/v${RELEASE}`;

@Component({
    selector: 'app-repositories',
    imports: [
        NgClass,
        FormsModule,
        RouterLink,
        ButtonModule,
        CardModule,
        DialogModule,
        InputTextModule,
        MessageModule,
        DataViewModule,
        SelectModule,
        LastScanTag,
        ScorecardView,
        DetectedLanguages,
        ScheduleFields,
        TranslatePipe,
        RuleCoverageBanner,
        SarifImports,
        ReportImports
    ],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './repositories.html'
})
export class Repositories {
    private readonly i18n = inject(I18nService);
    private readonly targetsApi = inject(TargetsApi);
    private readonly settingsApi = inject(SettingsApi);
    private readonly scansApi = inject(ScansApi);
    private readonly scorecardsApi = inject(ScorecardsApi);
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
    /** The installation's default interval, in minutes, for the dialog to name; null until known. */
    readonly defaultScanMinutes = signal<number | null>(null);

    form = {
        url: '',
        branch: 'main',
        name: '',
        subPath: '',
        requiredAgentLabel: '',
        scanIntervalMinutes: null as number | null,
        scanCron: '',
        scanManualOnly: false,
        // The empty string is "no key", and it is a value the server acts on rather than one it
        // ignores — see the comment on the payload in `submit`.
        sshKeyId: '',
        credentialKind: 'none' as CredentialKind,
        httpsTokenId: '',
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

    /**
     * The HTTPS tokens this form can attach. Loaded like the keys, and ignored on failure for the
     * same reason: an account that may not list them can still edit everything else.
     */
    readonly gitTokens = signal<GitTokenSummary[]>([]);

    /**
     * The credential kinds the URL allows.
     *
     * **Read from the URL rather than offered in full and refused on save**: an SSH key is useless
     * to an https:// clone and a token to an SSH one, and the server refuses both combinations.
     * Methods, not `computed`: `form` is a plain object bound with `ngModel`, and a computed over
     * it would never recompute.
     */
    credentialKinds(): { label: string; value: CredentialKind }[] {
        const transport = urlTransport(this.form.url);
        return [
            { label: this.i18n.t('repositories.credential_none'), value: 'none' as const },
            ...(transport !== 'https'
                ? [{ label: this.i18n.t('repositories.credential_ssh'), value: 'ssh' as const }]
                : []),
            ...(transport !== 'ssh'
                ? [{ label: this.i18n.t('repositories.credential_https'), value: 'https' as const }]
                : [])
        ];
    }

    /**
     * The tokens bound to the URL's host — the only ones the server would accept here (decision
     * 0022). While the host does not parse yet, all of them, so the choice is not empty mid-typing.
     */
    httpsTokenOptions(): { label: string; value: string }[] {
        const host = httpsHost(this.form.url);
        return this.gitTokens()
            .filter((token) => host === null || token.host.toLowerCase() === host)
            .map((token) => ({ label: `${token.name} (${token.host})`, value: token.id }));
    }

    /** The host the URL names, for the "no token for this host" hint. */
    urlHost(): string | null {
        return httpsHost(this.form.url);
    }

    urlCarriesSecret(): boolean {
        return urlCarriesSecret(this.form.url);
    }

    /**
     * Keeps the credential shown consistent with the URL being typed.
     *
     * A kind the new URL does not allow falls back to "none", and a token bound to another host is
     * dropped: **what the form shows is what it sends.** Leaving a hidden choice in place would
     * send a credential the screen no longer displays, and the server's refusal would then name
     * something the operator cannot see.
     */
    onUrlChange(): void {
        if (!this.credentialKinds().some((kind) => kind.value === this.form.credentialKind)) {
            this.form.credentialKind = 'none';
        }
        if (
            this.form.httpsTokenId &&
            !this.httpsTokenOptions().some((option) => option.value === this.form.httpsTokenId)
        ) {
            this.form.httpsTokenId = '';
        }
    }

    /** Exposed to the template: the list says what each target's schedule is, because a
     *  target nobody rescans looks monitored until somebody reads the date of its last scan. */
    /** Bound rather than referenced: the label is translated, so it needs the service — and it
     *  reads `translations()` so the row redraws when the reader changes language. */
    readonly scheduleLabel = (target: { scanCron: string | null; schedule?: ScheduleInForce | null }) => {
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
    private readonly scanInFlight = computed(() => anyScanRunning(this.repositories().map((row) => row.lastScan)));

    constructor() {
        pollWhile(this.scanInFlight, () => this.reload());
        this.reload();
        // A failure here leaves the list empty rather than blocking the form: the operator can
        // still edit everything else, and "no key" stays selectable.
        this.targetsApi.sshKeys().subscribe({ next: (keys) => this.sshKeys.set(keys) });
        this.targetsApi.gitTokens().subscribe({ next: (tokens) => this.gitTokens.set(tokens) });
        // Only the dialog reads it, and only an administrator opens the dialog. A failure leaves the
        // dialog naming the setting instead of a number.
        if (this.isAdmin()) {
            this.settingsApi
                .defaultScanIntervalMinutes()
                .subscribe({ next: (minutes) => this.defaultScanMinutes.set(minutes) });
        }
    }

    reload(): void {
        this.loading.set(true);
        this.targetsApi.repositories().subscribe({
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
        this.scansApi.triggerRepositoryScan(repository.id).subscribe({
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

        const requests = repos.map((r) => this.scansApi.triggerRepositoryScan(r.id));
        void import('rxjs').then(({ forkJoin }) => {
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
                  scanManualOnly: repository.scanManualOnly ?? false,
                  sshKeyId: repository.sshKeyId ?? '',
                  credentialKind: repository.httpsTokenId ? 'https' : repository.sshKeyId ? 'ssh' : 'none',
                  httpsTokenId: repository.httpsTokenId ?? '',
                  tier: repository.tier ?? 'TIER_2_BUSINESS_OPERATIONAL'
              }
            : {
                  url: '',
                  branch: 'main',
                  name: '',
                  subPath: '',
                  requiredAgentLabel: '',
                  scanIntervalMinutes: null,
                  scanCron: '',
                  scanManualOnly: false,
                  sshKeyId: '',
                  credentialKind: 'none',
                  httpsTokenId: '',
                  tier: 'TIER_2_BUSINESS_OPERATIONAL'
              };
        // A stored key beside an https:// URL predates the rule and would be refused on save; the
        // form shows "none" instead of a blank choice. The token is not checked here — the list of
        // tokens may not have arrived yet, and a hint names a mismatch anyway.
        if (!this.credentialKinds().some((kind) => kind.value === this.form.credentialKind)) {
            this.form.credentialKind = 'none';
        }
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
        // Only the credential of the chosen kind is sent; the other is cleared, since the server
        // refuses a repository holding both and a switch from key to token is one save.
        const kind = this.form.credentialKind;
        const body = {
            url: this.form.url.trim(),
            branch: this.form.branch.trim() || 'main',
            name: this.form.name.trim() || blank,
            subPath: this.form.subPath.trim() || blank,
            required_agent_label: this.form.requiredAgentLabel.trim() || blank,
            tier: this.form.tier as AssetTier,
            // **Zero, not `undefined`, when the field was cleared on the update path.** The server
            // reads absent as "leave alone", so `undefined` would keep the old interval while the
            // form showed nothing — the scans would carry on at the old pace. Zero returns the
            // target to the installation's default; switching rescans off is `scanManualOnly`.
            scanIntervalMinutes: this.form.scanIntervalMinutes ?? (editing ? 0 : undefined),
            // Always sent, empty included: the empty string is the only value the update path
            // distinguishes from "leave alone", so it is the only way to remove an expression.
            scanCron: this.form.scanCron.trim(),
            // Always sent: the dialog shows the switch, so what it shows is what is saved.
            scanManualOnly: this.form.scanManualOnly,
            // Same rule, same reason. Sending `undefined` when the operator picked "no key" would
            // leave the old key attached while this form showed none — and the next clone would
            // use a credential the screen says is gone.
            sshKeyId: kind === 'ssh' ? this.form.sshKeyId : '',
            // Absent on create when there is none, empty on update to detach one: the server reads
            // absent as "leave alone" there, which would keep a token this form shows as removed.
            https_token_id: (kind === 'https' ? this.form.httpsTokenId : '') || blank
        };

        this.saving.set(true);
        const call = editing
            ? this.targetsApi.updateRepository(editing.id, body)
            : this.targetsApi.createRepository(body);
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
                this.formError.set(
                    this.alreadyRegistered(response) ??
                        messageOf(response, this.i18n.t(editing ? 'repositories.error_save' : 'repositories.error_add'))
                );
            }
        });
    }

    /**
     * The same repository, branch and sub-path already filed — said in the reader's language, naming
     * the target when the server named it.
     *
     * The server sends the existing target's id only to a caller who sees it, and this screen lists
     * exactly what the caller sees, so the name is read from the list rather than from the English
     * sentence. Without an id — or one the list has not loaded — the sentence names nothing, as the
     * server's does: a target the caller cannot see is not revealed by its name here either.
     */
    private alreadyRegistered(failure: unknown): string | null {
        const problem = (failure as { error?: { type?: unknown; existingRepositoryId?: unknown } } | null)?.error;
        if (problem?.type !== TARGET_ALREADY_REGISTERED) return null;
        const existing = this.repositories().find((repository) => repository.id === problem.existingRepositoryId);
        return existing
            ? this.i18n.t('repositories.already_registered', { name: existing.displayName })
            : this.i18n.t('repositories.already_registered_unnamed');
    }

    askDelete(repository: MonitoredRepository): void {
        this.pendingDelete.set(repository);
        this.deleteVisible.set(true);
    }

    confirmDelete(): void {
        const repository = this.pendingDelete();
        if (!repository) return;
        this.saving.set(true);
        this.targetsApi.deleteRepository(repository.id).subscribe({
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
        this.scorecardsApi.getRepositoryScorecard(repository.id).subscribe({
            next: (card) => {
                this.selectedScorecard.set(card);
                this.copied.set(false);
                this.badge.set(null);
                this.scorecardVisible.set(true);
                // Separate call, and it may legitimately fail for a reader without write access;
                // a badge panel that cannot load must not take the scorecard down with it.
                this.scorecardsApi.getRepositoryBadge(repository.id).subscribe({
                    next: (state) => this.badge.set(state),
                    error: () => this.badge.set({ published: false, token: null, url: null })
                });
            },
            error: () => this.error.set(this.i18n.t('repositories.error_scorecard'))
        });
    }

    publishBadge(repoId: number): void {
        this.badgeBusy.set(true);
        this.scorecardsApi.publishRepositoryBadge(repoId).subscribe({
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
        this.scorecardsApi.revokeRepositoryBadge(repoId).subscribe({
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

    /** The repository whose imports are open — reports and SARIF; each panel loads itself from the id. */
    readonly sarifRepo = signal<MonitoredRepository | null>(null);
    readonly sarifVisible = signal(false);

    openSarifImports(repository: MonitoredRepository): void {
        this.sarifRepo.set(repository);
        this.sarifVisible.set(true);
    }

    openCicd(repository: MonitoredRepository): void {
        this.selectedCicdRepo.set(repository);
        this.cicdCopied.set(false);
        this.cicdVisible.set(true);
    }

    copySnippet(code: string): void {
        void navigator.clipboard.writeText(code).then(() => {
            this.cicdCopied.set(true);
            setTimeout(() => this.cicdCopied.set(false), 3000);
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

    copyBadgeMarkdown(): void {
        const url = this.badge()?.url;
        if (!url) {
            return;
        }
        const markdown = `[![Vectispire Security](${window.location.origin}${url})](${window.location.origin}/repositories)`;
        void navigator.clipboard.writeText(markdown).then(() => {
            this.copied.set(true);
            setTimeout(() => this.copied.set(false), 3000);
        });
    }
}

/** The RFC 9457 `type` of a duplicate target — the cause the routes publish, never the English sentence. */
const TARGET_ALREADY_REGISTERED = 'urn:vectispire:problem:target-already-registered';
