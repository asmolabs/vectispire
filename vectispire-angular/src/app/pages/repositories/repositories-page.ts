import { computed, inject, Injectable, signal } from '@angular/core';
import { messageOf } from '../../core/api-error';
import { ScansApi } from '../../core/api/scans.api';
import { ScorecardsApi } from '../../core/api/scorecards.api';
import { SettingsApi } from '../../core/api/settings.api';
import { TargetsApi } from '../../core/api/targets.api';
import type {
    BadgeState,
    GitTokenSummary,
    MonitoredRepository,
    SecurityScorecard,
    SshKeySummary
} from '../../core/api.models';
import { I18nService } from '../../core/i18n/i18n.service';
import { SessionStore } from '../../core/session.store';
import { anyScanRunning, pollWhile } from '@/app/core/poll-while';
import { LatestRequest } from '@/app/core/latest-request';
import { PAGE_SIZE, pageHolding } from '@/app/shared/list-paging';

/**
 * The monitored repositories as the screen shows them, shared by the components it is made of and
 * provided by `Repositories`, so each visit starts from nothing: the list and its polling while a scan
 * runs, the scans queued from it, and the repository each dialog — deletion, scorecard, imports,
 * CI/CD — is open on. The repository form keeps its own draft; it reloads the list through here.
 */
@Injectable()
export class RepositoriesPage {
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
    readonly deleteVisible = signal(false);
    readonly pendingDelete = signal<MonitoredRepository | null>(null);
    readonly scorecardVisible = signal(false);
    readonly selectedScorecard = signal<SecurityScorecard | null>(null);

    readonly badge = signal<BadgeState | null>(null);
    /** Whether the badge's snippet was just copied; reset when another scorecard opens. */
    readonly copied = signal(false);
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
     * **A scan that has been launched must be seen to progress.** This screen announced "queued"
     * and then stopped moving: the button looked to have no effect, when the work was waiting for a
     * worker. The timer runs only while a scan in this list is unsettled, and stops by itself when
     * the last one has finished — an idle estate costs nothing.
     */
    private readonly scanInFlight = computed(() => anyScanRunning(this.repositories().map((row) => row.lastScan)));

    /**
     * The list's request, latest wins: a poll tick and the reload after a save can be in flight
     * together, and the older answer landing last put rows back that the newer one had changed.
     */
    private readonly listRequest = new LatestRequest();
    /** The list's own failure, told apart from an action's: a poll that recovers clears only its own. */
    private listError: string | null = null;

    /**
     * Client-side pages, and the one the reader is on. A forge import registers hundreds of
     * repositories at once, and one card each made a page nobody could scroll to the end of. The
     * page is kept across the refreshes, which replace the list underneath it.
     */
    readonly pageSize = PAGE_SIZE;
    readonly first = signal(0);

    constructor() {
        // In the background: no overlay. Raised every five seconds while a scan ran, it flashed
        // over the whole list and swallowed the clicks of whoever was reading it.
        pollWhile(this.scanInFlight, () => this.reload(true));
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

    reload(background = false): void {
        if (!background) this.loading.set(true);
        this.listRequest.run(this.targetsApi.repositories(), {
            next: (repositories) => {
                this.repositories.set(repositories);
                this.first.set(pageHolding(this.first(), repositories.length));
                // A refresh nobody asked for leaves an action's error in place; it clears its own.
                if (!background || this.error() === this.listError) this.error.set(null);
                this.listError = null;
                this.loading.set(false);
            },
            error: (response: unknown) => {
                this.listError = messageOf(response, this.i18n.t('repositories.error_load'));
                this.error.set(this.listError);
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

    askDelete(repository: MonitoredRepository): void {
        this.pendingDelete.set(repository);
        this.deleteVisible.set(true);
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

    /** The scorecard of a repository, and its badge state — a separate read a reader may not be allowed. */
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
}
