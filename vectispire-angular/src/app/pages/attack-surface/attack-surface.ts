import { DatePipe, NgClass } from '@angular/common';
import { Component, OnInit, computed, inject, signal, ChangeDetectionStrategy } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { SelectModule } from '@openng/optimus-ui/select';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { messageOf } from '../../core/api-error';
import { ExposureApi } from '../../core/api/exposure.api';
import { TargetsApi } from '../../core/api/targets.api';
import { ScansApi } from '../../core/api/scans.api';
import { saveDocument } from '../../core/download';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { LatestRequest } from '@/app/core/latest-request';
import { anyScanRunning, pollWhile } from '@/app/core/poll-while';
import type {
    ApiEndpointView,
    GlobalAttackSurface,
    MonitoredRepository,
    RepositoryApisOverview
} from '../../core/api.models';

@Component({
    selector: 'app-attack-surface',
    imports: [
        DatePipe,
        NgClass,
        FormsModule,
        ButtonModule,
        CardModule,
        InputTextModule,
        MessageModule,
        SelectModule,
        TableModule,
        TagModule,
        TranslatePipe
    ],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './attack-surface.html'
})
export class AttackSurface implements OnInit {
    private readonly repoRequest = new LatestRequest();
    /** The estate's figures and the repository list, each latest-wins: a purge's reload, or the one
     *  that follows a scan, sent two more requests while the first two could still be running. */
    private readonly surfaceRequest = new LatestRequest();
    private readonly repositoriesRequest = new LatestRequest();

    private readonly exposureApi = inject(ExposureApi);
    private readonly targetsApi = inject(TargetsApi);
    private readonly scansApi = inject(ScansApi);
    readonly i18n = inject(I18nService);

    /**
     * The scans launched from this screen, with the status last read for each.
     *
     * <p>The screen used to poll its own figures every three seconds and stop at the first tick that
     * found an endpoint — so on an estate that already had some, it stopped at once and announced
     * "discovery complete" for a scan that was only queued. What ends the wait is the scan's own
     * status, read from the repository list (one request for every scan launched, not one each).
     */
    private readonly watchedScans = signal<readonly { repositoryId: number; id: number; status: string }[]>([]);
    private readonly scanInFlight = computed(() => anyScanRunning(this.watchedScans()));

    readonly loading = signal<boolean>(true);
    readonly repoLoading = signal<boolean>(false);
    readonly error = signal<string | null>(null);
    readonly exporting = signal<boolean>(false);
    readonly scanningRepo = signal<boolean>(false);
    readonly scanSuccess = signal<string | null>(null);

    readonly globalData = signal<GlobalAttackSurface | null>(null);
    readonly repositories = signal<MonitoredRepository[]>([]);
    readonly selectedRepoId = signal<string | null>(null);
    readonly repoOverview = signal<RepositoryApisOverview | null>(null);

    readonly repoOptions = computed(() => {
        const repos = this.repositories();
        return repos.map((r) => ({ label: r.displayName || r.name, value: String(r.id) }));
    });

    readonly currentStats = computed(() => {
        const repo = this.repoOverview();
        if (this.selectedRepoId() && repo) {
            const sum = repo.summary;
            const frameworks: string[] = [];
            repo.endpoints.forEach((e) => {
                if (e.framework && !frameworks.includes(e.framework)) {
                    frameworks.push(e.framework);
                }
            });
            return {
                totalEndpoints: sum.totalEndpoints,
                publicEndpoints: sum.publicEndpoints,
                unauthenticatedEndpoints: sum.unauthenticatedEndpoints,
                shadowEndpoints: sum.shadowEndpoints,
                sensitiveUnprotectedEndpoints: sum.sensitiveUnprotectedEndpoints,
                frameworks
            };
        }
        const g = this.globalData();
        return {
            totalEndpoints: g?.totalEndpoints ?? 0,
            publicEndpoints: g?.publicEndpoints ?? 0,
            unauthenticatedEndpoints: g?.unauthenticatedEndpoints ?? 0,
            shadowEndpoints: g?.shadowEndpoints ?? 0,
            sensitiveUnprotectedEndpoints: g?.sensitiveUnprotectedEndpoints ?? 0,
            frameworks: g?.frameworks ?? []
        };
    });

    readonly activeTab = signal<'endpoints' | 'contracts' | 'highrisk'>('endpoints');
    readonly searchQuery = signal<string>('');
    readonly filterMethod = signal<string>('ALL');
    readonly filterVisibility = signal<string>('ALL');
    readonly filterAuth = signal<string>('ALL');

    readonly methodOptions = computed(() => {
        this.i18n.translations();
        return [
            { label: this.i18n.t('attack_surface.methods.all'), value: 'ALL' },
            { label: this.i18n.t('attack_surface.methods.get'), value: 'GET' },
            { label: this.i18n.t('attack_surface.methods.post'), value: 'POST' },
            { label: this.i18n.t('attack_surface.methods.put'), value: 'PUT' },
            { label: this.i18n.t('attack_surface.methods.delete'), value: 'DELETE' },
            { label: this.i18n.t('attack_surface.methods.patch'), value: 'PATCH' }
        ];
    });

    readonly visibilityOptions = computed(() => {
        this.i18n.translations();
        return [
            { label: this.i18n.t('attack_surface.visibility.all'), value: 'ALL' },
            { label: this.i18n.t('attack_surface.visibility.public'), value: 'PUBLIC' },
            { label: this.i18n.t('attack_surface.visibility.internal'), value: 'INTERNAL' },
            { label: this.i18n.t('attack_surface.visibility.unknown'), value: 'UNKNOWN' }
        ];
    });

    readonly authOptions = computed(() => {
        this.i18n.translations();
        return [
            { label: this.i18n.t('attack_surface.auth.all'), value: 'ALL' },
            { label: this.i18n.t('attack_surface.auth.required'), value: 'AUTH' },
            { label: this.i18n.t('attack_surface.auth.none'), value: 'UNAUTH' }
        ];
    });

    constructor() {
        pollWhile(this.scanInFlight, () => this.refreshScans(), 3000);
    }

    ngOnInit(): void {
        this.loadData();
    }

    /**
     * The estate's figures and the repository list. `background` reloads them once the scans launched
     * here have finished: no loading state then — the tables blanking under the reader for an
     * answer that only adds rows is noise — and, when every scan completed, the count announced is
     * the one just read.
     */
    loadData(background: 'quiet' | 'announce' | null = null): void {
        if (!background) {
            this.loading.set(true);
            this.error.set(null);
        }

        this.surfaceRequest.run(this.exposureApi.getAttackSurface(), {
            next: (global) => {
                this.globalData.set(global);
                this.loading.set(false);
                if (background === 'announce') {
                    this.scanSuccess.set(
                        this.i18n.t('attack_surface.discovery_complete', { count: global.totalEndpoints })
                    );
                }
            },
            error: (err) => {
                this.error.set(messageOf(err, this.i18n.t('attack_surface.error_load')));
                this.loading.set(false);
            }
        });

        this.repositoriesRequest.run(this.targetsApi.repositories(), {
            next: (repos) => this.repositories.set(repos),
            // Swallowed, it left the repository picker empty with no reason given.
            error: (err) => this.error.set(messageOf(err, this.i18n.t('repositories.error_load')))
        });
    }

    /** One tick of the wait: the repository list carries each repository's latest scan and status. */
    private refreshScans(): void {
        this.repositoriesRequest.run(this.targetsApi.repositories(), {
            next: (repos) => {
                this.repositories.set(repos);
                const watched = this.watchedScans().map((scan) => {
                    const latest = repos.find((repo) => repo.id === scan.repositoryId)?.lastScan;
                    // A repository gone from the list has nothing left to wait for; a newer scan of
                    // the same repository is what its routes now depend on, so its status stands.
                    if (!latest) return { ...scan, status: 'cancelled' };
                    return latest.id >= scan.id ? { ...scan, status: latest.status } : scan;
                });
                this.watchedScans.set(watched);
                if (!anyScanRunning(watched)) {
                    this.scansSettled(watched);
                }
            },
            // A tick that fails is retried by the next one; the wait goes on.
            error: () => {}
        });
    }

    /** Discovery is complete only when every scan completed: a failed one found no route at all. */
    private scansSettled(scans: readonly { status: string }[]): void {
        const failed = scans.filter((scan) => scan.status.toLowerCase() !== 'completed').length;
        if (failed > 0) {
            this.scanSuccess.set(null);
            this.error.set(this.i18n.t('attack_surface.scan_failed', { count: failed }));
        }
        this.loadData(failed > 0 ? 'quiet' : 'announce');
        const selected = this.selectedRepoId();
        if (selected) {
            this.onSelectRepo(selected, true);
        }
    }

    /** `background` reloads the routes of the repository already shown: no mask over its table then. */
    onSelectRepo(repoId: string | number | null, background = false): void {
        if (!repoId || repoId === 'ALL' || repoId === '0') {
            this.repoRequest.cancel();
            this.selectedRepoId.set(null);
            this.repoOverview.set(null);
            this.repoLoading.set(false);
            return;
        }

        const id = Number(repoId);
        this.selectedRepoId.set(String(id));
        if (!background) this.repoLoading.set(true);

        this.repoRequest.run(this.exposureApi.getRepositoryApis(id), {
            next: (data) => {
                this.repoOverview.set(data);
                this.repoLoading.set(false);
            },
            error: (err) => {
                this.error.set(messageOf(err, this.i18n.t('attack_surface.error_repo_apis')));
                this.repoLoading.set(false);
            }
        });
    }

    readonly filteredEndpoints = computed<ApiEndpointView[]>(() => {
        const repoId = this.selectedRepoId();
        if (!repoId) {
            return [];
        }

        const overview = this.repoOverview();
        let list: ApiEndpointView[] = overview?.endpoints || [];

        const q = this.searchQuery().trim().toLowerCase();
        const m = this.filterMethod();
        const v = this.filterVisibility();
        const a = this.filterAuth();

        if (q) {
            list = list.filter(
                (ep) =>
                    ep.path.toLowerCase().includes(q) ||
                    (ep.summary && ep.summary.toLowerCase().includes(q)) ||
                    (ep.filePath && ep.filePath.toLowerCase().includes(q))
            );
        }

        if (m !== 'ALL') {
            list = list.filter((ep) => ep.method.toUpperCase() === m);
        }

        if (v !== 'ALL') {
            list = list.filter((ep) => ep.visibility === v);
        }

        if (a === 'AUTH') {
            list = list.filter((ep) => Boolean(ep.authRequired));
        } else if (a === 'UNAUTH') {
            list = list.filter((ep) => !ep.authRequired);
        }

        return list;
    });

    exportOpenApi(): void {
        const repoId = this.selectedRepoId();
        if (!repoId || repoId === 'ALL') return;

        const id = Number(repoId);
        this.exporting.set(true);
        this.exposureApi.exportSynthesizedOpenApi(id).subscribe({
            next: (response) => {
                saveDocument(response, `openapi-repository-${id}.json`);
                this.exporting.set(false);
            },
            error: (err) => {
                this.error.set(messageOf(err, this.i18n.t('attack_surface.error_export')));
                this.exporting.set(false);
            }
        });
    }

    readonly clearing = signal<boolean>(false);

    clearInventory(): void {
        const repoId = this.selectedRepoId();
        this.clearing.set(true);
        this.error.set(null);
        this.scanSuccess.set(null);

        const request$ =
            !repoId || repoId === 'ALL'
                ? this.exposureApi.clearAttackSurface()
                : this.exposureApi.clearRepositoryApis(Number(repoId));

        request$.subscribe({
            next: () => {
                this.clearing.set(false);
                this.scanSuccess.set(this.i18n.t('attack_surface.cleared'));
                this.loadData();
                if (repoId && repoId !== 'ALL') {
                    this.onSelectRepo(repoId);
                }
            },
            error: (err) => {
                this.clearing.set(false);
                this.error.set(messageOf(err, this.i18n.t('attack_surface.error_clear')));
            }
        });
    }

    triggerScan(): void {
        const repoId = this.selectedRepoId();
        if (!repoId) return;

        if (repoId === 'ALL') {
            this.triggerScanAll();
            return;
        }

        const id = Number(repoId);
        this.scanningRepo.set(true);
        this.error.set(null);
        this.scanSuccess.set(null);

        this.scansApi.triggerRepositoryScan(id).subscribe({
            next: (queued) => {
                this.scanningRepo.set(false);
                this.scanSuccess.set(this.i18n.t('attack_surface.scan_scheduled'));
                this.watchedScans.set([{ repositoryId: id, id: queued.id, status: queued.status }]);
            },
            error: (err) => {
                this.scanningRepo.set(false);
                this.error.set(messageOf(err, this.i18n.t('attack_surface.error_scan')));
            }
        });
    }

    triggerScanAll(): void {
        const repos = this.repositories();
        if (repos.length === 0) return;

        this.scanningRepo.set(true);
        this.error.set(null);
        this.scanSuccess.set(null);

        const requests = repos.map((r) => this.scansApi.triggerRepositoryScan(r.id));
        void import('rxjs').then(({ forkJoin }) => {
            forkJoin(requests).subscribe({
                next: (results) => {
                    this.scanningRepo.set(false);
                    this.scanSuccess.set(this.i18n.t('attack_surface.scan_scheduled_all', { count: results.length }));
                    this.watchedScans.set(
                        results.map((queued, i) => ({
                            repositoryId: repos[i].id,
                            id: queued.id,
                            status: queued.status
                        }))
                    );
                },
                error: (err) => {
                    this.scanningRepo.set(false);
                    this.error.set(messageOf(err, this.i18n.t('attack_surface.error_scan_all')));
                }
            });
        });
    }

    getMethodSeverity(method: string): 'info' | 'success' | 'warn' | 'danger' | 'secondary' {
        switch (method?.toUpperCase()) {
            case 'GET':
                return 'info';
            case 'POST':
                return 'success';
            case 'PUT':
            case 'PATCH':
                return 'warn';
            case 'DELETE':
                return 'danger';
            default:
                return 'secondary';
        }
    }

    getShadowSeverity(status: string): 'success' | 'warn' | 'danger' | 'secondary' {
        switch (status) {
            case 'DOCUMENTED':
                return 'success';
            case 'SHADOW_API':
                return 'danger';
            case 'UNDOCUMENTED':
                return 'warn';
            case 'HIGH_RISK_EXPOSURE':
                return 'danger';
            default:
                return 'secondary';
        }
    }
}
