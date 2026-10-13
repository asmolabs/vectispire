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
import { saveDocument } from '../../core/download';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { LatestRequest } from '@/app/core/latest-request';
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
    /** The estate's figures and the repository list, each latest-wins: a purge's reload sent two more
     *  requests while the first two could still be running. */
    private readonly surfaceRequest = new LatestRequest();
    private readonly repositoriesRequest = new LatestRequest();

    private readonly exposureApi = inject(ExposureApi);
    private readonly targetsApi = inject(TargetsApi);
    readonly i18n = inject(I18nService);

    readonly loading = signal<boolean>(true);
    readonly repoLoading = signal<boolean>(false);
    readonly error = signal<string | null>(null);
    readonly exporting = signal<boolean>(false);
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

    ngOnInit(): void {
        this.loadData();
    }

    loadData(): void {
        this.loading.set(true);
        this.error.set(null);

        this.surfaceRequest.run(this.exposureApi.getAttackSurface(), {
            next: (global) => {
                this.globalData.set(global);
                this.loading.set(false);
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

    onSelectRepo(repoId: string | number | null): void {
        if (!repoId || repoId === 'ALL' || repoId === '0') {
            this.repoRequest.cancel();
            this.selectedRepoId.set(null);
            this.repoOverview.set(null);
            this.repoLoading.set(false);
            return;
        }

        const id = Number(repoId);
        this.selectedRepoId.set(String(id));
        this.repoLoading.set(true);

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
