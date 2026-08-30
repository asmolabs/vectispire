import { CommonModule } from '@angular/common';
import { Component, OnDestroy, OnInit, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { SelectModule } from '@openng/optimus-ui/select';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { messageOf } from '../../core/api-error';
import { ApiService } from '../../core/api.service';
import { saveDocument } from '../../core/download';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import type {
    ApiContractView,
    ApiEndpointView,
    GlobalAttackSurface,
    MonitoredRepository,
    RepositoryApisOverview
} from '../../core/api.models';

@Component({
    selector: 'app-attack-surface',
    standalone: true,
    imports: [
        CommonModule,
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
    templateUrl: './attack-surface.html'
})
export class AttackSurface implements OnInit, OnDestroy {
    private readonly api = inject(ApiService);
    readonly i18n = inject(I18nService);
    private pollInterval: any = null;

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

    ngOnInit(): void {
        this.loadData();
    }

    loadData(): void {
        this.loading.set(true);
        this.error.set(null);

        this.api.getAttackSurface().subscribe({
            next: (global) => {
                this.globalData.set(global);
                this.loading.set(false);
            },
            error: (err) => {
                this.error.set(err?.error?.message ?? 'Erreur lors du chargement de la surface d\'attaque.');
                this.loading.set(false);
            }
        });

        this.api.repositories().subscribe({
            next: (repos) => {
                this.repositories.set(repos);
            },
            error: () => {}
        });
    }

    onSelectRepo(repoId: string | number | null): void {
        if (!repoId || repoId === 'ALL' || repoId === '0') {
            this.selectedRepoId.set(null);
            this.repoOverview.set(null);
            this.repoLoading.set(false);
            return;
        }

        const id = Number(repoId);
        this.selectedRepoId.set(String(id));
        this.repoLoading.set(true);

        this.api.getRepositoryApis(id).subscribe({
            next: (data) => {
                this.repoOverview.set(data);
                this.repoLoading.set(false);
            },
            error: (err) => {
                this.error.set(err?.error?.message ?? 'Erreur lors du chargement des APIs du dépôt.');
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
            list = list.filter((ep) => !Boolean(ep.authRequired));
        }

        return list;
    });

    exportOpenApi(): void {
        const repoId = this.selectedRepoId();
        if (!repoId || repoId === 'ALL') return;

        const id = Number(repoId);
        this.exporting.set(true);
        this.api.exportSynthesizedOpenApi(id).subscribe({
            next: (response) => {
                saveDocument(response, `openapi-repository-${id}.json`);
                this.exporting.set(false);
            },
            error: (err) => {
                this.error.set(err?.error?.message ?? 'Échec de l\'export OpenAPI.');
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

        const request$ = (!repoId || repoId === 'ALL')
            ? this.api.clearAttackSurface()
            : this.api.clearRepositoryApis(Number(repoId));

        request$.subscribe({
            next: () => {
                this.clearing.set(false);
                this.scanSuccess.set('Surface d\'attaque purgée avec succès.');
                this.loadData();
                if (repoId && repoId !== 'ALL') {
                    this.onSelectRepo(repoId);
                }
            },
            error: (err) => {
                this.clearing.set(false);
                this.error.set(messageOf(err, 'Échec lors de la purge de la surface d\'attaque.'));
            }
        });
    }

    ngOnDestroy(): void {
        this.stopPolling();
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

        this.api.triggerRepositoryScan(id).subscribe({
            next: () => {
                this.scanningRepo.set(false);
                this.scanSuccess.set('Scan planifié. Analyse des routes d\'APIs en cours d\'exécution...');
                this.startPolling();
            },
            error: (err) => {
                this.scanningRepo.set(false);
                this.error.set(err?.error?.message ?? 'Impossible de lancer l\'analyse.');
            }
        });
    }

    triggerScanAll(): void {
        const repos = this.repositories();
        if (repos.length === 0) return;

        this.scanningRepo.set(true);
        this.error.set(null);
        this.scanSuccess.set(null);

        const requests = repos.map((r) => this.api.triggerRepositoryScan(r.id));
        import('rxjs').then(({ forkJoin }) => {
            forkJoin(requests).subscribe({
                next: (results) => {
                    this.scanningRepo.set(false);
                    this.scanSuccess.set(`Scan planifié pour ${results.length} dépôts. Analyse et découverte en cours...`);
                    this.startPolling();
                },
                error: (err) => {
                    this.scanningRepo.set(false);
                    this.error.set(err?.error?.message ?? 'Impossible de lancer le scan global des dépôts.');
                }
            });
        });
    }

    private startPolling(): void {
        this.stopPolling();
        let attempts = 0;
        this.pollInterval = setInterval(() => {
            attempts++;
            this.loadData();
            if (this.selectedRepoId()) {
                this.onSelectRepo(this.selectedRepoId()!);
            }
            const currentCount = this.repoOverview()?.endpoints?.length ?? 0;
            const globalCount = this.globalData()?.totalEndpoints ?? 0;
            if (currentCount > 0 || globalCount > 0 || attempts >= 25) {
                if (currentCount > 0 || globalCount > 0) {
                    this.scanSuccess.set(`Découverte d'APIs terminée avec succès (${globalCount || currentCount} routes répertoriées).`);
                    this.stopPolling();
                } else if (attempts >= 25) {
                    this.stopPolling();
                }
            }
        }, 3000);
    }

    private stopPolling(): void {
        if (this.pollInterval) {
            clearInterval(this.pollInterval);
            this.pollInterval = null;
        }
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
