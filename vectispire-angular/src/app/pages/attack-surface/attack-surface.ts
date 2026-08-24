import { CommonModule } from '@angular/common';
import { Component, OnInit, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { SelectModule } from '@openng/optimus-ui/select';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
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
export class AttackSurface implements OnInit {
    private readonly api = inject(ApiService);
    readonly i18n = inject(I18nService);

    readonly loading = signal<boolean>(true);
    readonly repoLoading = signal<boolean>(false);
    readonly error = signal<string | null>(null);
    readonly exporting = signal<boolean>(false);

    readonly globalData = signal<GlobalAttackSurface | null>(null);
    readonly repositories = signal<MonitoredRepository[]>([]);
    readonly selectedRepoId = signal<number | null>(null);
    readonly repoOverview = signal<RepositoryApisOverview | null>(null);

    readonly activeTab = signal<'endpoints' | 'contracts' | 'highrisk'>('endpoints');
    readonly searchQuery = signal<string>('');
    readonly filterMethod = signal<string>('ALL');
    readonly filterVisibility = signal<string>('ALL');
    readonly filterAuth = signal<string>('ALL');

    readonly methodOptions = [
        { label: 'Toutes les méthodes', value: 'ALL' },
        { label: 'GET', value: 'GET' },
        { label: 'POST', value: 'POST' },
        { label: 'PUT', value: 'PUT' },
        { label: 'DELETE', value: 'DELETE' },
        { label: 'PATCH', value: 'PATCH' }
    ];

    readonly visibilityOptions = [
        { label: 'Toutes visibilités', value: 'ALL' },
        { label: 'Public (Exposé)', value: 'PUBLIC' },
        { label: 'Interne', value: 'INTERNAL' },
        { label: 'Inconnu', value: 'UNKNOWN' }
    ];

    readonly authOptions = [
        { label: 'Tous statuts auth', value: 'ALL' },
        { label: 'Authentifié requis', value: 'AUTH' },
        { label: 'Non authentifié (Public)', value: 'UNAUTH' }
    ];

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
                if (repos.length > 0 && this.selectedRepoId() === null) {
                    this.onSelectRepo(repos[0].id);
                }
            },
            error: () => {}
        });
    }

    onSelectRepo(repoId: number): void {
        this.selectedRepoId.set(repoId);
        this.repoLoading.set(true);

        this.api.getRepositoryApis(repoId).subscribe({
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
        const overview = this.repoOverview();
        if (!overview || !overview.endpoints) return [];

        let list = overview.endpoints;
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
            list = list.filter((ep) => ep.authRequired);
        } else if (a === 'UNAUTH') {
            list = list.filter((ep) => !ep.authRequired);
        }

        return list;
    });

    exportOpenApi(): void {
        const repoId = this.selectedRepoId();
        if (!repoId) return;

        this.exporting.set(true);
        this.api.exportSynthesizedOpenApi(repoId).subscribe({
            next: (response) => {
                saveDocument(response, `openapi-repository-${repoId}.json`);
                this.exporting.set(false);
            },
            error: (err) => {
                this.error.set(err?.error?.message ?? 'Échec de l\'export OpenAPI.');
                this.exporting.set(false);
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
