import { CommonModule } from '@angular/common';
import { Component, OnInit, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { MessageModule } from '@openng/optimus-ui/message';
import { SelectModule } from '@openng/optimus-ui/select';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { ApiService } from '../../core/api.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import type {
    AttackPath,
    AttackPathEdge,
    AttackPathGraph,
    AttackPathNode,
    MonitoredRepository
} from '../../core/api.models';

@Component({
    selector: 'app-attack-paths',
    standalone: true,
    imports: [
        CommonModule,
        FormsModule,
        RouterLink,
        ButtonModule,
        CardModule,
        DialogModule,
        MessageModule,
        SelectModule,
        TableModule,
        TagModule,
        TranslatePipe
    ],
    templateUrl: './attack-paths.html'
})
export class AttackPaths implements OnInit {
    private readonly api = inject(ApiService);

    readonly repositories = signal<MonitoredRepository[]>([]);
    readonly selectedRepoId = signal<number | null>(null);
    readonly graph = signal<AttackPathGraph | null>(null);
    readonly overviewList = signal<AttackPathGraph[]>([]);
    readonly loading = signal<boolean>(false);
    readonly error = signal<string | null>(null);

    readonly selectedNode = signal<AttackPathNode | null>(null);
    readonly nodeDetailsVisible = signal<boolean>(false);
    readonly selectedPath = signal<AttackPath | null>(null);
    readonly filterCriticalOnly = signal<boolean>(false);
    readonly activeTab = signal<'graph' | 'paths' | 'overview'>('graph');

    // Grouping nodes by logical topological column
    readonly ingressNodes = computed(() => {
        const g = this.graph();
        if (!g) return [];
        return g.nodes.filter(n => n.type === 'INTERNET_INGRESS');
    });

    readonly endpointNodes = computed(() => {
        const g = this.graph();
        if (!g) return [];
        const nodes = g.nodes.filter(n => n.type === 'API_ENDPOINT');
        return this.filterCriticalOnly() ? nodes.filter(n => n.isExploitable) : nodes;
    });

    readonly vulnNodes = computed(() => {
        const g = this.graph();
        if (!g) return [];
        const nodes = g.nodes.filter(n => n.type === 'VULNERABLE_COMPONENT');
        return this.filterCriticalOnly() ? nodes.filter(n => n.isExploitable) : nodes;
    });

    readonly sinkNodes = computed(() => {
        const g = this.graph();
        if (!g) return [];
        return g.nodes.filter(n => n.type === 'SECRET' || n.type === 'DATABASE' || n.type === 'INFRASTRUCTURE');
    });

    readonly highlightedNodeIds = computed(() => {
        const sp = this.selectedPath();
        if (!sp) return new Set<string>();
        return new Set(sp.nodeIds);
    });

    ngOnInit(): void {
        this.loadRepositories();
        this.loadOverview();
    }

    loadRepositories(): void {
        this.api.repositories().subscribe({
            next: (repos) => {
                this.repositories.set(repos);
                if (repos.length > 0 && !this.selectedRepoId()) {
                    this.selectedRepoId.set(repos[0].id);
                    this.loadGraph(repos[0].id);
                }
            },
            error: () => this.error.set('Impossible de charger la liste des dépôts.')
        });
    }

    loadOverview(): void {
        this.api.getAttackPathsOverview().subscribe({
            next: (list) => this.overviewList.set(list),
            error: () => {}
        });
    }

    onRepoChange(repoId: number): void {
        this.selectedRepoId.set(repoId);
        this.selectedNode.set(null);
        this.selectedPath.set(null);
        this.loadGraph(repoId);
    }

    loadGraph(repoId: number): void {
        this.loading.set(true);
        this.error.set(null);
        this.api.getAttackPathGraph(repoId).subscribe({
            next: (g) => {
                this.graph.set(g);
                this.loading.set(false);
            },
            error: () => {
                this.error.set('Erreur lors de la génération du graphe des chemins d\'attaque.');
                this.loading.set(false);
            }
        });
    }

    inspectNode(node: AttackPathNode): void {
        this.selectedNode.set(node);
        this.nodeDetailsVisible.set(true);
    }

    focusPath(path: AttackPath | null): void {
        if (this.selectedPath()?.id === path?.id) {
            this.selectedPath.set(null);
        } else {
            this.selectedPath.set(path);
        }
    }

    getNodeIcon(type: string): string {
        switch (type) {
            case 'INTERNET_INGRESS': return 'pi pi-globe text-blue-500';
            case 'API_ENDPOINT': return 'pi pi-link text-amber-500';
            case 'VULNERABLE_COMPONENT': return 'pi pi-shield text-rose-500';
            case 'SECRET': return 'pi pi-key text-yellow-500';
            case 'DATABASE': return 'pi pi-database text-purple-500';
            default: return 'pi pi-box text-surface-400';
        }
    }

    getSeverityBadge(sev: string): 'danger' | 'warn' | 'info' | 'success' | 'secondary' {
        switch (sev?.toUpperCase()) {
            case 'CRITICAL': return 'danger';
            case 'HIGH': return 'warn';
            case 'MEDIUM': return 'info';
            case 'LOW': return 'success';
            default: return 'secondary';
        }
    }

    getRiskScoreColor(score: number): string {
        if (score >= 75) return 'text-rose-600 dark:text-rose-400';
        if (score >= 40) return 'text-amber-500';
        return 'text-emerald-600 dark:text-emerald-400';
    }
}
