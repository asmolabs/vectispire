import { Component, OnInit, signal, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ApiService } from '../../core/api.service';
import { BlastRadiusReport, TopImpactPackage, TargetImpact, DependencyGraph } from '../../core/api.models';
import { ButtonModule } from '@openng/optimus-ui/button';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { MessageModule } from '@openng/optimus-ui/message';
import { ProgressSpinnerModule } from '@openng/optimus-ui/progressspinner';
import { RouterLink } from '@angular/router';

@Component({
    selector: 'app-blast-radius',
    standalone: true,
    imports: [
        CommonModule,
        FormsModule,
        ButtonModule,
        InputTextModule,
        TableModule,
        TagModule,
        MessageModule,
        ProgressSpinnerModule,
        RouterLink
    ],
    templateUrl: './blast-radius.html'
})
export class BlastRadius implements OnInit {
    private readonly api = inject(ApiService);

    searchQuery = '';
    readonly loading = signal<boolean>(false);
    readonly error = signal<string | null>(null);
    readonly report = signal<BlastRadiusReport | null>(null);
    readonly topPackages = signal<TopImpactPackage[]>([]);
    readonly selectedNodeId = signal<string | null>(null);

    ngOnInit(): void {
        this.loadTopPackages();
    }

    loadTopPackages(): void {
        this.loading.set(true);
        this.api.getTopBlastRadius(12).subscribe({
            next: (data) => {
                this.topPackages.set(data);
                this.loading.set(false);
            },
            error: () => {
                this.loading.set(false);
            }
        });
    }

    explore(query?: string): void {
        if (query !== undefined) {
            this.searchQuery = query;
        }

        const trimmed = this.searchQuery.trim();
        if (!trimmed) {
            this.report.set(null);
            this.selectedNodeId.set(null);
            return;
        }

        this.loading.set(true);
        this.error.set(null);

        this.api.exploreBlastRadius(trimmed).subscribe({
            next: (data) => {
                this.report.set(data);
                this.loading.set(false);
            },
            error: (err) => {
                this.error.set(err?.error?.message ?? 'Erreur lors de l\'exploration du graphe de dépendances.');
                this.loading.set(false);
            }
        });
    }

    resetSearch(): void {
        this.searchQuery = '';
        this.report.set(null);
        this.selectedNodeId.set(null);
    }

    selectQuickPackage(pkg: string): void {
        this.searchQuery = pkg;
        this.explore(pkg);
    }

    selectNode(node: { id: string; label: string; type: string }): void {
        this.selectedNodeId.set(node.id);
        this.selectQuickPackage(node.label);
    }

    getScoreSeverity(score: number): 'success' | 'warn' | 'danger' {
        if (score >= 70) return 'danger';
        if (score >= 40) return 'warn';
        return 'success';
    }

    getReachabilitySeverity(reachability: string): 'success' | 'warn' | 'danger' | 'info' {
        if (reachability === 'REACHABLE') return 'danger';
        if (reachability === 'UNREACHABLE') return 'success';
        return 'info';
    }
}
