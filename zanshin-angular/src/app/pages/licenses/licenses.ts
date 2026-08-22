import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { MessageModule } from '@openng/optimus-ui/message';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { SelectModule } from '@openng/optimus-ui/select';
import { ApiService } from '../../core/api.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import type { MonitoredContainer, MonitoredRepository, LicenseEntry, LicensePolicy, LicenseRiskCategory, LicenseSummary } from '../../core/api.models';

@Component({
    selector: 'app-licenses',
    standalone: true,
    imports: [CommonModule, FormsModule, CardModule, ButtonModule, MessageModule, TableModule, TagModule, SelectModule, TranslatePipe],
    templateUrl: './licenses.html'
})
export class Licenses {
    private readonly api = inject(ApiService);

    readonly summary = signal<LicenseSummary | null>(null);
    readonly inventory = signal<LicenseEntry[]>([]);
    readonly policy = signal<LicensePolicy | null>(null);
    readonly repos = signal<MonitoredRepository[]>([]);
    readonly containers = signal<MonitoredContainer[]>([]);
    readonly loading = signal<boolean>(true);
    readonly error = signal<string | null>(null);

    readonly selectedTarget = signal<string>('ALL');
    readonly selectedRisk = signal<string>('ALL');
    readonly selectedCompliance = signal<string>('ALL');

    readonly targetOptions = computed(() => {
        const options: { label: string; value: string }[] = [{ label: 'All targets / Toutes les cibles', value: 'ALL' }];
        for (const r of this.repos()) {
            options.push({ label: `Repository: ${r.displayName || r.name}`, value: `repo:${r.id}` });
        }
        for (const c of this.containers()) {
            options.push({ label: `Container: ${c.reference}`, value: `container:${c.id}` });
        }
        return options;
    });

    readonly filteredInventory = computed(() => {
        let items = this.inventory();
        const risk = this.selectedRisk();
        const comp = this.selectedCompliance();

        if (risk !== 'ALL') {
            items = items.filter((i) => i.riskCategory === risk);
        }
        if (comp === 'COMPLIANT') {
            items = items.filter((i) => i.compliant);
        } else if (comp === 'NON_COMPLIANT') {
            items = items.filter((i) => !i.compliant);
        }
        return items;
    });

    constructor() {
        this.loadTargets();
        this.loadData();
    }

    loadTargets(): void {
        this.api.repositories().subscribe({
            next: (r) => this.repos.set(r),
            error: () => {}
        });
        this.api.containers().subscribe({
            next: (c) => this.containers.set(c),
            error: () => {}
        });
    }

    onTargetChange(target: string): void {
        this.selectedTarget.set(target);
        this.loadData();
    }

    loadData(): void {
        this.loading.set(true);
        this.error.set(null);

        let repoId: number | undefined;
        let containerId: number | undefined;
        const target = this.selectedTarget();
        if (target.startsWith('repo:')) {
            repoId = Number(target.substring(5));
        } else if (target.startsWith('container:')) {
            containerId = Number(target.substring(10));
        }

        this.api.getLicenseSummary(repoId, containerId).subscribe({
            next: (s) => this.summary.set(s),
            error: () => this.error.set('Failed to load license summary.')
        });

        this.api.getLicensePolicy().subscribe({
            next: (p) => this.policy.set(p),
            error: () => {}
        });

        this.api.getLicenseInventory(repoId, containerId).subscribe({
            next: (inv) => {
                this.inventory.set(inv);
                this.loading.set(false);
            },
            error: () => {
                this.error.set('Failed to load license inventory.');
                this.loading.set(false);
            }
        });
    }

    riskSeverity(category: LicenseRiskCategory): 'success' | 'warn' | 'danger' | 'secondary' {
        switch (category) {
            case 'PERMISSIVE': return 'success';
            case 'WEAK_COPYLEFT': return 'warn';
            case 'STRONG_COPYLEFT': return 'danger';
            case 'FORBIDDEN': return 'danger';
            default: return 'secondary';
        }
    }
}
