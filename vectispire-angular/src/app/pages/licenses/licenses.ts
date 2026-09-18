import { CommonModule } from '@angular/common';
import { I18nService } from '../../core/i18n/i18n.service';
import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { MessageModule } from '@openng/optimus-ui/message';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { SelectModule } from '@openng/optimus-ui/select';
import { ToggleSwitchModule } from '@openng/optimus-ui/toggleswitch';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { messageOf } from '../../core/api-error';
import { ApiService } from '../../core/api.service';
import { SessionStore } from '../../core/session.store';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import type {
    MonitoredContainer,
    MonitoredRepository,
    LicenseEntry,
    LicensePolicy,
    LicenseRiskCategory,
    LicenseSummary,
    LicenseConflict,
    CompatibilityCell
} from '../../core/api.models';

@Component({
    selector: 'app-licenses',
    standalone: true,
    imports: [
        CommonModule,
        FormsModule,
        CardModule,
        ButtonModule,
        MessageModule,
        TableModule,
        TagModule,
        SelectModule,
        ToggleSwitchModule,
        InputTextModule,
        TranslatePipe
    ],
    templateUrl: './licenses.html'
})
export class Licenses {
    private readonly i18n = inject(I18nService);
    private readonly api = inject(ApiService);
    private readonly session = inject(SessionStore);

    readonly summary = signal<LicenseSummary | null>(null);
    readonly inventory = signal<LicenseEntry[]>([]);
    readonly policy = signal<LicensePolicy | null>(null);
    readonly conflicts = signal<LicenseConflict[]>([]);
    readonly matrixRules = signal<CompatibilityCell[]>([]);
    readonly repos = signal<MonitoredRepository[]>([]);
    readonly containers = signal<MonitoredContainer[]>([]);
    readonly loading = signal<boolean>(true);
    readonly error = signal<string | null>(null);

    readonly activeTab = signal<'inventory' | 'conflicts' | 'matrix'>('inventory');
    readonly proprietaryMode = signal<boolean>(true);
    readonly selectedTarget = signal<string>('ALL');
    readonly selectedRisk = signal<string>('ALL');
    readonly selectedCompliance = signal<string>('ALL');

    readonly targetOptions = computed(() => {
        const options: { label: string; value: string }[] = [{ label: this.i18n.t('common.all_targets'), value: 'ALL' }];
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

    readonly blockingConflictsCount = computed(() => {
        return this.conflicts().filter((c) => c.compatibility === 'INCOMPATIBLE_BLOCKING').length;
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

    /**
     * The licence policy: read, and now editable.
     *
     * <p><b>It was loaded and shown nowhere.</b> It is what decides what the screen calls
     * "non-compliant" — on the counter at the top, on every row of the inventory, in the conflicts
     * — and nobody could either see it or change it. A count of violations whose rule is invisible
     * cannot be argued with: it is simply endured.
     *
     * <p>Reserved to the security lead, as the server requires, and recorded by it: changing what
     * is forbidden changes the whole estate's compliance at once.
     */
    readonly CATEGORIES: LicenseRiskCategory[] =
        ['PERMISSIVE', 'WEAK_COPYLEFT', 'STRONG_COPYLEFT', 'FORBIDDEN', 'UNKNOWN'];

    readonly canEditPolicy = computed(() => this.session.isSecurityLead());
    readonly editingPolicy = signal(false);
    readonly savingPolicy = signal(false);
    readonly policyError = signal<string | null>(null);

    draftDisallowed: LicenseRiskCategory[] = [];
    draftAllowedLicenses = '';
    draftDisallowedLicenses = '';

    editPolicy(): void {
        const policy = this.policy();
        this.draftDisallowed = [...(policy?.disallowedCategories ?? [])];
        this.draftAllowedLicenses = (policy?.explicitlyAllowedLicenses ?? []).join(', ');
        this.draftDisallowedLicenses = (policy?.explicitlyDisallowedLicenses ?? []).join(', ');
        this.policyError.set(null);
        this.editingPolicy.set(true);
    }

    isDisallowed(category: LicenseRiskCategory): boolean {
        return this.draftDisallowed.includes(category);
    }

    toggleCategory(category: LicenseRiskCategory, disallowed: boolean): void {
        this.draftDisallowed = disallowed
            ? [...new Set([...this.draftDisallowed, category])]
            : this.draftDisallowed.filter((entry) => entry !== category);
    }

    savePolicy(): void {
        this.savingPolicy.set(true);
        this.policyError.set(null);

        this.api.updateLicensePolicy({
            disallowedCategories: this.draftDisallowed,
            explicitlyAllowedLicenses: identifiers(this.draftAllowedLicenses),
            explicitlyDisallowedLicenses: identifiers(this.draftDisallowedLicenses)
        }).subscribe({
            next: (updated) => {
                this.savingPolicy.set(false);
                this.editingPolicy.set(false);
                this.policy.set(updated);
                // Every row's compliance has just been recomputed by the server: keeping it on
                // screen as it was would show yesterday's verdict under today's policy.
                this.loadData();
            },
            error: (response) => {
                this.savingPolicy.set(false);
                this.policyError.set(messageOf(response, this.i18n.t('licenses.policy_save_failed')));
            }
        });
    }

    setTab(tab: 'inventory' | 'conflicts' | 'matrix'): void {
        this.activeTab.set(tab);
        if (tab === 'matrix' && this.matrixRules().length === 0) {
            this.loadMatrixRules();
        }
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

        this.loadConflicts();
    }

    loadConflicts(): void {
        let repoId: number | undefined;
        let containerId: number | undefined;
        const target = this.selectedTarget();
        if (target.startsWith('repo:')) {
            repoId = Number(target.substring(5));
        } else if (target.startsWith('container:')) {
            containerId = Number(target.substring(10));
        }

        this.api.getLicenseConflicts(repoId, containerId, this.proprietaryMode()).subscribe({
            next: (c) => this.conflicts.set(c),
            error: () => {}
        });
    }

    loadMatrixRules(): void {
        this.api.getLicenseCompatibilityMatrix().subscribe({
            next: (rules) => this.matrixRules.set(rules),
            error: () => {}
        });
    }

    toggleProprietary(mode: boolean): void {
        this.proprietaryMode.set(mode);
        this.loadConflicts();
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

    compatSeverity(comp: string): 'success' | 'warn' | 'danger' | 'secondary' {
        switch (comp) {
            case 'COMPATIBLE': return 'success';
            case 'CONDITIONAL': return 'warn';
            case 'INCOMPATIBLE_BLOCKING': return 'danger';
            default: return 'secondary';
        }
    }
}

/**
 * A list of SPDX identifiers typed by hand.
 *
 * <p>Separated by commas or spaces, blanks dropped: a trailing comma is how one types a list, not
 * a licence named "".
 */
function identifiers(raw: string): string[] {
    return raw.split(/[,\s]+/).map((entry) => entry.trim()).filter((entry) => entry.length > 0);
}
