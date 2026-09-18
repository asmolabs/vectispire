import { CommonModule } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { SelectModule } from '@openng/optimus-ui/select';
import { ApiService } from '../../core/api.service';
import { I18nService } from '../../core/i18n/i18n.service';
import type { InventoryOccurrence, MonitoredContainer, MonitoredRepository, SbomDiffReport } from '../../core/api.models';
import { TranslatePipe } from '../../core/i18n/translate.pipe';

@Component({
    selector: 'app-inventory',
    standalone: true,
    imports: [CommonModule, FormsModule, CardModule, SelectModule, TableModule, TagModule, MessageModule, ButtonModule, InputTextModule, TranslatePipe],
    templateUrl: './inventory.html'
})
export class Inventory {
    private readonly api = inject(ApiService);
    private readonly i18n = inject(I18nService);

    name = '';
    version = '';

    readonly occurrences = signal<InventoryOccurrence[]>([]);
    readonly truncated = signal(false);
    readonly loading = signal(false);
    readonly searched = signal(false);
    readonly error = signal<string | null>(null);

    readonly activeTab = signal<'search' | 'diff'>('search');

    /**
     * The difference between two inventories.
     *
     * <p><b>It took typing two scan numbers by hand.</b> "e.g. 10", "e.g. 12" — two internal
     * identifiers no screen shows prominently, for a question that is almost always asked like
     * this: "what changed in this repository since last time". `getLatestSbomDiff` already answered
     * exactly that one, and no component called it.
     *
     * <p>Comparing two named scans stays, because it answers a different question — "between the
     * version we shipped and the one before" — that the latest pair does not cover.
     */
    fromScanId: number | null = null;
    toScanId: number | null = null;
    readonly diffReport = signal<SbomDiffReport | null>(null);
    readonly diffLoading = signal(false);
    readonly diffError = signal<string | null>(null);

    /** The comparable targets, repositories and images together: the question is not asked otherwise. */
    readonly targets = signal<{ label: string; value: string }[]>([]);
    diffTarget = '';

    constructor() {
        // Loaded separately: being unable to list them leaves the comparison by number, which was
        // until now the only path.
        this.api.repositories().subscribe({
            next: (repositories: MonitoredRepository[]) => this.addTargets(
                repositories.map((repository) => ({
                    label: repository.name ?? repository.url,
                    value: `repo:${repository.id}`
                }))),
            error: () => {}
        });
        this.api.containers().subscribe({
            next: (containers: MonitoredContainer[]) => this.addTargets(
                containers.map((container) => ({
                    label: `${container.imageName}:${container.tag}`,
                    value: `container:${container.id}`
                }))),
            error: () => {}
        });
    }

    private addTargets(more: { label: string; value: string }[]): void {
        this.targets.update((current) => [...current, ...more]);
    }

    search(): void {
        if (!this.name.trim()) {
            return;
        }
        this.loading.set(true);
        this.error.set(null);

        this.api.searchComponents(this.name.trim(), this.version.trim()).subscribe({
            next: (results) => {
                this.occurrences.set(results.occurrences);
                this.truncated.set(results.truncated);
                this.searched.set(true);
                this.loading.set(false);
            },
            error: () => {
                this.loading.set(false);
                this.error.set('The search could not be run.');
            }
        });
    }

    /**
     * What changed on a target since its second-to-last scan.
     *
     * <p>The refusal carries its cause: a target scanned only once has nothing to compare, and that
     * is a different sentence from "the calculation failed". Without it, the screen returns the
     * same error for a new repository and for a server that is down.
     */
    runLatestDiff(): void {
        if (!this.diffTarget) return;

        const [kind, id] = this.diffTarget.split(':');
        this.diffLoading.set(true);
        this.diffError.set(null);
        this.diffReport.set(null);

        this.api.getLatestSbomDiff(
                kind === 'repo' ? Number(id) : undefined,
                kind === 'container' ? Number(id) : undefined)
            .subscribe({
                next: (report) => {
                    this.diffReport.set(report);
                    this.diffLoading.set(false);
                },
                error: (response: { status?: number }) => {
                    this.diffLoading.set(false);
                    this.diffError.set(this.i18n.t(
                        response?.status === 404 ? 'inventory.diff_needs_two_scans' : 'inventory.diff_failed'));
                }
            });
    }

    runDiff(): void {
        if (!this.fromScanId || !this.toScanId) {
            this.diffError.set(this.i18n.t('inventory.diff_needs_two_ids'));
            return;
        }
        this.diffLoading.set(true);
        this.diffError.set(null);
        this.api.getSbomDiff(this.fromScanId, this.toScanId).subscribe({
            next: (report) => {
                this.diffReport.set(report);
                this.diffLoading.set(false);
            },
            error: () => {
                this.diffError.set(this.i18n.t('inventory.diff_failed'));
                this.diffLoading.set(false);
            }
        });
    }
}
