import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal, ChangeDetectionStrategy } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { SelectModule } from '@openng/optimus-ui/select';
import { TargetsApi } from '../../core/api/targets.api';
import { ScansApi } from '../../core/api/scans.api';
import { I18nService } from '../../core/i18n/i18n.service';
import type { InventoryOccurrence, MonitoredContainer, MonitoredRepository, SbomDiffReport, ScanSummary } from '../../core/api.models';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { LatestRequest } from '@/app/core/latest-request';

@Component({
    selector: 'app-inventory',
    standalone: true,
    imports: [CommonModule, FormsModule, CardModule, SelectModule, TableModule, TagModule, MessageModule, ButtonModule, InputTextModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './inventory.html'
})
export class Inventory {
    private readonly scansRequest = new LatestRequest();

    private readonly targetsApi = inject(TargetsApi);
    private readonly scansApi = inject(ScansApi);
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
    /**
     * The chosen target's scans, newest first — what the two pickers offer.
     *
     * <p><b>This screen used to ask for two scan numbers.</b> `ex: 10`, `ex: 12`: internal
     * identifiers no screen displays prominently, for a question that is almost always "what
     * changed since last time". The server has listed a target's scans all along and nothing
     * called it.
     */
    readonly scans = signal<ScanSummary[]>([]);
    readonly scansLoading = signal(false);

    readonly diffReport = signal<SbomDiffReport | null>(null);
    readonly diffLoading = signal(false);
    readonly diffError = signal<string | null>(null);

    /** The comparable targets, repositories and images together: the question is not asked otherwise. */
    readonly targets = signal<{ label: string; value: string }[]>([]);
    diffTarget = '';

    constructor() {
        // Loaded separately, and the comparison cannot start without them: picking a target is now
        // the first move rather than an alternative to typing two scan numbers. A failure here
        // leaves the search tab working, which is the other half of this screen.
        this.targetsApi.repositories().subscribe({
            next: (repositories: MonitoredRepository[]) => this.addTargets(
                repositories.map((repository) => ({
                    label: repository.name ?? repository.url,
                    value: `repo:${repository.id}`
                }))),
            error: () => {}
        });
        this.targetsApi.containers().subscribe({
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

        this.scansApi.searchComponents(this.name.trim(), this.version.trim()).subscribe({
            next: (results) => {
                this.occurrences.set(results.occurrences);
                this.truncated.set(results.truncated);
                this.searched.set(true);
                this.loading.set(false);
            },
            error: () => {
                this.loading.set(false);
                this.error.set(this.i18n.t('inventory.search_failed'));
            }
        });
    }

    /**
     * Loads the target's scans and offers its two most recent, in that order.
     *
     * <p><b>The common case is answered before anybody clicks.</b> "What changed since last time"
     * is what this screen is opened for; preselecting the last two makes it the default rather
     * than a second action, and the pickers are there for the other question — between the version
     * we shipped and the one before.
     *
     * <p>A target with a single scan has no pair. The screen says so rather than leaving two empty
     * pickers, because "nothing to compare" and "the comparison failed" are different sentences
     * and only one of them is about this repository.
     */
    onTargetChosen(): void {
        this.scans.set([]);
        this.fromScanId = null;
        this.toScanId = null;
        this.diffReport.set(null);
        this.diffError.set(null);
        if (!this.diffTarget) return;

        const [kind, id] = this.diffTarget.split(':');
        this.scansLoading.set(true);
        this.scansRequest.run(this.scansApi.scansOf(
                kind === 'repo' ? Number(id) : undefined,
                kind === 'container' ? Number(id) : undefined), {
                next: (history) => {
                    this.scans.set(history);
                    this.scansLoading.set(false);
                    if (history.length >= 2) {
                        this.toScanId = history[0].id;
                        this.fromScanId = history[1].id;
                    } else {
                        this.diffError.set(this.i18n.t('inventory.diff_needs_two_scans'));
                    }
                },
                error: () => {
                    this.scansLoading.set(false);
                    this.diffError.set(this.i18n.t('inventory.diff_failed'));
                }
            });
    }

    /**
     * How a scan reads in the pickers: the date first, because that is what a reader recognises.
     *
     * <p>The identifier is kept at the end rather than dropped. It is what the API takes, what a
     * support conversation quotes, and the only thing that tells two scans of the same minute
     * apart.
     */
    readonly scanOptions = computed(() =>
        this.scans().map((scan) => ({ label: this.scanLabel(scan), value: scan.id })));

    scanLabel(scan: ScanSummary): string {
        const when = scan.createdAt ? new Date(scan.createdAt).toLocaleString() : '—';
        const branch = scan.branch ? ` · ${scan.branch}` : '';
        return `${when}${branch} · ${scan.findingsCount ?? 0} · #${scan.id}`;
    }

    runDiff(): void {
        if (!this.fromScanId || !this.toScanId) {
            this.diffError.set(this.i18n.t('inventory.diff_needs_two_ids'));
            return;
        }
        this.diffLoading.set(true);
        this.diffError.set(null);
        this.scansApi.getSbomDiff(this.fromScanId, this.toScanId).subscribe({
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
