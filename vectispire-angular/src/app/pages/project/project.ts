import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, computed, effect, inject, input, signal, untracked } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { messageOf } from '../../core/api-error';
import { SolutionsApi } from '../../core/api/solutions.api';
import type {
    ConsolidatedInventory,
    InventoryState,
    ProjectDetail,
    ScopeCompliance,
    TargetInventory
} from '../../core/api.models';
import { saveDocument } from '../../core/download';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { LatestRequest } from '../../core/latest-request';
import { DetectedLanguages } from '../../shared/detected-languages';
import { ScopeComplianceView } from '../../shared/scope-compliance';

/**
 * What a target's last scan says of its inventory, in words. Literal keys (decision 0019): a state
 * added to the server's enum fails to compile here instead of reaching the reader as a raw key.
 */
const INVENTORY_KEYS = {
    listed: 'project.inventory_listed',
    empty: 'project.inventory_empty',
    absent: 'project.inventory_absent',
    never_scanned: 'project.inventory_never_scanned'
} as const satisfies Record<InventoryState, string>;

function isNotFound(failure: unknown): boolean {
    return (failure as { status?: number } | null)?.status === 404;
}

/**
 * One project on its own page: what it holds, its compliance and score, and the components its
 * targets carry (decision 0023).
 *
 * **Readable by whoever sees part of it**, and the page says which part: the server computes every
 * figure over the reader's visible targets and flags `partial`, the same marker the tree shows. A
 * project the reader sees nothing of answers 404 like one that does not exist, and the page cannot
 * tell them apart, so it does not try.
 */
@Component({
    selector: 'app-project',
    imports: [
        DatePipe,
        FormsModule,
        RouterLink,
        ButtonModule,
        CardModule,
        InputTextModule,
        MessageModule,
        TableModule,
        TagModule,
        TranslatePipe,
        DetectedLanguages,
        ScopeComplianceView
    ],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './project.html'
})
export class Project {
    private readonly api = inject(SolutionsApi);
    private readonly i18n = inject(I18nService);

    private readonly detailRequest = new LatestRequest();
    private readonly complianceRequest = new LatestRequest();
    private readonly componentsRequest = new LatestRequest();

    /** The route's `:projectId`, bound by `withComponentInputBinding`. */
    readonly projectId = input.required<string>();
    readonly id = computed(() => Number(this.projectId()));

    readonly detail = signal<ProjectDetail | null>(null);
    readonly compliance = signal<ScopeCompliance | null>(null);
    readonly inventory = signal<ConsolidatedInventory | null>(null);
    readonly loading = signal(true);
    readonly notFound = signal(false);
    readonly error = signal<string | null>(null);
    readonly complianceError = signal<string | null>(null);
    readonly inventoryError = signal<string | null>(null);
    readonly downloading = signal(false);

    readonly query = signal('');

    readonly languages = computed<readonly string[]>(() => this.detail()?.detectedLanguages ?? []);

    /** Matched on the name and on the purl, which carries the ecosystem a reader often searches by. */
    readonly components = computed(() => {
        const all = this.inventory()?.components ?? [];
        const needle = this.query().trim().toLowerCase();
        if (!needle) return all;
        return all.filter(
            (component) =>
                component.name.toLowerCase().includes(needle) || (component.purl ?? '').toLowerCase().includes(needle)
        );
    });

    /** The targets whose inventory the list cannot speak for: never scanned, or scanned without an SBOM. */
    readonly unlisted = computed(() =>
        (this.inventory()?.targets ?? []).filter(
            (target) => target.inventory === 'absent' || target.inventory === 'never_scanned'
        )
    );

    constructor() {
        // An effect rather than a call in the constructor: a signal input is not bound yet there.
        effect(() => {
            const id = this.id();
            untracked(() => this.load(id));
        });
    }

    /**
     * Three reads side by side. The header's decides the page — a 404 there is the not-found state —
     * and the two sections fail on their own, so a compliance summary that cannot be computed does not
     * take the component list down with it.
     */
    private load(id: number): void {
        this.loading.set(true);
        this.notFound.set(false);
        this.error.set(null);
        this.complianceError.set(null);
        this.inventoryError.set(null);
        this.detail.set(null);
        this.compliance.set(null);
        this.inventory.set(null);

        this.detailRequest.run(this.api.project(id), {
            next: (detail) => {
                this.detail.set(detail);
                this.loading.set(false);
            },
            error: (failure) => {
                this.loading.set(false);
                if (isNotFound(failure)) {
                    this.notFound.set(true);
                    return;
                }
                this.error.set(messageOf(failure, this.i18n.t('project.error_load')));
            }
        });
        this.complianceRequest.run(this.api.projectCompliance(id), {
            next: (compliance) => this.compliance.set(compliance),
            error: (failure) => {
                if (isNotFound(failure)) {
                    this.notFound.set(true);
                    return;
                }
                this.complianceError.set(messageOf(failure, this.i18n.t('project.error_compliance')));
            }
        });
        this.componentsRequest.run(this.api.projectComponents(id), {
            next: (inventory) => this.inventory.set(inventory),
            error: (failure) => {
                if (isNotFound(failure)) {
                    this.notFound.set(true);
                    return;
                }
                this.inventoryError.set(messageOf(failure, this.i18n.t('project.error_components')));
            }
        });
    }

    inventoryLabel(target: TargetInventory): string {
        this.i18n.translations();
        const key = (INVENTORY_KEYS as Record<string, string | undefined>)[target.inventory];
        return key ? this.i18n.t(key, { count: target.componentCount }) : target.inventory;
    }

    inventorySeverity(target: TargetInventory): 'success' | 'secondary' | 'warn' {
        if (target.inventory === 'listed') return 'success';
        if (target.inventory === 'empty') return 'secondary';
        return 'warn';
    }

    /**
     * Saved as a download, never opened: the token is on the request, which a navigation would not
     * carry. The body of a blob request's refusal is a Blob, so the status is all a 404 can say.
     */
    downloadCycloneDx(): void {
        const id = this.id();
        this.downloading.set(true);
        this.inventoryError.set(null);
        this.api.projectCycloneDx(id).subscribe({
            next: (response) => {
                this.downloading.set(false);
                saveDocument(response, `vectispire-project-${id}-cyclonedx-vex.json`);
            },
            error: (failure) => {
                this.downloading.set(false);
                if (isNotFound(failure)) {
                    this.notFound.set(true);
                    return;
                }
                this.inventoryError.set(this.i18n.t('project.error_cyclonedx'));
            }
        });
    }
}
