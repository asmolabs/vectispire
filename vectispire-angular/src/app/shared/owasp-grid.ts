import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { SelectModule } from '@openng/optimus-ui/select';
import { ApiService } from '@/app/core/api.service';
import { messageOf } from '@/app/core/api-error';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { TranslatePipe } from '@/app/core/i18n/translate.pipe';
import { SessionStore } from '@/app/core/session.store';
import type {
    Applicability,
    EvidenceSource,
    Implementation,
    OwaspGrid,
    OwaspCoverageLine,
    OwaspState
} from '@/app/core/api.models';

/**
 * The ten categories, answered by rule rather than by a model.
 *
 * **Four states and not two, because two would lie.** A category with nothing found and a category
 * nothing looks at produce the same green. Several of the ten are covered by no scanner here, and
 * saying so is the most useful thing this grid does.
 *
 * Placed above the model-written report, not in its place: the report produces the prose no rules
 * engine writes, and it does not serve as evidence. Reading them in that order is the order in
 * which they are worth something.
 */
@Component({
    selector: 'zs-owasp-grid',
    standalone: true,
    imports: [
        CommonModule,
        FormsModule,
        ButtonModule,
        DialogModule,
        InputTextModule,
        MessageModule,
        SelectModule,
        TranslatePipe
    ],
    templateUrl: './owasp-grid.html'
})
export class OwaspGridComponent {
    private readonly api = inject(ApiService);
    private readonly session = inject(SessionStore);
    readonly i18n = inject(I18nService);

    readonly grid = signal<OwaspGrid | null>(null);

    /**
     * The declaration being written, and the fields it carries.
     *
     * **The same form as the statement of applicability, because it is the same thing.** A category
     * no scanner here measures has nothing but a declaration to carry a review: who asserts it, on
     * what evidence, and when it is looked at again. Writing a second entry model for one table
     * would give two forms that diverge on the first rule added to either.
     */
    readonly editing = signal<OwaspCoverageLine | null>(null);
    readonly busy = signal(false);
    readonly error = signal<string | null>(null);

    applicability: Applicability = 'APPLICABLE';
    implementation: Implementation = 'IMPLEMENTED';
    evidenceSource: EvidenceSource = 'EXTERNAL';
    justification = '';
    externalEvidence = '';
    owner = '';
    reviewDue = '';

    readonly canDeclare = computed(() => this.session.isSecurityLead());

    /**
     * Declarable where measurement stops, and nowhere else.
     *
     * A category a scanner here can read does not need asserting: it is measured, and a declaration
     * set beside a measurement is a second source that will end up contradicting it. The button
     * therefore appears only on the squares nothing measures.
     */
    declarable(line: OwaspCoverageLine): boolean {
        return this.canDeclare() && line.state === 'NOT_COVERED';
    }

    openDeclare(line: OwaspCoverageLine): void {
        const existing = line.declaration;
        this.applicability = existing?.applicability ?? 'APPLICABLE';
        this.implementation = existing?.implementation ?? 'IMPLEMENTED';
        // `EXTERNAL` by default, not `VECTISPIRE`: the category is precisely the one this product
        // does not measure, so its evidence lives elsewhere by construction.
        this.evidenceSource = existing?.evidenceSource ?? 'EXTERNAL';
        this.justification = existing?.justification ?? '';
        this.externalEvidence = existing?.externalEvidence ?? '';
        this.owner = existing?.owner ?? '';
        this.reviewDue = existing?.reviewDueAt ? existing.reviewDueAt.slice(0, 10) : '';
        this.error.set(null);
        this.editing.set(line);
    }

    /**
     * The server's two refusals, said here by a dead button rather than after the typing.
     *
     * They are the same as under ISO 27001, and they name no framework: an exclusion with no reason
     * is a line stepping out of scope without saying why, and evidence declared elsewhere without
     * saying where is the same omission moved.
     */
    incomplete(): boolean {
        if (this.applicability === 'EXCLUDED') {
            return !this.justification.trim();
        }
        return this.evidenceSource !== 'VECTISPIRE' && !this.externalEvidence.trim();
    }

    submit(): void {
        const line = this.editing();
        if (!line || this.incomplete()) {
            return;
        }
        this.busy.set(true);
        this.error.set(null);

        this.api
            .declareOwaspCategory(line.id, {
                applicability: this.applicability,
                justification: this.justification.trim() || null,
                implementation: this.applicability === 'EXCLUDED' ? null : this.implementation,
                evidence_source: this.evidenceSource,
                external_evidence: this.externalEvidence.trim() || null,
                owner: this.owner.trim() || null,
                review_due_at: this.reviewDue ? new Date(this.reviewDue).toISOString() : null
            })
            .subscribe({
                next: () => {
                    this.editing.set(null);
                    this.busy.set(false);
                    // Reloaded rather than merged in place: the grid also carries counters, and
                    // recomputing them here would make a second implementation of them.
                    this.reload();
                },
                error: (failure) => {
                    this.busy.set(false);
                    this.error.set(messageOf(failure, this.i18n.t('owasp_grid.declare_failed')));
                }
            });
    }

    private reload(): void {
        this.api.owaspCoverage().subscribe({
            next: (data) => this.grid.set(data),
            error: () => this.grid.set(null)
        });
    }

    /**
     * The standard's order, always.
     *
     * Sorting by severity would put the actionable categories on top, which is the right reflex for
     * a dashboard and the wrong one here: an audit questionnaire asks A01 then A02, and a reordered
     * grid forces the reader to hunt for every row.
     */
    readonly lines = computed<OwaspCoverageLine[]>(() => this.grid()?.lines ?? []);

    constructor() {
        this.reload();
    }

    /**
     * A zero that is good news is painted green, not as an alarm.
     *
     * "0 covered but unmeasured" in orange was good news shown as a problem. A table where good
     * news is orange teaches its reader to ignore orange.
     */
    alarming(count: number, tone: 'danger' | 'warn'): string {
        if (count === 0) {
            return 'text-emerald-700';
        }
        return tone === 'danger' ? 'text-red-700' : 'text-orange-700';
    }

    /** The grey of "not covered" is not the green of "nothing found", and that is the whole point. */
    colourOf(state: OwaspState): string {
        switch (state) {
            case 'FINDINGS':
                return 'text-red-700';
            case 'NOT_MEASURED':
                return 'text-orange-700';
            case 'NOT_COVERED':
                return 'text-muted-color';
            default:
                return 'text-emerald-700';
        }
    }
}
