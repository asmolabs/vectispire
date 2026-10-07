import { DatePipe } from '@angular/common';
import {
    Component,
    computed,
    effect,
    inject,
    input,
    output,
    signal,
    untracked,
    ChangeDetectionStrategy
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Params, RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { SelectModule } from '@openng/optimus-ui/select';
import { OwaspApi } from '@/app/core/api/owasp.api';
import { messageOf } from '@/app/core/api-error';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { keyFor } from '@/app/core/i18n/literal-keys';
import { TranslatePipe } from '@/app/core/i18n/translate.pipe';
import { LatestRequest } from '@/app/core/latest-request';
import { SessionStore } from '@/app/core/session.store';
import { OwaspScope, scopeParams, scopeQuery } from './owasp-scope';
import type {
    Applicability,
    EvidenceSource,
    Implementation,
    OwaspGrid,
    OwaspCoverageLine,
    OwaspState
} from '@/app/core/api.models';

/**
 * A state and a declaration in words, through literal keys (decision 0019): the cells used to build
 * `'owasp_grid.state.' + state`, a key the i18n check could not see. A value the client does not
 * know is shown as sent.
 */
export const OWASP_STATE_KEYS = {
    FINDINGS: 'owasp_grid.state.FINDINGS',
    NOT_MEASURED: 'owasp_grid.state.NOT_MEASURED',
    NOT_COVERED: 'owasp_grid.state.NOT_COVERED',
    NO_FINDING: 'owasp_grid.state.NO_FINDING'
} as const satisfies Record<OwaspState, string>;

export const DECLARED_KEYS = {
    APPLICABLE: 'owasp_grid.declared.APPLICABLE',
    EXCLUDED: 'owasp_grid.declared.EXCLUDED'
} as const satisfies Record<Applicability, string>;

export const GRID_IMPLEMENTATION_KEYS = {
    IMPLEMENTED: 'owasp_grid.implementation.IMPLEMENTED',
    PARTIALLY_IMPLEMENTED: 'owasp_grid.implementation.PARTIALLY_IMPLEMENTED',
    PLANNED: 'owasp_grid.implementation.PLANNED',
    NOT_IMPLEMENTED: 'owasp_grid.implementation.NOT_IMPLEMENTED'
} as const satisfies Record<Implementation, string>;

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
    imports: [
        DatePipe,
        FormsModule,
        ButtonModule,
        DialogModule,
        InputTextModule,
        MessageModule,
        SelectModule,
        RouterLink,
        TranslatePipe
    ],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './owasp-grid.html'
})
export class OwaspGridComponent {
    private readonly owaspApi = inject(OwaspApi);
    private readonly session = inject(SessionStore);
    private readonly load = new LatestRequest();
    readonly i18n = inject(I18nService);

    /** The project or solution the grid is read over; `null` is the reader's estate. */
    readonly scope = input<OwaspScope>(null);
    /** Asked when a scope can no longer be read: the page owns the URL the scope lives in. */
    readonly estateAsked = output<void>();

    readonly grid = signal<OwaspGrid | null>(null);
    /** Why a scoped grid could not be read — a project deleted, or no longer visible, since the link was made. */
    readonly loadError = signal<string | null>(null);

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

        this.owaspApi
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
        const scope = this.scope();
        this.loadError.set(null);
        // Through one slot: a reader switching scopes twice must not see the first answer land last,
        // under the second scope's name.
        this.load.run(this.owaspApi.owaspCoverage(scopeQuery(scope)), {
            next: (data) => this.grid.set(data),
            error: (failure) => {
                this.grid.set(null);
                // The estate's grid failing stays quiet — the report below carries its own errors. A
                // scope's does not: a link to a project since deleted would otherwise open on an empty
                // page with the project's name in the picker, which reads as a project with no grid.
                if (scope !== null) {
                    this.loadError.set(messageOf(failure, this.i18n.t('owasp_grid.load_failed')));
                }
            }
        });
    }

    /**
     * The backlog a category's count counts: its open issues as the grid places them, settled triage
     * left out as the grid leaves it out, in the same scope. Without `unsettled` the list would hold
     * the accepted risks too and come out longer than the figure clicked.
     */
    openParams(line: OwaspCoverageLine): Params {
        return { owasp_category: line.id, unsettled: 'true', ...scopeParams(this.scope()) };
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
        // Read again whenever the scope changes, and only then: the scope is the one input.
        effect(() => {
            this.scope();
            untracked(() => this.reload());
        });
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
    stateLabel(state: string): string {
        return this.labelOf(OWASP_STATE_KEYS, state);
    }

    applicabilityLabel(applicability: string): string {
        return this.labelOf(DECLARED_KEYS, applicability);
    }

    implementationLabel(implementation: string): string {
        return this.labelOf(GRID_IMPLEMENTATION_KEYS, implementation);
    }

    private labelOf<V extends string>(keys: Readonly<Record<V, string>>, value: string): string {
        const key = keyFor(keys, value);
        return key ? this.i18n.t(key) : value;
    }

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
