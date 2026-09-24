import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { TagModule } from '@openng/optimus-ui/tag';
import { messageOf } from '@/app/core/api-error';
import { ComplianceApi } from '@/app/core/api/compliance.api';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { SessionStore } from '@/app/core/session.store';
import { TranslatePipe } from '@/app/core/i18n/translate.pipe';
import type { Applicability, ControlDeclaration, Divergence, EvidenceSource, Implementation, SoaLine, SoaStatement } from '@/app/core/api.models';

/**
 * The statement of applicability: what is claimed, set against what is measured.
 *
 * **The useful artefact is neither the declaration nor the measurement, it is their
 * disagreement.** A control declared in place that the estate measures non-compliant is exactly
 * what an assessor writes up, and neither half of the product could see it alone. The screen
 * therefore sorts by severity of divergence and not by control identifier.
 *
 * **A fresh instance shows twenty-four findings and that is correct.** Clause 6.1.3 d requires
 * *every* control to be addressed; silence is the gap. Sorting the undeclared to the bottom would
 * have made the empty document look like a clean one.
 *
 * **`evidence_source` is the field that stops the screen lying.** Vectispire measures a slice of
 * each control; a row whose evidence lives elsewhere is shown as not measured here, which is a
 * pointer to the other document and not a finding.
 */
@Component({
    selector: 'zs-soa',
    standalone: true,
    imports: [CommonModule, FormsModule, ButtonModule, DialogModule, InputTextModule, MessageModule, TagModule, TranslatePipe],
    templateUrl: './soa.html'
})
export class Soa {
    private readonly complianceApi = inject(ComplianceApi);
    private readonly i18n = inject(I18nService);
    private readonly session = inject(SessionStore);

    readonly statements = signal<SoaStatement[]>([]);

    /**
     * The lapsed reviews, across all frameworks.
     *
     * <p><b>The counter was there, the list nowhere.</b> Every document displayed "n reviews
     * overdue" and nothing said which: a number you cannot open is not a record of review, it is a
     * reproach. The route existed and nobody called it.
     *
     * <p>Returned separately from the documents, because that is how the question is asked: a
     * management review asks what the organisation has stopped looking at, not what one particular
     * framework let slip.
     */
    readonly overdue = signal<ControlDeclaration[]>([]);
    readonly framework = signal<string | null>(null);
    readonly error = signal<string | null>(null);
    readonly busy = signal(false);

    readonly editing = signal<SoaLine | null>(null);
    applicability: Applicability = 'APPLICABLE';
    implementation: Implementation = 'IMPLEMENTED';
    evidenceSource: EvidenceSource = 'VECTISPIRE';
    justification = '';
    externalEvidence = '';
    owner = '';
    reviewDue = '';

    readonly canDeclare = computed(() => this.session.isSecurityLead());

    /**
     * The screen opens on ISO 27001, not on the enumeration's first framework.
     *
     * <p>It opened on NIS 2 because that is the first value declared — on a screen whose subtitle
     * speaks of ISO 27001's clause 6.1.3 d. An enumeration's default is not a screen's choice.
     */
    private static readonly OPENS_ON = 'ISO_27001';

    readonly current = computed<SoaStatement | null>(() => {
        const all = this.statements();
        const chosen = this.framework();
        return all.find((statement) => statement.framework === chosen)
            ?? all.find((statement) => statement.framework === Soa.OPENS_ON)
            ?? all[0]
            ?? null;
    });

    /**
     * The divergences first, most severe to least, then the rows that are fine.
     *
     * The server returns the rows in the framework's order, which is the standard's. That is the
     * right order for printing the document and the wrong one for opening it: the question asked
     * here is "what is wrong", and it is answered at the top of the screen.
     */
    private static readonly ORDER: Divergence[] = [
        'CONTRADICTED',
        'EXCLUDED_WITHOUT_JUSTIFICATION',
        'UNDECLARED',
        'OVERSTATED',
        'UNDERSTATED',
        'NOT_MEASURED_HERE',
        'NOT_APPLICABLE',
        'CONSISTENT'
    ];

    readonly lines = computed<SoaLine[]>(() => {
        const statement = this.current();
        if (!statement) {
            return [];
        }
        return [...statement.lines].sort((a, b) => Soa.ORDER.indexOf(a.divergence) - Soa.ORDER.indexOf(b.divergence));
    });

    constructor() {
        this.load();
    }

    load(): void {
        // Separately: failing to get the list of lapsed reviews does not prevent reading the
        // statement, which is the screen's subject.
        this.complianceApi.overdueReviews().subscribe({
            next: (declarations) => this.overdue.set(declarations ?? []),
            error: () => this.overdue.set([])
        });

        this.complianceApi.statementsOfApplicability().subscribe({
            next: (data) => this.statements.set(data),
            error: (failure) => this.error.set(messageOf(failure, this.i18n.t('soa.load_failed')))
        });
    }

    isFinding(line: SoaLine): boolean {
        return line.divergence === 'CONTRADICTED'
            || line.divergence === 'EXCLUDED_WITHOUT_JUSTIFICATION'
            || line.divergence === 'UNDECLARED';
    }

    severityOf(line: SoaLine): 'danger' | 'warn' | 'info' | 'secondary' {
        if (this.isFinding(line)) {
            return 'danger';
        }
        if (line.divergence === 'OVERSTATED' || line.divergence === 'UNDERSTATED') {
            return 'warn';
        }
        return line.divergence === 'CONSISTENT' ? 'secondary' : 'info';
    }

    openDeclare(line: SoaLine): void {
        const existing = line.declaration;
        this.applicability = existing?.applicability ?? 'APPLICABLE';
        this.implementation = existing?.implementation ?? 'IMPLEMENTED';
        this.evidenceSource = existing?.evidenceSource ?? 'VECTISPIRE';
        this.justification = existing?.justification ?? '';
        this.externalEvidence = existing?.externalEvidence ?? '';
        this.owner = existing?.owner ?? '';
        this.reviewDue = existing?.reviewDueAt ? existing.reviewDueAt.slice(0, 10) : '';
        this.error.set(null);
        this.editing.set(line);
    }

    /**
     * The server's two refusals, said here by a disabled button.
     *
     * Letting the request go in order to show its message would work. A disabled button says the
     * same thing before the keystroke rather than after.
     */
    incomplete(): boolean {
        if (this.applicability === 'EXCLUDED') {
            return !this.justification.trim();
        }
        return this.evidenceSource !== 'VECTISPIRE' && !this.externalEvidence.trim();
    }

    submit(): void {
        const line = this.editing();
        const statement = this.current();
        if (!line || !statement || this.incomplete()) {
            return;
        }
        this.busy.set(true);
        this.error.set(null);

        this.complianceApi
            .declareControl(statement.framework, line.control.id, {
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
                    // Reloaded rather than merged locally: the row changes divergence, and
                    // recomputing that rule in the browser would make a second implementation that
                    // would end up no longer saying the same thing.
                    this.load();
                },
                error: (failure) => {
                    this.error.set(messageOf(failure, this.i18n.t('soa.declare_failed')));
                    this.busy.set(false);
                }
            });
    }
}
