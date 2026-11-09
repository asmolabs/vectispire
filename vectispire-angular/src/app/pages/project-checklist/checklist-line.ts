import { DatePipe } from '@angular/common';
import { HttpHeaders } from '@angular/common/http';
import { ChangeDetectionStrategy, Component, computed, inject, input } from '@angular/core';
import { ButtonModule } from '@openng/optimus-ui/button';
import { TagModule } from '@openng/optimus-ui/tag';
import { messageOf } from '../../core/api-error';
import { ChecklistsApi } from '../../core/api/checklists.api';
import type { ChecklistEvidence, ChecklistLine } from '../../core/api.models';
import { saveDocument } from '../../core/download';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { ChecklistPage } from './checklist-page';
import { answerLabel, authorOf, evidenceKindLabel, isAutomatic, measuredWords, problemLabel } from './checklist-model';
import { ChecklistRefusal } from './checklist-refusal';
import { LineAnswerForm } from './line-answer-form';
import { LineHistory } from './line-history';
import { LineMeasurement } from './line-measurement';
import { LineProofForm } from './line-proof-form';

/**
 * One line of the checklist: its control, its problems, its measurement beside its answer, its proofs,
 * the acts it offers on the newest draft, and its history when asked for.
 *
 * Everything the line shows is computed from the line and the page's state rather than asked of a
 * method on every pass: a checklist holds hundreds of lines, each drawn on every change detection.
 */
@Component({
    selector: 'app-checklist-line',
    imports: [
        DatePipe,
        ButtonModule,
        TagModule,
        TranslatePipe,
        ChecklistRefusal,
        LineAnswerForm,
        LineHistory,
        LineMeasurement,
        LineProofForm
    ],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './checklist-line.html'
})
export class ChecklistLineCard {
    private readonly api = inject(ChecklistsApi);
    private readonly i18n = inject(I18nService);
    protected readonly page = inject(ChecklistPage);

    readonly line = input.required<ChecklistLine>();

    private readonly itemId = computed(() => this.line().itemId);
    /** What the last refusal said keeps this line back, or `null` when it named no such thing. */
    protected readonly refused = computed(() => this.page.incomplete()[this.itemId()] ?? null);
    /** What the last measurement refusal said of this line, or null. */
    protected readonly conflict = computed(() => this.page.measuredConflicts()[this.itemId()] ?? null);
    /** A carried answer onto a line that changed: the line stands out until somebody answers or confirms it. */
    protected readonly awaiting = computed(() => !!this.line().answer?.needsConfirmation);
    protected readonly measured = computed(() => this.page.measuredLines().get(this.itemId()) ?? null);
    protected readonly lineRefusal = computed(() => {
        const refusal = this.page.refusal();
        return refusal?.itemId === this.itemId() ? refusal : null;
    });
    protected readonly answeringHere = computed(() => this.page.answering()?.itemId === this.itemId());
    protected readonly provingHere = computed(() => this.page.proving()?.itemId === this.itemId());
    protected readonly historyOpen = computed(() => this.itemId() in this.page.histories());
    protected readonly history = computed(() => this.page.histories()[this.itemId()] ?? null);

    protected readonly evidenceKindText = computed(() => evidenceKindLabel(this.i18n, this.line().evidenceKind));
    protected readonly problems = computed(() =>
        this.line().problems.map((problem) => ({ problem, text: problemLabel(this.i18n, problem) }))
    );
    protected readonly refusedProblems = computed(
        () => this.refused()?.map((problem) => ({ problem, text: problemLabel(this.i18n, problem) })) ?? null
    );
    protected readonly conflictWords = computed(() => {
        const conflicted = this.conflict();
        if (!conflicted) return null;
        return {
            answer: conflicted.answer
                ? answerLabel(this.i18n, conflicted.answer)
                : this.i18n.t('project_checklist.unanswered_value'),
            outcome: measuredWords(this.i18n, conflicted.outcome, conflicted.reason),
            was: conflicted.submittedOutcome
                ? measuredWords(this.i18n, conflicted.submittedOutcome, conflicted.submittedReason)
                : null
        };
    });
    protected readonly answerText = computed(() => {
        const given = this.line().answer;
        return given ? answerLabel(this.i18n, given.value) : '';
    });
    protected readonly automatic = computed(() => isAutomatic(this.line().answer));
    protected readonly author = computed(() => {
        const given = this.line().answer;
        return given ? authorOf(this.i18n, given) : '';
    });

    protected confirmAnswer(): void {
        const shown = this.page.summary();
        if (!shown) return;
        this.page.write(
            this.api.confirmChecklistAnswer(this.page.id(), shown.revision, this.itemId(), shown.edition),
            this.itemId()
        );
    }

    protected startEvidence(): void {
        const line = this.line();
        this.page.answering.set(null);
        this.page.evidenceError.set(null);
        this.page.proving.set({
            itemId: line.itemId,
            kind: line.evidenceKind === 'file' ? 'file' : 'link',
            link: '',
            file: null,
            performedOn: this.page.today
        });
    }

    protected withdraw(proof: ChecklistEvidence): void {
        const shown = this.page.summary();
        if (!shown) return;
        this.page.write(
            this.api.withdrawChecklistEvidence(this.page.id(), shown.revision, proof.id, shown.edition),
            proof.itemId
        );
    }

    /**
     * Saved as a download under the name the list shows, never opened in the page. The name is the
     * one the proof was stored under, rather than the header's, which `filenameOf` reads only in its
     * plain form and a name outside ASCII does not take.
     */
    protected download(proof: ChecklistEvidence): void {
        const shown = this.page.summary();
        if (!shown) return;
        this.api.checklistEvidenceFile(this.page.id(), shown.revision, proof.id).subscribe({
            next: (response) =>
                saveDocument(response.clone({ headers: new HttpHeaders() }), proof.fileName ?? 'evidence'),
            error: (failure) => this.page.error.set(messageOf(failure, this.i18n.t('project_checklist.error_download')))
        });
    }

    protected toggleHistory(): void {
        const shown = this.page.summary();
        if (!shown) return;
        const itemId = this.itemId();
        const close = () =>
            this.page.histories.update((open) => {
                const rest = { ...open };
                delete rest[itemId];
                return rest;
            });
        if (this.historyOpen()) {
            close();
            return;
        }
        this.page.histories.update((open) => ({ ...open, [itemId]: null }));
        this.api.checklistLineHistory(this.page.id(), shown.revision, itemId).subscribe({
            next: (history) => this.page.histories.update((open) => ({ ...open, [itemId]: history })),
            error: (failure) => {
                close();
                this.page.error.set(messageOf(failure, this.i18n.t('project_checklist.error_history')));
            }
        });
    }
}
