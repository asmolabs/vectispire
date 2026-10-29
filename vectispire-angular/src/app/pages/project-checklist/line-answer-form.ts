import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, computed, inject, input } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { TextareaModule } from '@openng/optimus-ui/textarea';
import { ChecklistsApi } from '../../core/api/checklists.api';
import type { ChecklistAnswerValue, ChecklistLine } from '../../core/api.models';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { ChecklistPage } from './checklist-page';
import { AnswerDraft, answerLabel, isAutomatic } from './checklist-model';

const ANSWER_VALUES: readonly ChecklistAnswerValue[] = ['yes', 'no', 'not_applicable'];

/**
 * The answer being written on one line: the value, the comment a no or a not-applicable needs, and the
 * measurement it rests on when the form was opened from one.
 *
 * A form, so that the fields say what they need before anything is sent — a value, and a comment
 * unless the value is yes — and the check made here is the server's: it refuses the same two.
 */
@Component({
    selector: 'app-line-answer-form',
    imports: [DatePipe, FormsModule, ButtonModule, TextareaModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './line-answer-form.html'
})
export class LineAnswerForm {
    private readonly api = inject(ChecklistsApi);
    private readonly i18n = inject(I18nService);
    protected readonly page = inject(ChecklistPage);

    readonly line = input.required<ChecklistLine>();

    protected readonly automatic = computed(() => isAutomatic(this.line().answer));
    /**
     * The answers the version offers — "not applicable" only where its importer mapped a word to it —
     * each with the template's own word, as the importer mapped it: what the signed document will write.
     */
    protected readonly answers = computed(() => {
        const view = this.page.view();
        const words = view?.answerWords;
        return ANSWER_VALUES.filter((value) => value !== 'not_applicable' || !!view?.offersNotApplicable).map(
            (value) => ({
                value,
                label: answerLabel(this.i18n, value),
                word: words ? (value === 'yes' ? words.yes : value === 'no' ? words.no : words.notApplicable) : null
            })
        );
    });

    protected setAnswer(patch: Partial<Pick<AnswerDraft, 'value' | 'comment'>>): void {
        this.page.answering.update((draft) => (draft ? { ...draft, ...patch } : draft));
    }

    /** Refused here as the server would: no answer chosen, or a negative one without its reason. */
    protected save(): void {
        const draft = this.page.answering();
        const shown = this.page.summary();
        const line = this.line();
        if (!draft || !shown || draft.itemId !== line.itemId) return;
        if (!draft.value) {
            this.page.answerError.set(this.i18n.t('project_checklist.problem_choose'));
            return;
        }
        if (draft.value !== 'yes' && !draft.comment.trim()) {
            this.page.answerError.set(this.i18n.t('project_checklist.problem_comment'));
            return;
        }
        this.page.answerError.set(null);
        this.page.write(
            this.api.answerChecklistLine(
                this.page.id(),
                shown.revision,
                line.itemId,
                draft.value,
                draft.comment,
                shown.edition,
                draft.restingOn?.value === draft.value ? draft.restingOn.digest : null
            ),
            line.itemId,
            () => this.page.answering.set(null)
        );
    }
}
