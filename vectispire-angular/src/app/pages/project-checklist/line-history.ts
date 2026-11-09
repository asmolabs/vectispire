import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, computed, inject, input } from '@angular/core';
import type { ChecklistLineHistory } from '../../core/api.models';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { answerLabel, authorOf, isAutomatic } from './checklist-model';

/**
 * A line's history: every answer and proof, never edited, oldest first — a withdrawn answer as
 * withdrawn, Vectispire's own as Vectispire's, a carried one with who carried it. `null` while read.
 */
@Component({
    selector: 'app-line-history',
    imports: [DatePipe, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './line-history.html'
})
export class LineHistory {
    private readonly i18n = inject(I18nService);

    readonly history = input.required<ChecklistLineHistory | null>();

    protected readonly answers = computed(() =>
        (this.history()?.answers ?? []).map((row) => ({
            ...row,
            text: answerLabel(this.i18n, row.value),
            automatic: isAutomatic(row),
            author: authorOf(this.i18n, row)
        }))
    );
}
