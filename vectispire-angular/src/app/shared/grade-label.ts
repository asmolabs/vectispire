import { Pipe, PipeTransform, inject } from '@angular/core';
import { I18nService } from '../core/i18n/i18n.service';
import type { SecurityGrade } from '../core/api.models';

/**
 * The letter a grade is read as. `A_PLUS` is the name of a Java constant, not a mark: the scorecard
 * and the dashboard's ranking printed "Grade A_PLUS" for the best targets on the board. The letters
 * are the same in every language, so they are not translated; `NO_DATA` is no letter at all.
 * `satisfies` makes a grade the server adds a build failure here rather than a raw constant on screen.
 */
const GRADE_LETTERS = {
    A_PLUS: 'A+',
    A: 'A',
    B: 'B',
    C: 'C',
    D: 'D',
    F: 'F',
    NO_DATA: null
} as const satisfies Record<SecurityGrade, string | null>;

/** "Grade A+", or the no-data wording: every screen showing a grade reads it through here. */
export function gradeLabel(grade: SecurityGrade, t: I18nService['t']): string {
    const letter = GRADE_LETTERS[grade];
    return letter === null ? t('soa.measured.NO_DATA') : t('repositories.grade_tag', { grade: letter });
}

@Pipe({
    name: 'gradeLabel',
    standalone: true,
    // Impure like `translate`: the text changes when the language does, the grade not.
    pure: false
})
export class GradeLabelPipe implements PipeTransform {
    private readonly i18n = inject(I18nService);

    transform(grade: SecurityGrade): string {
        return gradeLabel(grade, (key, params) => this.i18n.t(key, params));
    }
}
