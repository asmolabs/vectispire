import { Pipe, PipeTransform } from '@angular/core';
import { gradeSeverity } from '../../shared/scorecard';

/**
 * `row.grade | gradeTone` — a grade's colour, one target, one grade, painted alike on every screen
 * (`gradeSeverity`). Pure: the colour depends on the grade alone, so Angular calls it again only for
 * a new one, where the dashboard called a method per tag on every pass.
 */
@Pipe({ name: 'gradeTone' })
export class GradeTonePipe implements PipeTransform {
    transform(grade: string | undefined): ReturnType<typeof gradeSeverity> {
        return gradeSeverity(grade);
    }
}
