import { Pipe, PipeTransform, inject } from '@angular/core';
import { I18nService } from './i18n.service';

/**
 * `{{ row.percentageWithinSla | localPercent }}`: a share in percentage points, with its sign as the
 * reader's language writes it (`I18nService.percent`) — "87.5%", "87,5 %".
 *
 * The sibling of `localNumber`, and impure for the same reason: the language changes without a
 * reload. A template never writes the `%` itself. An absent figure stays `null`, so the template's
 * `?? '—'` still decides how it reads; a figure that is no number reads as a dash, never "NaN %".
 */
@Pipe({
    name: 'localPercent',
    pure: false
})
export class LocalPercentPipe implements PipeTransform {
    private readonly i18n = inject(I18nService);

    transform(value: number, maximumFractionDigits?: number, minimumFractionDigits?: number): string;
    transform(
        value: number | null | undefined,
        maximumFractionDigits?: number,
        minimumFractionDigits?: number
    ): string | null;
    transform(value: number | null | undefined, maximumFractionDigits = 1, minimumFractionDigits = 0): string | null {
        if (value === null || value === undefined) return null;
        if (!Number.isFinite(value)) return '—';
        return this.i18n.percent(value, maximumFractionDigits, minimumFractionDigits);
    }
}
