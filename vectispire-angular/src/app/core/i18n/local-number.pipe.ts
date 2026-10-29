import { Pipe, PipeTransform, inject } from '@angular/core';
import { I18nService } from './i18n.service';

/**
 * `{{ row.medianDays | localNumber }}`: a figure in the reader's decimal mark (`I18nService.decimal`).
 *
 * Not Angular's `number` pipe: that one reads `LOCALE_ID`, fixed when the application starts, and
 * the language here changes at run time without a reload. Impure like `translate`, for the same
 * reason. An absent figure stays absent — `null`, so the template's `?? '—'` still decides how it
 * reads — rather than becoming "0"; a figure that is no number reads as a dash, never "NaN".
 */
@Pipe({
    name: 'localNumber',
    pure: false
})
export class LocalNumberPipe implements PipeTransform {
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
        return this.i18n.decimal(value, maximumFractionDigits, minimumFractionDigits);
    }
}
