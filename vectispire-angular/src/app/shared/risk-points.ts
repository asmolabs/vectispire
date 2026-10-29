import { Pipe, PipeTransform, inject } from '@angular/core';
import { I18nService } from '../core/i18n/i18n.service';

/**
 * "54.5 risk points", in the reader's language and decimal mark.
 *
 * The risk points are a sum of what is open, weighted (decision 0036): a medium weighs 0.5 and a low
 * 0.125, so the figure has decimals, and French writes them with a comma. The plural follows the
 * number itself — French reads "0,5 point de risque", English "0.5 risk points" — which is why the
 * count goes to `t` as a number and the figure as text beside it. Never a percentage: there is no
 * total it is a share of.
 */
export function riskPointsLabel(points: number, i18n: Pick<I18nService, 't' | 'currentLang'>): string {
    const figure = new Intl.NumberFormat(i18n.currentLang(), { maximumFractionDigits: 3 }).format(points);
    return i18n.t('repositories.risk_points', { count: points, points: figure });
}

@Pipe({
    name: 'riskPoints',
    // Impure like `translate`: the text changes when the language does.
    pure: false
})
export class RiskPointsPipe implements PipeTransform {
    private readonly i18n = inject(I18nService);

    transform(points: number): string {
        return riskPointsLabel(points, this.i18n);
    }
}
