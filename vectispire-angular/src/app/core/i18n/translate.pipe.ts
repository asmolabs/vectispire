import { Pipe, PipeTransform, inject } from '@angular/core';
import { I18nService } from './i18n.service';
import { LanguageMemo } from './language-memo';

/**
 * `{{ 'key' | translate }}`. Impure, because a pure pipe would not follow a language switch, and
 * memoized, so the pass that finds nothing changed costs three comparisons ({@link LanguageMemo}).
 */
@Pipe({
    name: 'translate',
    pure: false
})
export class TranslatePipe implements PipeTransform {
    private readonly i18n = inject(I18nService);
    private readonly memo = new LanguageMemo<string>(this.i18n);

    transform(key: string, params?: Record<string, string | number>): string {
        if (!key) return '';
        return this.memo.get([key, params], () => this.i18n.t(key, params));
    }
}
