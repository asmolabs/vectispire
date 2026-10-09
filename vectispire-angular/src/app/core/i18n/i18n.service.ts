import { Injectable, computed, inject, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';

export type SupportedLanguage = 'en' | 'fr';

/** A bundle: nested sections down to the strings, as the JSON files hold them. */
export type TranslationTree = { [key: string]: string | TranslationTree };

@Injectable({
    providedIn: 'root'
})
export class I18nService {
    private readonly http = inject(HttpClient);
    private readonly STORAGE_KEY = 'vectispire_lang';

    readonly supportedLanguages: readonly SupportedLanguage[] = ['en', 'fr'];
    readonly currentLang = signal<SupportedLanguage>('en');
    readonly translations = signal<TranslationTree>({});
    readonly isLoaded = signal<boolean>(false);

    /**
     * Initializes the language from stored preference or browser settings,
     * then loads the corresponding translation dictionary.
     */
    async init(): Promise<void> {
        const stored = localStorage.getItem(this.STORAGE_KEY) as SupportedLanguage | null;
        let initialLang: SupportedLanguage = 'en';

        if (stored && this.supportedLanguages.includes(stored)) {
            initialLang = stored;
        } else if (typeof navigator !== 'undefined' && navigator.language?.startsWith('fr')) {
            initialLang = 'fr';
        }

        await this.setLanguage(initialLang);
    }

    /**
     * Changes the current language and loads its translations if necessary.
     */
    async setLanguage(lang: SupportedLanguage): Promise<void> {
        if (!this.supportedLanguages.includes(lang)) {
            lang = 'en';
        }

        try {
            const data = await firstValueFrom(this.http.get<TranslationTree>(`/i18n/${lang}.json`));
            this.translations.set(data);
            this.currentLang.set(lang);
            this.isLoaded.set(true);
            localStorage.setItem(this.STORAGE_KEY, lang);
            if (typeof document !== 'undefined') {
                document.documentElement.lang = lang;
            }
        } catch (error) {
            console.error(`Failed to load translations for ${lang}:`, error);
        }
    }

    /**
     * Resolves a dotted key (e.g. 'menu.dashboard' or 'common.save') and substitutes
     * any interpolation parameters.
     *
     * **A `count` parameter chooses the plural form.** A key written as `key_one` / `key_other` in the
     * bundles is asked for as `key`, and the language's own rule picks the form: English says "1
     * repository" and "0 repositories", French "0 dépôt" and "2 dépôts" — 0 is singular there, which a
     * test on `count === 1` gets wrong. Before this, every count read "{{count}} repositories" or hid
     * behind "(s)", and a single scan was announced as "1 scans".
     */
    t(key: string, params?: Record<string, string | number>): string {
        const value = this.resolve(this.translations(), key, params?.['count']);

        if (value === undefined) {
            return key;
        }

        if (!params) {
            return value;
        }

        return Object.entries(params).reduce((acc, [paramKey, paramVal]) => {
            return acc.replace(new RegExp(`{{\\s*${paramKey}\\s*}}`, 'g'), String(paramVal));
        }, value);
    }

    /** Integer counts are the common case, and the pipe is impure: one rule object per language. */
    private readonly pluralRules = computed(() => new Intl.PluralRules(this.currentLang()));

    /**
     * The key itself, or its plural form for `count`. A key is plural when it has both `_one` and
     * `_other`: a key that merely ends that way — `gate_verdicts.refused_one`, `remediation.gap_other` —
     * is a word of its own, and must not be swapped in for its stem because a count was passed.
     * A plural key asked without a count gets its general form rather than showing as a raw key.
     */
    private resolve(dict: TranslationTree, key: string, count: string | number | undefined): string | undefined {
        const one = this.resolveKey(dict, `${key}_one`);
        const other = this.resolveKey(dict, `${key}_other`);
        if (typeof one === 'string' && typeof other === 'string') {
            if (count === undefined) return other;
            const form = this.resolveKey(dict, `${key}_${this.pluralForm(count)}`);
            return typeof form === 'string' ? form : other;
        }
        const direct = this.resolveKey(dict, key);
        return typeof direct === 'string' ? direct : undefined;
    }

    /**
     * A figure with decimals, in the reader's decimal mark: "12.5" in English, "12,5" in French.
     *
     * `toFixed` and a bare `{{ value }}` write the English mark whatever the language, and the
     * French screens read "11.4 jours" — a decimal point a French reader takes for a thousands
     * separator. `minimumFractionDigits` keeps a fixed width where a column or a tile wants one
     * ("5,0 j" beside "12,5 j"); the default drops a trailing zero.
     */
    decimal(value: number, maximumFractionDigits = 1, minimumFractionDigits = 0): string {
        return this.numberFormat(maximumFractionDigits, minimumFractionDigits).format(value);
    }

    private numberFormat(maximumFractionDigits: number, minimumFractionDigits: number): Intl.NumberFormat {
        return new Intl.NumberFormat(this.currentLang(), { maximumFractionDigits, minimumFractionDigits });
    }

    /** The current language's decimal and grouping marks, to read back a figure `decimal` wrote. */
    private readonly marks = computed(() => {
        const parts = new Intl.NumberFormat(this.currentLang()).formatToParts(12345.6);
        return {
            decimal: parts.find((part) => part.type === 'decimal')?.value ?? '.',
            group: parts.find((part) => part.type === 'group')?.value ?? ','
        };
    });

    /**
     * A count passed as text keeps its decimals for the rule: "1.0" is plural in English ("1.0
     * days") although the number it parses to is 1. The text is read in the current language's
     * marks, since `decimal` wrote it so: `Number("1,5")` is `NaN`, and a French "1,5 jour" would
     * have fallen to the plural form.
     */
    private pluralForm(count: string | number): Intl.LDMLPluralRule {
        if (typeof count === 'number') return this.pluralRules().select(count);
        const { decimal, group } = this.marks();
        const plain = count.split(group).join('').split(decimal).join('.');
        const value = Number(plain);
        if (!Number.isFinite(value)) return 'other';
        const decimals = plain.split('.')[1]?.length ?? 0;
        return decimals === 0
            ? this.pluralRules().select(value)
            : new Intl.PluralRules(this.currentLang(), { minimumFractionDigits: decimals }).select(value);
    }

    private resolveKey(obj: TranslationTree, path: string): string | TranslationTree | undefined {
        if (!obj || !path) return undefined;
        let node: string | TranslationTree | undefined = obj;
        for (const part of path.split('.')) {
            // A string reached before the path ends means the key goes deeper than the bundle.
            if (node === undefined || typeof node === 'string') return undefined;
            node = node[part];
        }
        return node;
    }
}
