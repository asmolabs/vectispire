import { Injectable, inject, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';

export type SupportedLanguage = 'en' | 'fr';

@Injectable({
    providedIn: 'root'
})
export class I18nService {
    private readonly http = inject(HttpClient);
    private readonly STORAGE_KEY = 'vectispire_lang';

    readonly supportedLanguages: readonly SupportedLanguage[] = ['en', 'fr'];
    readonly currentLang = signal<SupportedLanguage>('en');
    readonly translations = signal<Record<string, any>>({});
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
            const data = await firstValueFrom(this.http.get<Record<string, any>>(`/i18n/${lang}.json`));
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
     */
    t(key: string, params?: Record<string, string | number>): string {
        const dict = this.translations();
        const value = this.resolveKey(dict, key);

        if (typeof value !== 'string') {
            return key;
        }

        if (!params) {
            return value;
        }

        return Object.entries(params).reduce((acc, [paramKey, paramVal]) => {
            return acc.replace(new RegExp(`{{\\s*${paramKey}\\s*}}`, 'g'), String(paramVal));
        }, value);
    }

    private resolveKey(obj: Record<string, any>, path: string): any {
        if (!obj || !path) return null;
        return path.split('.').reduce((prev, curr) => (prev && prev[curr] !== undefined ? prev[curr] : null), obj);
    }
}
