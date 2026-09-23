import { TestBed } from '@angular/core/testing';
import english from '../../../../public/i18n/en.json';
import { I18nService, TranslationTree } from '../i18n/i18n.service';

/**
 * Loads the real English bundle under whatever a spec has already set.
 *
 * <p>A screen whose messages go through {@code i18n.t} shows the key itself when no bundle is
 * loaded, and a spec asserting the sentence then fails for a reason unrelated to what it tests.
 * Copying each sentence into each spec would be a second dictionary to keep in step; reading the
 * shipped one means a spec asserts what a reader actually sees. What a spec set explicitly wins, so
 * a test pinning its own wording keeps it.
 */
export function useEnglish(): void {
    const i18n = TestBed.inject(I18nService);
    i18n.translations.set(merge(english as TranslationTree, i18n.translations()));
}

function merge(base: TranslationTree, over: TranslationTree): TranslationTree {
    const out: TranslationTree = { ...base };
    for (const [key, value] of Object.entries(over)) {
        const below = out[key];
        out[key] = typeof value === 'object' && typeof below === 'object' ? merge(below, value) : value;
    }
    return out;
}
