import { TestBed } from '@angular/core/testing';
import english from '../../../../public/i18n/en.json';
import french from '../../../../public/i18n/fr.json';
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
    i18n.translations.set(merge(english, i18n.translations()));
}

function merge(base: TranslationTree, over: TranslationTree): TranslationTree {
    const out: TranslationTree = { ...base };
    for (const [key, value] of Object.entries(over)) {
        const below = out[key];
        out[key] = typeof value === 'object' && typeof below === 'object' ? merge(below, value) : value;
    }
    return out;
}

/**
 * The real French bundle, and French as the current language — the decimal mark and the plural rule
 * follow `currentLang`, so a spec about how a French reader sees a figure needs both, not the bundle
 * alone. It **replaces** what was loaded rather than merging under it: called after `useEnglish`, a
 * merge would keep every English sentence, which is the switch a spec of the French screen is testing.
 */
export function useFrench(): void {
    const i18n = TestBed.inject(I18nService);
    i18n.translations.set(french);
    i18n.currentLang.set('fr');
}
