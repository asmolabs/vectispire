import { I18nService, SupportedLanguage, TranslationTree } from './i18n.service';

/**
 * The last answer of a pipe whose text depends on the language, given again while neither its
 * arguments nor the language have changed.
 *
 * **Why the pipes stay impure.** Angular memoizes a pure pipe on its arguments alone
 * (`ɵɵpipeBind1` compares the bound values, nothing else), and the language is not one of them: a
 * pure `translate` would keep every label of an open page in the language it was first drawn in.
 * Passing the language as an argument would mean editing every one of the template's pipes, and
 * re-creating the views on a switch would throw away a form being filled in. So the pipes are still
 * called on every pass, and this makes the call cheap: three identity comparisons instead of walking
 * the bundle, testing the plural forms and building an `Intl` formatter — on the checklist screen,
 * ninety-nine lookups per pass, each of them for the same answer as the pass before.
 *
 * The bundle and the language are read from their signals, so a switch — or the bundle arriving after
 * the first render, when every key still shows as itself — invalidates every memo at once. Arguments
 * compare by identity, and a plain object (the `{ count: n }` of a plural) by its entries too: a
 * template literal keeps its identity, a method building the object on each pass does not.
 */
export class LanguageMemo<T> {
    private args: readonly unknown[] | undefined;
    private bundle: TranslationTree | undefined;
    private language: SupportedLanguage | undefined;
    private value: T | undefined;

    constructor(private readonly i18n: I18nService) {}

    get(args: readonly unknown[], compute: () => T): T {
        const bundle = this.i18n.translations();
        const language = this.i18n.currentLang();
        if (this.args && bundle === this.bundle && language === this.language && sameArguments(this.args, args)) {
            return this.value as T;
        }
        this.value = compute();
        this.args = args;
        this.bundle = bundle;
        this.language = language;
        return this.value;
    }
}

function sameArguments(before: readonly unknown[], now: readonly unknown[]): boolean {
    return before.length === now.length && before.every((value, index) => sameValue(value, now[index]));
}

function sameValue(before: unknown, now: unknown): boolean {
    if (Object.is(before, now)) return true;
    if (!isPlainObject(before) || !isPlainObject(now)) return false;
    const keys = Object.keys(before);
    return keys.length === Object.keys(now).length && keys.every((key) => Object.is(before[key], now[key]));
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
    if (typeof value !== 'object' || value === null) return false;
    const prototype = Object.getPrototypeOf(value) as unknown;
    return prototype === Object.prototype || prototype === null;
}
