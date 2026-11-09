import english from '../../../../public/i18n/en.json';
import french from '../../../../public/i18n/fr.json';

const lookup = (bundle: unknown, key: string): unknown =>
    key.split('.').reduce<unknown>((node, part) => (node as Record<string, unknown> | undefined)?.[part], bundle);

/**
 * The keys of a literal-key map that one of the two bundles lacks, as `en: a.b` / `fr: a.b`.
 *
 * The compiler proves every member of a union has an entry in its `Record<Union, 'a.b'>`; it cannot
 * prove the entry names a sentence. A spec asserting this is empty is what does — the same check as
 * `check-i18n-keys.mjs`, at the level of one map, so a failure names the map it came from.
 */
export function missingFromBundles(keys: Iterable<string>): string[] {
    const missing: string[] = [];
    for (const key of keys) {
        if (typeof lookup(english, key) !== 'string') missing.push(`en: ${key}`);
        if (typeof lookup(french, key) !== 'string') missing.push(`fr: ${key}`);
    }
    return missing;
}
