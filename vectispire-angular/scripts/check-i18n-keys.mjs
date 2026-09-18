#!/usr/bin/env node
/**
 * Checks that every translation key a screen asks for exists in both bundles.
 *
 * Why this script exists: the AI provider picker offered two hard-coded English labels —
 * `'Ollama — a model on a host you run'`, `'OpenAI-compatible API'` — on a screen where every
 * other label went through `i18n.t`. Three successive audits reported it with nothing able to
 * see it. Routing them through the bundles fixed that screen; this prevents the *next* key from
 * being referenced and never added, which shows the key itself to the operator and looks like a
 * typo rather than a missing translation.
 *
 * What this script checks, since 30 August: that the *number* of referenced keys is the expected
 * one — a floor at 40 had let a fall from 54 to 52 through without a word, that is the exact
 * return of the defect above — and that the number of hard-coded labels does not rise. The second
 * is a ratchet, not a prohibition: the interface is only partly translated, and a rule that fails
 * on its first run is a rule people switch off.
 *
 * What this script deliberately does not check: that the French bundle mirrors the English. It
 * does not, and that is intended — `settings.ts` falls back on the server's English label when a
 * key resolves to itself, so 52 keys exist in French with no English counterpart. Requiring parity
 * would fail on a correct tree, and that is how an exemption list begins.
 *
 * Only literal calls are checkable: a key built from a variable is not a key this script can read.
 *
 * Run by `npm test` before the unit suite, like `check-assets.mjs`: it is a file check, it needs
 * no browser.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

const flatten = (value, prefix = '') =>
    Object.entries(value).flatMap(([key, child]) => {
        const path = prefix ? `${prefix}.${key}` : key;
        return child !== null && typeof child === 'object'
            ? flatten(child, path)
            : [path];
    });

const walk = (dir) =>
    readdirSync(dir).flatMap((entry) => {
        const path = join(dir, entry);
        return statSync(path).isDirectory() ? walk(path) : [path];
    });

const bundle = (lang) =>
    new Set(flatten(JSON.parse(readFileSync(join(root, 'public/i18n', `${lang}.json`), 'utf8'))));

// **Both spellings, because only one was being seen.** This script recognised `t('key')` only.
// But an Angular template translating through the pipe — `{{ 'key' | translate }}`, the
// recommended form and the one most used here — contains none of those: a whole page written that
// way was neither counted nor checked, and a misspelt key would have gone through without a word,
// rendered as it stands on screen. The `.html` file was being read all the same, which gave the
// appearance of coverage.
const CALL = /\bt\(\s*['"]([a-z0-9_.]+)['"]/g;
const PIPE = /['"]([a-z0-9_]+(?:\.[a-z0-9_]+)+)['"]\s*\|\s*translate\b/g;

const referenced = new Set();
for (const file of walk(join(root, 'src/app'))) {
    if (!/\.(ts|html)$/.test(file) || file.endsWith('.spec.ts')) continue;
    const source = readFileSync(file, 'utf8');
    for (const pattern of [CALL, PIPE]) {
        for (const [, key] of source.matchAll(pattern)) {
            referenced.add(key);
        }
    }
}

// **The count is pinned, not floored, and it is pinned because the floor saw nothing.** This file
// first carried `if (referenced.size < 40)`. An audit put back the two hard-coded labels this
// script had been written to prevent: the count fell from 54 to 52, 40 stayed cleared, the suite
// went green and the defect was back without a word. A floor that cannot be reached never fires;
// it is a guard rail that looks like one.
//
// An exact number is updated in the same commit as the key being added or removed, so it asks the
// question at the moment somebody can answer it. Changing it is a one-line move — but it is a
// *deliberate* move, and that is the whole difference.
const EXPECTED_KEYS = 1067;
if (referenced.size !== EXPECTED_KEYS) {
    const direction = referenced.size < EXPECTED_KEYS ? 'disappeared' : 'appeared';
    console.error(
        `${referenced.size} keys referenced in src/app, ${EXPECTED_KEYS} expected: ` +
        `${Math.abs(referenced.size - EXPECTED_KEYS)} ${direction}.`);
    console.error(
        `If that is intended, update EXPECTED_KEYS in the same commit. If it is not, a label has ` +
        `just gone hard-coded again — which is exactly what happened on 30 August, and the floor ` +
        `of 40 this file used to carry did not see it.`);
    process.exit(1);
}

// **No hard-coded labels left, and the ceiling is zero.**
//
// This file first carried a ratchet at 89: `src/app` held that many, across 14 files, and a rule
// that fails on its very first run is a rule people switch off. The ratchet was the right shape
// while the debt existed — it blocked the *next* one without demanding that all 89 be translated
// the same day.
//
// They were. The ceiling therefore drops to 0, and the ratchet becomes a prohibition: it is the
// rule we wanted from the start, and it is only tenable now.
//
// What the 89 hid, and what counting them did not show: the interface was not "hard-coded
// English", it was **hard-coded bilingual in both wrong directions**. The attack surface,
// compliance and licences carried frozen French labels, which the English-speaking reader received
// as they stood; the findings, the dashboard and the roles carried frozen English, which the
// French-speaking reader received as they stood. No language preference changed a single one.
const HARDCODED_LABEL_CEILING = 0;
const literalLabel = /\b(?:label|title|placeholder|header|hint)\s*:\s*'([^']{2,})'/g;
let hardcoded = 0;
const worstOffenders = new Map();
for (const file of walk(join(root, 'src/app'))) {
    if (!/\.ts$/.test(file) || file.endsWith('.spec.ts')) continue;
    const hits = [...readFileSync(file, 'utf8').matchAll(literalLabel)];
    if (hits.length > 0) {
        hardcoded += hits.length;
        worstOffenders.set(file.slice(root.length + 1), hits.length);
    }
}
// **The second ratchet: the labels frozen in the *templates*, which the first does not see.**
//
// The ceiling above reads only `.ts` files and looks in them only for `label: '…'`. It therefore
// reported zero hard-coded labels while twelve templates carried a hundred and forty-three, in
// French, inside an English interface: the dashboard ran "Failing targets" straight into "Dette de
// Sécurité Estimée", and a "Cibles Affectées" column sat next to a "Target" column. A rule that
// looks in the wrong place is worse than an absent rule — it reassures.
//
// **What is detectable, and what is not.** An accented text node is frozen French, mechanically:
// no translation key contains one. Frozen English is not detected the same way — any word at all
// is English — so this ratchet covers one half of the problem, and saying so here beats letting
// people believe it covers both.
//
// **Accents alone were not enough either.** The counter reached zero while the dashboard still
// showed "Composant", "Score de Levier (ROI)", "Critiques Ouvertes" — French without a single
// accent. A word list fills the gap where accents stop; it will never be complete, but every word
// added is a word that will not come back.
const FRENCH_IN_TEMPLATES_CEILING = 0;
const accented = /[éèêàùûôîçÉÈÊÀÇ]/;
const frenchWords = new RegExp(
    '\\b(Composant|Composants|Cible|Cibles|Critique|Critiques|Ouverte|Ouvertes|Ouvert|Ouverts|' +
    'Résolue|Résolues|Sévérité|Dépôt|Dépôts|Règle|Règles|Chemin|Chemins|Exploitables|Priorité|' +
    'Aucun|Aucune|Levier|Estimé|Estimée|Détaillé|Détecté|Détectés|Détectées|Moyenne|Faible|' +
    'Élevée|Élevé|Score de|Total Chemins|Liées|Impactées|Ajoutés|Supprimés|Calculer|Différentiel|Nouveaux|Nouvelle|Ancienne|Licence|Licences|Changement|Solde)\\b');
const textNode = />([^<>{}]{3,}?)</g;

// **And the attribute labels, which the text node does not see.** `label="Matrice de
// Compatibilité Légale"` is not between two angle brackets: it escaped both ratchets — the first
// because it reads only `.ts`, the second because it reads only text nodes. Yet that is the shape
// a PrimeNG button takes, and so the likeliest place for a frozen label. Only static values are
// read: `[label]="…"` is an expression, and an expression either already goes through the
// dictionary or never will.
const staticAttribute = /\s(?:label|placeholder|header|title|ariaLabel)="([^"{}]{3,}?)"/g;
let frozenFrench = 0;
const frenchOffenders = new Map();
for (const file of walk(join(root, 'src/app'))) {
    if (!/\.html$/.test(file)) continue;
    const source = readFileSync(file, 'utf8');
    const hits = [...source.matchAll(textNode), ...source.matchAll(staticAttribute)]
        .map((match) => match[1].trim())
        .filter((text) => accented.test(text) || frenchWords.test(text));
    if (hits.length > 0) {
        frozenFrench += hits.length;
        frenchOffenders.set(file.slice(root.length + 1), hits.length);
    }
}
if (frozenFrench > FRENCH_IN_TEMPLATES_CEILING) {
    console.error(
        `${frozenFrench} frozen French label(s) in the templates, against a ceiling of ` +
        `${FRENCH_IN_TEMPLATES_CEILING}.`);
    console.error(
        `A label written in plain text shows in the language it was typed in, to everybody. Route ` +
        `it through the translate pipe and add the key to both bundles.`);
    for (const [file, count] of [...frenchOffenders].sort((a, b) => b[1] - a[1]).slice(0, 5)) {
        console.error(`  ${String(count).padStart(3)}  ${file}`);
    }
    process.exit(1);
}
if (frozenFrench < FRENCH_IN_TEMPLATES_CEILING) {
    console.error(
        `${frozenFrench} frozen French label(s), against a ceiling of ` +
        `${FRENCH_IN_TEMPLATES_CEILING}: lower FRENCH_IN_TEMPLATES_CEILING in the same commit. A ` +
        `ratchet nobody tightens stops being a debt and becomes a permission.`);
    process.exit(1);
}

if (hardcoded > HARDCODED_LABEL_CEILING) {
    console.error(`${hardcoded} hard-coded label(s) in src/app, against a ceiling of 0.`);
    console.error(
        `A label written in plain text is a label the language preference does not touch: it will ` +
        `show in the language it was typed in, to everybody. Route it through i18n.t and add the ` +
        `key to both bundles.`);
    for (const [file, count] of [...worstOffenders].sort((a, b) => b[1] - a[1]).slice(0, 5)) {
        console.error(`  ${count.toString().padStart(3)}  ${file}`);
    }
    process.exit(1);
}

let failed = false;
for (const lang of ['en', 'fr']) {
    const known = bundle(lang);
    const missing = [...referenced].filter((key) => !known.has(key)).sort();
    if (missing.length > 0) {
        failed = true;
        console.error(`Keys missing from public/i18n/${lang}.json:`);
        for (const key of missing) console.error(`  - ${key}`);
    }
}

if (failed) {
    console.error('Add them to both bundles: an unresolved key is shown as it stands.');
    process.exit(1);
}

console.log(
    `i18n check: ${referenced.size} keys referenced, all present in French and English; ` +
    `${hardcoded} hard-coded labels (ceiling ${HARDCODED_LABEL_CEILING}); ` +
    `${frozenFrench} frozen French labels in the templates (ceiling ${FRENCH_IN_TEMPLATES_CEILING}).`);
