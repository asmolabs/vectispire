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
 * does not, and that is intended — `settings-catalog.ts` falls back on the server's English label
 * when a key resolves to itself, so 52 keys exist in French with no English counterpart. Requiring
 * parity would fail on a correct tree, and that is how an exemption list begins.
 *
 * Only literal keys are checkable: a key built from a value is not a key this script can read — so
 * building one is refused outright (below), and a key held in a map is read where the map spells it.
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

/**
 * Every template, wherever it is written: the `.html` files, and the `template:` strings inline in
 * a component.
 *
 * **The template ratchets below read `.html` only, and eight components have no `.html`.** The
 * layout — topbar, sidebar, menu, footer, the theme configurator — writes its templates inline,
 * twelve hundred lines of them, and "Presets", "Menu Mode" or "Primary" sat there untranslated in a
 * French interface with every counter at zero. A rule that reads the wrong files reassures.
 */
const templates = () =>
    walk(join(root, 'src/app')).flatMap((file) => {
        if (file.endsWith('.html')) return [{ file, source: readFileSync(file, 'utf8') }];
        if (!file.endsWith('.ts') || file.endsWith('.spec.ts')) return [];
        const inline = readFileSync(file, 'utf8').match(/\btemplate:\s*`([\s\S]*?)`/);
        return inline ? [{ file, source: inline[1] }] : [];
    });

const bundle = (lang) =>
    new Set(flatten(JSON.parse(readFileSync(join(root, 'public/i18n', `${lang}.json`), 'utf8'))));

// **Both spellings, because only one was being seen.** This script recognised `t('key')` only.
// But an Angular template translating through the pipe — `{{ 'key' | translate }}`, the
// recommended form and the one most used here — contains none of those: a whole page written that
// way was neither counted nor checked, and a misspelt key would have gone through without a word,
// rendered as it stands on screen. The `.html` file was being read all the same, which gave the
// appearance of coverage.
// A segment after the namespace may be in capitals: it is then the server's own constant
// (`owasp_grid.state.NOT_COVERED`), and reading lower case alone left forty-four keys uncounted.
const CALL = /\bt\(\s*['"]([a-z0-9_]+(?:\.[A-Za-z0-9_]+)*)['"]/g;
const PIPE = /['"]([a-z0-9_]+(?:\.[A-Za-z0-9_]+)+)['"]\s*\|\s*translate\b/g;

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

// **A key built at run time is refused, and a key spelt in a map is read.**
//
// The two patterns above read a key only where it is written as the argument. Twenty-three sites
// in eleven files built theirs instead — `` t(`ssh_keys.encryption_status.${state}`) ``, `'soa.divergence.' +
// line.divergence | translate` — and this script counted none of them: a divergence added on the
// server, or a bundle entry lost in a merge, reached the reader as `soa.divergence.UNDERSTATED`
// with every check green. Decision 0019 had said "a screen renders literal keys" for a month; a
// rule that lives only in a document is followed by whoever happens to have read it.
//
// So the shape is refused: a template literal whose static text reads as a key of a bundle
// namespace with a hole in it, and a key prefix (`'ns.part.'`, `'ns.part_'`) joined with `+`. The
// cure is the one `shared/finding-types.ts` shows — a `Record<Union, 'ns.key'>` over the server's
// union, and the value shown as sent when it is one the client does not know.
//
// **And the map's keys are counted.** A key held in such a map is a quoted literal in a `.ts` file,
// not the argument of a call: read here as any literal shaped like a key whose first segment is a
// namespace of the bundles. Every one of them was in both bundles the day this was written — that
// is what lets the read be this wide without an exemption.
//
// **What it cannot see.** A prefix held in a variable (`const p = 'soa.'; t(p + x)`), a suffix
// joined on the right (`x + '.label'`, where `'.json'` would read the same), and `.concat`. Each
// is a deliberate detour round the rule rather than the habit it catches.
//
// **One exception, and why it is one.** The settings catalogue looks a translation up by the
// server's setting key and *falls back on the server's English label* when there is none — the
// English bundle has no `settings.keys` at all, by design (see the header of this file). The key is
// optional there, never shown: a miss shows the server's sentence, not a path. A `Record` over the
// setting keys would make every one of them required in English, which is the parity this script
// deliberately does not demand. Any other entry here is a decision for the review.
const BUILT_KEY_EXCEPTIONS = new Set([
    'src/app/pages/settings/settings-catalog.ts  `settings.keys.${…}.label`',
    'src/app/pages/settings/settings-catalog.ts  `settings.keys.${…}.help`'
]);
const namespaces = new Set(
    ['en', 'fr'].flatMap((lang) => Object.keys(JSON.parse(readFileSync(join(root, 'public/i18n', `${lang}.json`), 'utf8'))))
);
const KEY_SHAPE = /^[a-z0-9_]+(?:\.[A-Za-z0-9_]+)+$/;
const inNamespace = (text) => namespaces.has(text.split('.')[0]);
/** A template literal's text, holes as `\u0000`, that reads as a key once its holes are filled. */
const builtKey = (text) =>
    text.includes('\u0000') && /\./.test(text) && /^[a-z0-9_\u0000]+(?:\.[A-Za-z0-9_\u0000]+)+$/.test(text) && inNamespace(text);
/** A literal ending in `.` or `_` that names a namespace: the left half of a concatenated key. */
const keyPrefix = (text) => /^[a-z0-9_]+(?:\.[A-Za-z0-9_]+)*\.[A-Za-z0-9_]*$/.test(text) && /[._]$/.test(text) && inNamespace(text);

const builtKeys = [];
for (const file of walk(join(root, 'src/app'))) {
    if (!file.endsWith('.ts') || file.endsWith('.spec.ts') || file.endsWith('api.generated.ts')) continue;
    if (file.includes('/testing/')) continue;
    const relative = file.slice(root.length + 1);
    const source = readFileSync(file, 'utf8');
    const lineAt = (at) => source.slice(0, at).split('\n').length;
    for (const { text, multiline, at, end, template } of stringLiterals(source)) {
        if (multiline) continue;
        if (!template && KEY_SHAPE.test(text) && inNamespace(text)) referenced.add(text);
        if (template && builtKey(text)) {
            const spelt = `${relative}  \`${text.replace(/\u0000/g, '${…}')}\``;
            if (!BUILT_KEY_EXCEPTIONS.has(spelt)) builtKeys.push(`${relative}:${lineAt(at)}  ${spelt.split('  ')[1]}`);
        } else if (!template && keyPrefix(text) && /^\s*\+/.test(source.slice(end))) {
            builtKeys.push(`${relative}:${lineAt(at)}  '${text}' + …`);
        }
    }
}
// **The templates are read by pattern, not by the scanner.** A binding is a double-quoted attribute
// holding single-quoted literals — `[value]="'soa.divergence.' + line.divergence | translate"` — and
// a scanner pairing quotes reads the whole attribute as one string and the key inside it as nothing:
// the first draft of this rule missed exactly that line. The patterns admit only key characters
// between the quotes, so an apostrophe in a text node cannot pair with a key's opening quote and
// hide it.
for (const { file, source: raw } of templates()) {
    const relative = file.slice(root.length + 1);
    const source = raw.replace(/<!--[\s\S]*?-->/g, (comment) => comment.replace(/[^\n]/g, ' '));
    const lineAt = (at) => source.slice(0, at).split('\n').length;
    for (const match of source.matchAll(/'([A-Za-z0-9_.]+)'\s*\+/g)) {
        if (keyPrefix(match[1])) builtKeys.push(`${relative}:${lineAt(match.index)}  '${match[1]}' + …`);
    }
    for (const match of source.matchAll(/`([^`\n]*)`/g)) {
        const text = match[1].replace(/\$\{[^}]*\}/g, '\u0000');
        if (builtKey(text)) builtKeys.push(`${relative}:${lineAt(match.index)}  \`${match[1]}\``);
    }
}
if (builtKeys.length > 0) {
    console.error(`${builtKeys.length} translation key(s) built at run time, which this check cannot read:`);
    for (const offender of builtKeys) console.error(`  ${offender}`);
    console.error(
        `Spell each key: a Record<Union, 'ns.key'> over the server's union, as shared/finding-types.ts does, ` +
            `and show an unknown value as sent (decision 0019).`);
    process.exit(1);
}

// **The route titles, which live outside `src/app`.** `app.routes.ts` names each page's tab title
// as a key that `TranslatedTitleStrategy` resolves — neither a `t(…)` call nor a pipe, and in a
// file the walk above does not read. Unread, a misspelt title would reach the tab as the raw key.
// A title that is not a key is a sentence frozen in one language, which the `label:` ratchet
// below would refuse in `src/app` and cannot see here.
const ROUTE_TITLE = /\btitle:\s*['"]([a-z0-9_]+(?:\.[a-z0-9_]+)+)['"]/g;
const routes = readFileSync(join(root, 'src/app.routes.ts'), 'utf8');
for (const [, key] of routes.matchAll(ROUTE_TITLE)) {
    referenced.add(key);
}
const routeTitles = [...routes.matchAll(/\btitle:/g)].length;
if (routeTitles !== [...routes.matchAll(ROUTE_TITLE)].length) {
    console.error(`A route title in src/app.routes.ts is not a translation key: write 'titles.…' and add it to both bundles.`);
    process.exit(1);
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
const EXPECTED_KEYS = 3535;
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

/**
 * Hard-coded labels inside a property binding.
 *
 * **Zero from the day the check exists, and that is only tenable because the debt was paid in the
 * same commit.** Thirty-two were found the moment the guard learnt to look there; a ratchet would
 * have been the honest shape had they been left, and they were not.
 */
const BOUND_LABEL_CEILING = 0;
const accented = /[éèêàùûôîçÉÈÊÀÇ]/;
const frenchWords = new RegExp(
    '\\b(Composant|Composants|Cible|Cibles|Critique|Critiques|Ouverte|Ouvertes|Ouvert|Ouverts|' +
    'Résolue|Résolues|Sévérité|Dépôt|Dépôts|Règle|Règles|Chemin|Chemins|Exploitables|Priorité|' +
    'Aucun|Aucune|Levier|Estimé|Estimée|Détaillé|Détecté|Détectés|Détectées|Moyenne|Faible|' +
    'Inventaire|Politiques|Politique|Gouvernance|Conflits|Compatibilité|Matrice|' +
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
for (const { file, source } of templates()) {
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

// **The third ratchet: literals inside a binding, which neither of the other two can see.**
//
// The first reads `.ts` files, the second reads static attributes and text nodes. Neither reads
// `[label]="…"`, and the comment above says so plainly — "an expression either already goes
// through the dictionary or never will". That was wrong, and the count proves it: the ceiling
// read zero while thirty-two labels sat in bindings, seven of them French and the rest English.
//
// **The English half is the one that hid best.** Most were `aria-label`s — "Delete ", "Disable ",
// "Run a scan of " — so a French-speaking reader using a screen reader heard English, and nothing
// on screen showed it. A rule that looks in the wrong place is worse than an absent rule; this
// file already says so about the other half of the problem.
//
// **What this can and cannot tell apart.** A binding holds expressions, not just labels:
// `webhookCopied() === 'jira'` compares, `', '` and `' — '` join. The literals are taken by
// pairing quotes rather than by matching a pattern — a pattern spanning two separate literals
// reports the operator between them, which is how the first draft of this check flagged
// `':' + ep.lineNumber : ''` as prose. Flagged is a literal that holds a letter and then reads
// like prose: it contains a space, or begins with a capital and runs to three characters or more.
//
// That passes a lowercase one-word label, and it passes every separator. The miss is the cheaper
// of the two mistakes: a rule that fires on a comparison is a rule somebody switches off.
const textBinding = /\[(?:label|header|placeholder|pTooltip|title|ariaLabel|ariaDescription|emptyMessage|summary|detail|subheader|tooltip)\]="([^"]*)"/g;
const translated = /'[^']*'\s*\|\s*translate/g;

/** The quoted literals of an expression, paired in order — never matched across two of them. */
const literalsOf = (expression) => expression.split("'").filter((_, index) => index % 2 === 1);

let boundLabels = 0;
const boundOffenders = new Map();
for (const { file, source } of templates()) {
    let hits = 0;
    for (const [, expression] of source.matchAll(textBinding)) {
        for (const literal of literalsOf(expression.replace(translated, ''))) {
            if (!/[A-Za-zÀ-ÿ]/.test(literal)) continue;
            const looksLikeProse = /\s/.test(literal) || (/^[A-ZÀ-Ý]/.test(literal) && literal.length >= 3);
            if (looksLikeProse) hits += 1;
        }
    }
    if (hits > 0) {
        boundLabels += hits;
        boundOffenders.set(file.slice(root.length + 1), hits);
    }
}
if (boundLabels > BOUND_LABEL_CEILING) {
    console.error(
        `${boundLabels} hard-coded label(s) inside a binding, against a ceiling of ` +
        `${BOUND_LABEL_CEILING}.`);
    console.error(
        `A label in [label]="…" or [ariaLabel]="…" is a label the language preference never ` +
        `reaches. Route it through the translate pipe and add the key to both bundles.`);
    for (const [file, count] of [...boundOffenders].sort((a, b) => b[1] - a[1]).slice(0, 5)) {
        console.error(`  ${String(count).padStart(3)}  ${file}`);
    }
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

// **The fourth ratchet: visible text that comes from no key at all, in either language.**
//
// The three above hunt a *language*. The second says so in as many words — "frozen English is not
// detected the same way, any word at all is English" — and concludes that half the problem is
// undetectable. That conclusion follows from the question, not from the templates: asking which
// language a string is in has no mechanical answer, but asking whether a string came out of the
// dictionary has one. A translated template's visible text is an interpolation of a key. Anything
// else between two tags is text somebody typed, and it is typed in exactly one language whatever
// that language happens to be.
//
// Read that way the count was 390 across 21 templates, in both directions at once: `Global policy`,
// `Fail on actively exploited findings` and `Initial password` beside `Priorisation EPSS &
// Threat Intelligence` and `Centre de Notifications Webhooks`. The French half of that had been
// reported as zero for as long as this file has existed, because `frenchWords` is a list and a
// list only finds what somebody thought to add.
//
// **A ratchet and not a prohibition, because the debt cannot be paid in one commit.** The number
// may only fall. It has fallen twice: to 390 when `agents` and `rule-sets` were paid, and to 293
// when `gate-policies` and `repositories` were — each time because a French screenshot of those
// screens was about to be published, which is the honest reason and worth writing down. This is
// the guard rail, not the schedule.
//
// **It then fell to 10, and those ten are not debt.** The remaining templates were paid screen by
// screen. What is left is of two kinds, and neither is a sentence somebody forgot: four technical
// tokens a reader has to copy as they stand — `HMAC-SHA256`, the `X-Vectispire-Signature` header,
// `Authorization: Bearer`, a PEM placeholder — and six places where `>([^<>]…)<` spans two
// comparisons in adjacent class bindings (`[class.x]="score >= 70" [class.y]="score < 70"`). The
// ceiling stays a number rather than an exemption list, so the eleventh string still fails.
//
// **What it deliberately does not flag.** A bare word without a space and under four characters,
// which is where units, symbols and column keys live; an environment variable name, which has no
// translation; and anything inside `{{ … }}`, which has already been through the pipe or is a
// value. Control flow is removed before the text nodes are read — `@if (…) {` and `} @else {`
// are not prose, and a scanner that balances the parentheses is needed rather than a pattern,
// because `@if (activity()?.stats; as stats) {` closes three of them.
const UNTRANSLATED_TEXT_CEILING = 10;

/** Removes `@if (…) {`, `} @else if (…) {`, and the braces, leaving only what a reader sees. */
function stripControlFlow(source) {
    let out = '';
    let i = 0;
    while (i < source.length) {
        const keyword = /^@[a-z]+(\s+if)?/.exec(source.slice(i));
        if (keyword) {
            let j = i + keyword[0].length;
            while (j < source.length && /\s/.test(source[j])) j += 1;
            if (source[j] === '(') {
                let depth = 0;
                do {
                    if (source[j] === '(') depth += 1;
                    else if (source[j] === ')') depth -= 1;
                    j += 1;
                } while (j < source.length && depth > 0);
            }
            while (j < source.length && /\s/.test(source[j])) j += 1;
            if (source[j] === '{') j += 1;
            i = j;
            continue;
        }
        out += source[i] === '{' || source[i] === '}' ? ' ' : source[i];
        i += 1;
    }
    return out;
}

const environmentVariable = /^[A-Z][A-Z0-9_]{5,}$/;
// The product's own name, which the footer writes as text and no language translates. Counted, it
// would have made reading the inline templates look like a regression of one.
const productName = /^Vectispire$/;
let untranslated = 0;
const untranslatedOffenders = new Map();
for (const { file, source } of templates()) {
    const raw = source.replace(/<!--[\s\S]*?-->/g, '');
    // The interpolation becomes one neutral marker: it must not weld the words on either side of
    // it into a sentence that nobody wrote.
    const readable = stripControlFlow(raw.replace(/\{\{[\s\S]*?\}\}/g, '\u0000'))
        .replace(/&[a-z]+;|&#\d+;/g, ' ');
    let hits = 0;
    const consider = (candidate) => {
        const text = candidate.replace(/\u0000/g, '').replace(/\s+/g, ' ').trim();
        if (text.length < 3 || !/[A-Za-zÀ-ÿ]{3,}/.test(text)) return;
        if (environmentVariable.test(text)) return;
        if (productName.test(text)) return;
        const looksLikeProse = /\s/.test(text) || (/^[A-ZÀ-Ý]/.test(text) && text.length >= 4);
        if (looksLikeProse) hits += 1;
    };
    for (const [, text] of readable.matchAll(/>([^<>]{3,}?)</g)) consider(text);
    for (const [, text] of raw.matchAll(staticAttribute)) consider(text);
    if (hits > 0) {
        untranslated += hits;
        untranslatedOffenders.set(file.slice(root.length + 1), hits);
    }
}
if (untranslated > UNTRANSLATED_TEXT_CEILING) {
    console.error(
        `${untranslated} untranslated string(s) in the templates, against a ceiling of ` +
        `${UNTRANSLATED_TEXT_CEILING}.`);
    console.error(
        `Text written between two tags is shown in the language it was typed in, to every reader. ` +
        `Route it through the translate pipe and add the key to both bundles.`);
    for (const [file, count] of [...untranslatedOffenders].sort((a, b) => b[1] - a[1]).slice(0, 5)) {
        console.error(`  ${String(count).padStart(3)}  ${file}`);
    }
    process.exit(1);
}
if (untranslated < UNTRANSLATED_TEXT_CEILING) {
    console.error(
        `${untranslated} untranslated string(s), against a ceiling of ${UNTRANSLATED_TEXT_CEILING}: ` +
        `lower UNTRANSLATED_TEXT_CEILING in the same commit. A ratchet that is not tightened when ` +
        `the debt is paid gives the room straight back.`);
    process.exit(1);
}

// **The fifth ratchet: sentences written in the code, which no template check can see.**
//
// Every rule above reads templates or `label:` keys. The messages a screen shows are mostly
// neither: `this.error.set('Could not load the log.')`, a fallback after `??`, the second argument
// of `messageOf(…)`, a notice built with a template literal. A hundred and fifty of them sat in
// the components — errors, confirmations, status labels, pagination — in English on the English
// screens and in French on the attack surface, EPSS and compliance, reaching every reader in the
// language they were typed in, with every counter above at zero.
//
// **What counts.** A string literal in a component's code that reads like prose: two words or
// more, starting with a capital or carrying an accent. Not counted: comments, imports, inline
// templates (read above), `console` lines — a log is for the operator's terminal, not the screen —
// multi-line template literals, which here are the CI snippets a user copies as code, and tokens
// made only of capitals and digits (`EU CRA`, `NIS 2`), which are names rather than sentences.
const MESSAGES_IN_CODE_CEILING = 0;
/**
 * The string literals of a source file, read by a scanner rather than a pattern.
 *
 * A pattern pairs quotes wrongly as soon as a backtick sits inside a string, a comment or a regular
 * expression — the first draft matched `'Security Gate'` from inside a copied CI snippet because an
 * earlier backtick had shifted every pair after it. Comments are skipped, `'…'` and `"…"` are read
 * to their closing quote, and a template literal is read with its `${…}` holes; one that spans
 * lines is reported as such, since here those are the snippets a user copies as code.
 */
function stringLiterals(source) {
    const found = [];
    let i = 0;
    const readTemplate = () => {
        let text = '';
        let multiline = false;
        i += 1;
        while (i < source.length && source[i] !== '`') {
            if (source[i] === '\\') { text += source.slice(i, i + 2); i += 2; continue; }
            if (source[i] === '$' && source[i + 1] === '{') {
                let depth = 1;
                i += 2;
                while (i < source.length && depth > 0) {
                    if (source[i] === '{') depth += 1;
                    else if (source[i] === '}') depth -= 1;
                    else if (source[i] === '`') readTemplate();
                    i += 1;
                }
                text += '\u0000';
                continue;
            }
            if (source[i] === '\n') multiline = true;
            text += source[i];
            i += 1;
        }
        i += 1;
        return { text, multiline };
    };
    while (i < source.length) {
        const c = source[i];
        if (c === '/' && source[i + 1] === '/') { i = source.indexOf('\n', i); if (i < 0) break; continue; }
        if (c === '/' && source[i + 1] === '*') { i = source.indexOf('*/', i + 2); if (i < 0) break; i += 2; continue; }
        if (c === "'" || c === '"') {
            let j = i + 1;
            while (j < source.length && source[j] !== c && source[j] !== '\n') j += source[j] === '\\' ? 2 : 1;
            found.push({ text: source.slice(i + 1, j), multiline: false, at: i, end: j + 1 });
            i = j + 1;
            continue;
        }
        if (c === '`') {
            const at = i;
            const { text, multiline } = readTemplate();
            found.push({ text, multiline, at, end: i, template: true });
            continue;
        }
        i += 1;
    }
    return found;
}

let messagesInCode = 0;
const messageOffenders = new Map();
for (const file of walk(join(root, 'src/app'))) {
    if (!file.endsWith('.ts') || file.endsWith('.spec.ts') || file.endsWith('api.generated.ts')) continue;
    if (file.includes('/testing/')) continue;
    const source = readFileSync(file, 'utf8');
    const lineOf = (at) => source.slice(source.lastIndexOf('\n', at) + 1, source.indexOf('\n', at));
    let hits = 0;
    for (const { text, multiline, at } of stringLiterals(source)) {
        if (multiline) continue;
        const line = lineOf(at);
        if (/^\s*import\b/.test(line) || /\bconsole\.\w+\(/.test(line) || /\btemplate:\s*`/.test(line)) continue;
        if (!/^[A-ZÀ-Ý"«]/.test(text) && !accented.test(text)) continue;
        if (!/[A-Za-zÀ-ÿ]{2,}[\s'’][A-Za-zÀ-ÿ]{2,}/.test(text)) continue;
        if (/^[A-Z0-9 .\-]+$/.test(text)) continue;
        hits += 1;
    }
    if (hits > 0) {
        messagesInCode += hits;
        messageOffenders.set(file.slice(root.length + 1), hits);
    }
}
if (messagesInCode !== MESSAGES_IN_CODE_CEILING) {
    console.error(
        `${messagesInCode} sentence(s) written in the code, against a ceiling of ${MESSAGES_IN_CODE_CEILING}.`);
    console.error(
        messagesInCode > MESSAGES_IN_CODE_CEILING
            ? `A message set from the code is shown in the language it was typed in. Route it through ` +
                  `i18n.t and add the key to both bundles.`
            : `Lower MESSAGES_IN_CODE_CEILING in the same commit: a ratchet not tightened gives the room back.`);
    for (const [file, count] of [...messageOffenders].sort((a, b) => b[1] - a[1]).slice(0, 8)) {
        console.error(`  ${String(count).padStart(3)}  ${file}`);
    }
    process.exit(1);
}

// **The sixth rule: a static attribute a reader sees, which is never prose.**
//
// The ratchets above read `label`, `placeholder`, `header`, `title` and `ariaLabel`, and count only
// what looks like prose: a space, or a capital and four letters. `<p-tag value="AJOUTÉ">` was in
// none of those attributes, and `value="Configuré"`, `value="UNPROTECTED"`, `value="HIGH RISK"` with
// it: the inventory diff told an English reader "SUPPRIMÉ", the notification channels "Inactif",
// with every counter at zero. A tag's `value` is its whole visible text, and an `alt` is what a
// screen reader says for an image — `alt="Vectispire Security Badge"` stayed English in French.
//
// So this one is a prohibition with no prose heuristic: any static value with a letter in it, on
// an attribute that is shown or spoken, fails — the bound form `[value]="'key' | translate"` is the
// only way to write one. `value` counts only on the display components; on an `<option>` or a radio
// button it is the form's value, never shown. Text around an interpolation (`title="Delete {{ x }}"`)
// counts too: the interpolated part is a value, the rest is a sentence in one language.
//
// **What passes.** A placeholder written in lower case without a space is an example of what to
// type — a URL, a host, a branch, an image tag, `customer-network` — and is the same in every
// language. And three exact values, each the same word in both: `KEV`, the name of CISA's Known
// Exploited Vulnerabilities catalogue, which the French interface also calls KEV; `CI/CD`, the
// trade's own term; and the PEM header of the key field, which a reader must recognise as it
// stands. A fourth entry is a decision for the review, not a convenience.
const SHOWN_ATTRIBUTES = new Set([
    'label', 'header', 'subheader', 'placeholder', 'title', 'ariaLabel', 'aria-label', 'alt',
    'pTooltip', 'emptyMessage', 'emptyFilterMessage', 'filterPlaceholder'
]);
const DISPLAY_COMPONENTS = new Set(['p-tag', 'p-badge', 'p-chip']);
const STATIC_TOKENS = new Set(['KEV', 'CI/CD', '-----BEGIN PUBLIC KEY----- ...']);
const exampleInput = /^[a-z0-9][a-z0-9./:_\-…]*$/;

/** The opening tags of a template, read with their quotes respected: `[x]="a > b"` does not end one. */
function* openingTags(source) {
    for (const match of source.matchAll(/<([a-zA-Z][\w-]*)\b/g)) {
        let quote = null;
        let end = source.length;
        for (let i = match.index; i < source.length; i += 1) {
            const c = source[i];
            if (quote) {
                if (c === quote) quote = null;
            } else if (c === '"' || c === "'") quote = c;
            else if (c === '>') { end = i; break; }
        }
        yield { name: match[1], text: source.slice(match.index, end), at: match.index };
    }
}

const frozenAttributes = [];
for (const { file, source } of templates()) {
    const raw = source.replace(/<!--[\s\S]*?-->/g, (comment) => comment.replace(/[^\n]/g, ' '));
    for (const tag of openingTags(raw)) {
        for (const [, attribute, value] of tag.text.matchAll(/\s([a-zA-Z][\w-]*)="([^"]*)"/g)) {
            const shown = SHOWN_ATTRIBUTES.has(attribute) || (attribute === 'value' && DISPLAY_COMPONENTS.has(tag.name));
            if (!shown) continue;
            const text = value.replace(/\{\{[\s\S]*?\}\}/g, '').trim();
            if (!/[A-Za-zÀ-ÿ]/.test(text) || STATIC_TOKENS.has(text)) continue;
            if (attribute === 'placeholder' && exampleInput.test(text)) continue;
            const line = raw.slice(0, tag.at).split('\n').length;
            frozenAttributes.push(`${file.slice(root.length + 1)}:${line}  <${tag.name} ${attribute}="${value}">`);
        }
    }
}
if (frozenAttributes.length > 0) {
    console.error(`${frozenAttributes.length} static attribute(s) showing text no language preference reaches:`);
    for (const offender of frozenAttributes) console.error(`  ${offender}`);
    console.error(
        `Bind it through the pipe — [value]="'section.key' | translate" — with the key in both bundles. ` +
            `If it is a token every language writes alike, it belongs in STATIC_TOKENS, with its reason.`);
    process.exit(1);
}

// **A plural key is referenced by its stem.** `t('repositories.scan_all_queued', { count })` reads
// `scan_all_queued_one` or `scan_all_queued_other` as the language's rule says (I18nService.t), so
// the stem is present when both forms are: the `_one` alone would leave every other count a raw
// key, the `_other` alone would say "1 repositories" again. A key that only ends that way —
// `gate_verdicts.refused_one` beside `refused` — is a word of its own, and the service treats it so.
// What is refused is a stem both plain and plural: which one the reader got would depend on whether
// a count happened to be passed.
const presentIn = (known, key) => known.has(key) || (known.has(`${key}_one`) && known.has(`${key}_other`));
let failed = false;
for (const lang of ['en', 'fr']) {
    const known = bundle(lang);
    const ambiguous = [...known]
        .filter((key) => key.endsWith('_other'))
        .map((key) => key.slice(0, -'_other'.length))
        .filter((stem) => known.has(stem) && known.has(`${stem}_one`));
    if (ambiguous.length > 0) {
        failed = true;
        console.error(`Keys both plain and plural in public/i18n/${lang}.json:`);
        for (const key of ambiguous) console.error(`  - ${key}`);
    }
    const missing = [...referenced].filter((key) => !presentIn(known, key)).sort();
    if (missing.length > 0) {
        failed = true;
        console.error(`Keys missing from public/i18n/${lang}.json:`);
        for (const key of missing) console.error(`  - ${key}`);
    }
}

// **A count is spelt by a plural pair, never by "(s)".** Twelve messages still wrote "entrée(s)
// vérifiée(s)", "member(s)", "Line(s) 1 are": two counts in one sentence, or a count that was a list
// of line numbers, had kept them out of the `_one`/`_other` move. Each is a pair now — a second count
// is a phrase of its own passed in (`{{targets}}` is `teams.delete_consequence_targets`), a list of
// lines passes its length as `count`. `http(s)` is a scheme, not a plural.
const hedgedPlural = /[A-Za-zÀ-ÿ]\((?:s|es|ies|x)\)/;
for (const lang of ['en', 'fr']) {
    const tree = JSON.parse(readFileSync(join(root, 'public/i18n', `${lang}.json`), 'utf8'));
    const hedged = flatten(tree).filter((key) => {
        const value = key.split('.').reduce((node, part) => node[part], tree);
        return hedgedPlural.test(value.replace(/\bhttp\(s\)/g, ''));
    });
    if (hedged.length > 0) {
        failed = true;
        console.error(`Messages hedging a plural with "(s)" in public/i18n/${lang}.json — write a _one/_other pair:`);
        for (const key of hedged) console.error(`  - ${key}`);
    }
}

// **And a plural key asked for by name is given its count.** Without one, I18nService.t falls back
// on `_other`: "1 entries verified", exactly the sentence the pair exists to prevent, and nothing on
// screen tells the missing argument apart from a correct plural. Only a literal reference can be read
// — a key held in a map (`CONFLICT_KEYS`, `AS_MEASURED_SKIP_KEYS`) is asked for through a variable, and
// its call passes `count` for every key the map holds.
const pluralStems = new Set(
    ['en', 'fr'].flatMap((lang) => {
        const known = bundle(lang);
        return [...known]
            .filter((key) => key.endsWith('_one') && known.has(`${key.slice(0, -4)}_other`))
            .map((key) => key.slice(0, -4));
    })
);
const countless = [];
for (const file of walk(join(root, 'src/app'))) {
    if (!/\.(ts|html)$/.test(file) || file.endsWith('.spec.ts')) continue;
    const source = readFileSync(file, 'utf8');
    const asked = [
        ...source.matchAll(/['"]([a-z0-9_]+(?:\.[a-z0-9_]+)+)['"]\s*\|\s*translate\b(\s*:)?/g),
        ...source.matchAll(/\bt\(\s*['"]([a-z0-9_.]+)['"]\s*(,)?/g)
    ];
    for (const match of asked) {
        if (!pluralStems.has(match[1])) continue;
        const args = match[2] ? source.slice(match.index + match[0].length, match.index + match[0].length + 300) : '';
        if (/^\s*\{[^}]*\bcount\b/.test(args)) continue;
        const line = source.slice(0, match.index).split('\n').length;
        countless.push(`${file.slice(root.length + 1)}:${line}  ${match[1]}`);
    }
}
if (countless.length > 0) {
    failed = true;
    console.error('Plural keys asked for without a count — the reader would get the plural whatever the number:');
    for (const offender of countless) console.error(`  - ${offender}`);
}

if (failed) {
    console.error(
        'Fix the keys listed above: an unresolved key is shown as it stands, and a hedged or countless ' +
            'plural reads wrong for every number but one.');
    process.exit(1);
}

console.log(
    `i18n check: ${referenced.size} keys referenced, all present in French and English; ` +
    `${hardcoded} hard-coded labels (ceiling ${HARDCODED_LABEL_CEILING}); ` +
    `${frozenFrench} frozen French labels in the templates (ceiling ${FRENCH_IN_TEMPLATES_CEILING}); ` +
    `${boundLabels} hard-coded labels inside a binding (ceiling ${BOUND_LABEL_CEILING}); ` +
    `${untranslated} untranslated strings in the templates (ceiling ${UNTRANSLATED_TEXT_CEILING}); ` +
    `${messagesInCode} sentences in the code (ceiling ${MESSAGES_IN_CODE_CEILING}); ` +
    `no static attribute showing text (${STATIC_TOKENS.size} tokens allowed).`);
