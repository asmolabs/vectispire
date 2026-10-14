#!/usr/bin/env node
/**
 * Refuses a spec that is allowed to be untyped again.
 *
 * <p><b>Why this guard exists.</b> For as long as the lint was type-aware, `eslint.config.js` switched
 * the three `no-unsafe-*` rules off for `*.spec.ts`, on the ground that specs handle `any` by nature
 * and that the assertion which follows is the check. It is not. `request.body` and
 * `fixture.nativeElement` are `any`, so `expect(body.expires_in_days)` compiled whatever
 * `TriageRequest` became; and `{ … } as never` opened every test session for a user carrying an
 * `id` the server does not send and missing the `mfaEnabled` it does. Three hundred and fifty-four
 * findings, and a fixture the cast had kept from its type. They were fixed on 2026-10-14 and the
 * rules switched on; ESLint now refuses a new one.
 *
 * <p><b>What this file adds to ESLint, and why ESLint cannot do it itself.</b> Two things:
 *
 * <ul>
 *   <li><b>That the rules are still on for specs.</b> The hole this closes was not a missing rule but
 *       an override that switched rules off, in the same file that declares them, read by nobody. The
 *       script asks ESLint for the configuration it computes for every spec file and refuses one where
 *       any of {@link GUARDED} is not an error — an override added later, a glob that stops matching,
 *       a rule renamed upstream.
 *   <li><b>The exceptions, by name.</b> A disable comment for one of these rules in a spec must say
 *       why (`-- reason`), and the ones that exist are written in {@link ALLOWED} — file and rule —
 *       so a new one is a decision in the commit that makes it, and one removed asks for its line to
 *       go. A plain count would let a swap through: one fixed, another added, the number unchanged.
 *   <li><b>That every model is in `schema-models.ts`.</b> `asSchema` holds a fixture to the model the
 *       client reads its schema as, through that map; a model missing from it would leave its
 *       fixtures to the run-time check, which cannot see a field the server always sends as null.
 * </ul>
 *
 * <p>It refuses a run that examined no spec file: a guard that reads nothing reports green.
 * Run by `npm test` before the unit suite, like the asset, i18n and dead-method checks.
 */
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ESLint } from 'eslint';

const root = dirname(dirname(fileURLToPath(import.meta.url)));

/** The rules that keep `any` and its two cast spellings out of the specs. */
const GUARDED = [
    '@typescript-eslint/no-explicit-any',
    '@typescript-eslint/no-unsafe-member-access',
    '@typescript-eslint/no-unsafe-call',
    '@typescript-eslint/no-unsafe-assignment',
    '@typescript-eslint/no-unsafe-argument',
    '@typescript-eslint/no-unsafe-return',
    'no-restricted-syntax'
];

/**
 * The disable comments a spec may carry for a guarded rule, each with the reason it stays.
 *
 * - `remediation.spec.ts`: `HighImpactFix.recommendedVersion` is claimed `string` in api.models.ts, and
 *   the server sends null when no finding announces a fix. The case under test is that null; the claim
 *   is the defect, and goes with this line once it says `string | null`.
 * - `search-bound.spec.ts`: the `openapi.json` import is typed as its literal — 240 paths whose
 *   operations, parameters and schemas are all weak shapes — and no narrower declared type accepts it.
 */
const ALLOWED = [
    'src/app/pages/remediation/remediation.spec.ts no-restricted-syntax',
    'src/app/shared/search-bound.spec.ts no-restricted-syntax'
];

function* walk(directory) {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
        const path = join(directory, entry.name);
        if (entry.isDirectory()) yield* walk(path);
        else yield path;
    }
}

const specs = [...walk(join(root, 'src'))].filter((file) => file.endsWith('.spec.ts'));
if (specs.length === 0) {
    console.error('Spec type check: no *.spec.ts found under src — the guard read nothing, which is not a pass.');
    process.exit(1);
}

const problems = [];

// 1. The rules, as ESLint resolves them for each file, not as the config file reads to a person.
const eslint = new ESLint({ cwd: root });
const severity = (setting) => (Array.isArray(setting) ? setting[0] : setting);
for (const file of specs) {
    const config = await eslint.calculateConfigForFile(file);
    for (const rule of GUARDED) {
        const level = severity(config?.rules?.[rule]);
        if (level !== 2 && level !== 'error') {
            problems.push(`${relative(root, file)}: ${rule} is ${level ?? 'not configured'} here, not an error`);
        }
    }
}

// 2. The exceptions: each with a reason, and each one listed.
const DISABLE = /eslint-disable(?:-next-line|-line)?\b([^\n*]*)/g;
const found = [];
for (const file of specs) {
    const source = readFileSync(file, 'utf8');
    for (const match of source.matchAll(DISABLE)) {
        const [rules, reason] = match[1].split(/\s--\s/);
        const named = rules
            .split(',')
            .map((rule) => rule.trim())
            .filter(Boolean);
        // A bare `eslint-disable` switches every rule off, the guarded ones included.
        const touched = named.length === 0 ? GUARDED : named.filter((rule) => GUARDED.includes(rule));
        if (touched.length === 0) continue;
        const where = `${relative(root, file)}:${source.slice(0, match.index).split('\n').length}`;
        if (named.length === 0) problems.push(`${where}: a bare eslint-disable switches the type rules off with the rest`);
        if (!reason || reason.trim() === '') problems.push(`${where}: disables ${touched.join(', ')} without saying why (\`-- reason\`)`);
        for (const rule of touched) found.push(`${relative(root, file)} ${rule}`);
    }
}
for (const exception of found.filter((entry) => !ALLOWED.includes(entry))) {
    problems.push(`${exception}: a new exception — type the value, or add it to ALLOWED with its reason in the same commit`);
}
for (const exception of ALLOWED.filter((entry) => !found.includes(entry))) {
    problems.push(`${exception}: listed in ALLOWED and no longer in the code — remove its line, the ratchet only goes down`);
}

// 3. Every model the client builds on a schema is in the map `asSchema` holds fixtures to: a model
// left out would let its fixtures fall back to the run-time check alone, silently.
const models = readFileSync(join(root, 'src/app/core/api.models.ts'), 'utf8');
const map = readFileSync(join(root, 'src/app/core/testing/schema-models.ts'), 'utf8');
const declared = [
    ...models.matchAll(/export type (\w+) =\s*Refine<\s*Schema<'(\w+)'>/g),
    ...models.matchAll(/export type (\w+) = Schema<'(\w+)'>;/g)
];
if (declared.length === 0) problems.push('api.models.ts: no model built on a schema was found — the pattern no longer reads it');
for (const [, model, schema] of declared) {
    if (!map.includes(`    ${schema}: Models.${model};`)) {
        problems.push(`schema-models.ts: \`${schema}: Models.${model};\` is missing — its fixtures are not checked against the model`);
    }
}

if (problems.length > 0) {
    console.error(`${problems.length} problem(s) with the typing of the specs:`);
    for (const problem of problems) console.error(`  ${problem}`);
    process.exit(1);
}
console.log(
    `Spec type check: ${specs.length} spec files, ${GUARDED.length} rules on as errors in each, ` +
        `${found.length} listed exception(s), ${declared.length} models held to their fixtures.`
);
