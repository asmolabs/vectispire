#!/usr/bin/env node
/**
 * Runs the unit suite (`ng test`), then refuses a spec file that ran fewer tests than it declares.
 *
 * <p><b>Why this guard exists.</b> On a branch, `npm test` once reported 113 files green and 1287
 * tests where 1339 were expected: the 52 missing were exactly `measurements.spec.ts`. Three reruns
 * gave 1339 and the cause was never found. Vitest saw nothing wrong: it fails a file that registers
 * no test, but a file left out of the run, or whose tests are all skipped, is not a failure to it —
 * so the run was green on 96% of the suite. A green suite is only worth what it ran; whatever made
 * a file go quiet, the run must say so.
 *
 * <p><b>Why a floor counted from the source, not a committed baseline.</b> A per-file count kept in
 * the repository, like the i18n ratchets, would have to move in every commit that adds a test, and
 * two branches adding one each would collide on it — the i18n count already did. The floor is
 * instead read from each spec's syntax tree: one per `it(…)`/`test(…)` call, `.only`, `.concurrent`,
 * `.sequential` and `.fails` included, one per `it.each(…)(…)`/`it.for(…)(…)` since a table holds at
 * least one row. A test generated in a loop counts once and runs many times, so the floor is a lower
 * bound, never above what a healthy run executes; it was checked against the suite and equalled
 * the run on 105 files, fell below it on 8, exceeded it on none. What it cannot see is the loss of
 * some generated tests while one still runs — the incident above lost a whole file, which it does.
 *
 * <p>Not counted: `it.skip`, `it.todo`, `xit`, `it.skipIf`/`it.runIf` — a test written as not
 * running, visibly, where it stands. Counted: a test under `describe.skip`. A skipped group hides
 * every test in it behind one word at its top, which is the silence this file exists to refuse;
 * skip the tests themselves if they must be. For the same reason a file may report no more
 * skipped tests than it writes as skipped: half of `measurements.spec.ts` under `describe.skip`
 * still cleared its floor, its loops generating more tests than it writes, and was caught only by
 * that. A stray `.only` is caught the same way, through the tests it silences. And every spec file
 * must run at least one test.
 *
 * <p><b>Why this script runs `ng test` itself.</b> It reads Vitest's JSON report, written beside the
 * console output by the same run — not a second run, which would double the suite's time and could
 * disagree with the first. Starting the run here is how it knows the report is this run's: it
 * deletes the old one first, and a report that is then missing is a failure, not a stale success.
 * The run is one-shot (`--no-watch`), since a floor needs a finished run. Vitest's own
 * `passWithNoTests` is left at its default, false: a run that found no file at all fails there.
 *
 * <p>Arguments are passed on to `ng test`. They may narrow the run (`--include`, `--filter`), and a
 * narrowed run cannot be held to the whole suite's floor, so with any argument the floor is not
 * checked — and the script says so rather than passing quietly. `npm test` in CI passes none.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const require = createRequire(join(root, 'package.json'));
const ts = require('typescript');
const report = join(root, '.angular', 'vitest-report.json');
const forwarded = process.argv.slice(2);

rmSync(report, { force: true });
mkdirSync(dirname(report), { recursive: true });

const run = spawnSync(
    process.execPath,
    [
        require.resolve('@angular/cli/bin/ng.js'),
        'test',
        '--no-watch',
        '--reporters=default',
        '--reporters=json',
        `--output-file=${report}`,
        ...forwarded
    ],
    { cwd: root, stdio: 'inherit' }
);
if (run.status !== 0) process.exit(run.status ?? 1);

if (forwarded.length > 0) {
    console.log(`Test floor not checked: the run was given arguments (${forwarded.join(' ')}) and may be partial.`);
    process.exit(0);
}

function* specs(directory) {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
        const path = join(directory, entry.name);
        if (entry.isDirectory()) yield* specs(path);
        else if (entry.name.endsWith('.spec.ts')) yield path;
    }
}

const TEST = new Set(['it', 'test']);
const RUNNING = new Set(['only', 'concurrent', 'sequential', 'fails']);
const NOT_RUNNING = new Set(['skip', 'todo']);
const TABLES = new Set(['each', 'for']);
const CONDITIONS = new Set(['skipIf', 'runIf']);

const isTest = (node) => ts.isIdentifier(node) && TEST.has(node.text);
/** `it.<name>`, with `<name>` in `names`. */
const isTestModifier = (node, names) =>
    ts.isPropertyAccessExpression(node) && isTest(node.expression) && names.has(node.name.text);

/**
 * What a spec declares, read from its syntax tree rather than its text: the tests that run, and
 * those written as not running — whose skipped entries in the report are expected.
 */
function declared(file) {
    const source = ts.createSourceFile(file, readFileSync(file, 'utf8'), ts.ScriptTarget.Latest, true);
    const count = { running: 0, skipped: 0 };
    const visit = (node) => {
        if (ts.isCallExpression(node)) {
            const callee = node.expression;
            if (isTest(callee) || isTestModifier(callee, RUNNING)) count.running += 1;
            else if (isTestModifier(callee, NOT_RUNNING)) count.skipped += 1;
            else if (ts.isIdentifier(callee) && callee.text === 'xit') count.skipped += 1;
            else if (ts.isCallExpression(callee) && isTestModifier(callee.expression, TABLES)) count.running += 1;
            // A conditional test may run or not; it counts as neither, and its skipped rows are allowed.
            else if (ts.isCallExpression(callee) && isTestModifier(callee.expression, CONDITIONS))
                count.skipped += Infinity;
        }
        ts.forEachChild(node, visit);
    };
    visit(source);
    return count;
}

if (!existsSync(report)) {
    console.error(`✗ ng test passed but wrote no report at ${relative(root, report)}: the floor cannot be checked.`);
    process.exit(1);
}
const results = JSON.parse(readFileSync(report, 'utf8')).testResults ?? [];
// Passed or failed ran; anything else — skipped, pending, todo — was reported and not run.
const outcomes = new Map(
    results.map((file) => {
        const ran = file.assertionResults.filter((test) => test.status === 'passed' || test.status === 'failed');
        return [file.name, { ran: ran.length, skipped: file.assertionResults.length - ran.length }];
    })
);

const failures = [];
let files = 0;
let floor = 0;
let total = 0;
for (const file of specs(join(root, 'src'))) {
    const name = relative(root, file).split(sep).join('/');
    const source = declared(file);
    const expected = Math.max(1, source.running);
    files += 1;
    floor += expected;
    const outcome = outcomes.get(file);
    if (outcome === undefined) {
        failures.push(`${name}: on disk, absent from the run (declares ${expected})`);
        continue;
    }
    total += outcome.ran;
    if (outcome.ran < expected) failures.push(`${name}: ran ${outcome.ran}, declares at least ${expected}`);
    // The floor alone misses a group skipped in a file whose loops generate more tests than it
    // writes: the rest still clears the floor. A skip the file does not write test by test catches it.
    else if (outcome.skipped > source.skipped)
        failures.push(`${name}: ${outcome.skipped} test(s) not run, ${source.skipped} written as skipped`);
}

if (failures.length > 0) {
    console.error(`✗ ${failures.length} spec file(s) ran fewer tests than they declare — the suite is not all there:`);
    for (const failure of failures) console.error(`  ${failure}`);
    process.exit(1);
}
console.log(`✓ Test floor: ${files} spec files ran ${total} tests, none below what it declares (floor ${floor}).`);
