#!/usr/bin/env node
/**
 * Refuses an `api.service` method no screen calls any more.
 *
 * **Why this guard exists.** Four complete server-side features lived for weeks with no screen at
 * all: the remediation plan ranked by leverage, switching on the second factor, per-account target
 * assignment, and signing out itself. In each case the client method existed, nobody called it,
 * and nothing could see it — a dead method does not break compilation, does not turn a suite red,
 * and reports itself to nobody. Finding them took looking.
 *
 * It is the same defect as the hard-coded labels and the schema collisions: a product that can
 * answer a question and tells nobody. And as with those, the answer is a ratchet rather than a
 * prohibition — the debt exists, it is being paid down, and a rule that fails on its first run is
 * a rule people switch off.
 *
 * **The list is pinned, not counted.** A plain number would let a swap through: one method wired
 * up, another left dead, the count does not move and the debt relocates. The names are therefore
 * written here, and any divergence — one name more, one name fewer — asks for a decision in the
 * commit that makes it.
 *
 * **What this script does not see, and saying so beats letting people assume.** Only literal
 * `.name(` calls are recognised. A method reached through a name built at runtime would look dead;
 * there is none today, and the day there is one, the exemption is a line here rather than a
 * disabled guard.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const SERVICE = 'src/app/core/api.service.ts';

/**
 * The methods no screen calls, and that are tolerated all the same.
 *
 * **Empty, and that is the state we wanted.** Fifteen on the morning of 15 September 2026; zero by
 * the evening. Nine found their screen — signing out, the second factor, an account's visibility,
 * attaching a ticket, the latest-pair diff, the licence policy, explaining a CVE, model
 * availability, the overdue reviews — and six were removed in favour of the path that suited, or
 * because a screen for them would have added nothing.
 *
 * The ratchet therefore becomes a prohibition, like the hard-coded labels' before it: a client
 * method nothing calls fails the suite, and adding one here is a deliberate move that justifies
 * itself in the commit that makes it.
 */
const DEAD = new Set([]);

const walk = (dir) =>
    readdirSync(dir).flatMap((entry) => {
        const path = join(dir, entry);
        return statSync(path).isDirectory() ? walk(path) : [path];
    });

// A public method of the service: four spaces of indentation, a name, a parenthesis.
const DECLARED = /^ {4}([a-zA-Z0-9_]+)\(/gm;

const service = readFileSync(join(root, SERVICE), 'utf8');
const declared = [...service.matchAll(DECLARED)].map(([, name]) => name).filter((name) => name !== 'constructor');

// The specs are excluded: a call that exists only in a test is not a screen, and a method kept
// alive by its own test is exactly what this guard is looking for.
let callers = '';
for (const file of walk(join(root, 'src/app'))) {
    if (!/\.(ts|html)$/.test(file) || file.endsWith('.spec.ts') || file.endsWith('api.service.ts')) continue;
    callers += readFileSync(file, 'utf8') + '\n';
}

const unused = declared.filter((name) => !new RegExp(`\\.${name}\\s*\\(`).test(callers));

const appeared = unused.filter((name) => !DEAD.has(name));
const connected = [...DEAD].filter((name) => !unused.includes(name));

if (appeared.length > 0) {
    console.error(
        `${appeared.length} api.service method(s) no screen calls any more: ${appeared.join(', ')}.`);
    console.error(
        `A shipped calculation nobody can reach. Give it a screen, or remove it — and if it is ` +
        `deliberate, add its name to DEAD in the same commit.`);
    process.exit(1);
}

if (connected.length > 0) {
    console.error(
        `${connected.length} method(s) are no longer dead: ${connected.join(', ')}.`);
    console.error(
        `Good news, and the ratchet must come down in the same commit: remove them from DEAD.`);
    process.exit(1);
}

console.log(
    `API method check: ${declared.length} declared, ${unused.length} with no screen ` +
    `(ratchet at ${DEAD.size}).`);
