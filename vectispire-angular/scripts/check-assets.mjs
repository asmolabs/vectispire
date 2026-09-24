#!/usr/bin/env node
/**
 * Checks that no third-party resource is referenced by the application shell.
 *
 * Why this script exists: Vectispire's content security policy (`style-src 'self'`,
 * `font-src 'self' data:`) refuses every stylesheet or font served by a third party.
 * Such a reference breaks nothing visible in development — the browser blocks the
 * request, the page falls back to the system font, and nobody notices. That is
 * exactly what happened to the Reflex version: its typography never reached
 * production, and it took measuring in the browser to find out.
 *
 * The Sakai template this front end comes from loaded Lato from a CDN. This script
 * is what guarantees the fix will not be undone by a future template update.
 *
 * Run by `npm test` before the unit suite: it is a file check, it needs no browser.
 */
import { readFileSync, existsSync, statSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createRequire } from 'node:module';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const failures = [];

/** Every file in a tree, recursively. */
function* walk(directory) {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
        const path = join(directory, entry.name);
        if (entry.isDirectory()) yield* walk(path);
        else yield path;
    }
}

function check(label, relativePath, test) {
    const path = join(root, relativePath);
    if (!existsSync(path)) {
        failures.push(`${label} : ${relativePath} est introuvable`);
        return;
    }
    const problem = test(readFileSync(path, 'utf8'), path);
    if (problem) failures.push(`${label} : ${problem}`);
}

// The index and the global stylesheet are the only two places a third-party resource
// can be pulled from without going through the bundler.
for (const file of ['src/index.html', 'src/assets/styles.scss']) {
    check('aucune ressource tierce', file, (content) => {
        // The comments explain precisely why there is no CDN here; counting them as
        // violations would make the rule untenable.
        const withoutComments = content
            .replace(/<!--[\s\S]*?-->/g, '')
            .replace(/\/\*[\s\S]*?\*\//g, '')
            .replace(/^\s*\/\/.*$/gm, '');
        const external = withoutComments.match(/https?:\/\/[^\s"')]+/g);
        return external ? `external reference(s): ${[...new Set(external)].join(', ')}` : null;
    });
}

// **And the component templates, because that is where the leak happened.** This
// script read only the shell above; two pages inherited from the Sakai template —
// `auth/access.html` and `auth/error.html` — each pulled an illustration from
// `primefaces.org/cdn`, and nothing saw it. The CSP refuses them: the page renders, the
// text is there, the image is missing, and nobody ever opens those two screens.
//
// Only resource positions are examined — `src`, `srcset`, `url()`, and `href` on a
// `<link>`. An `xmlns="http://www.w3.org/2000/svg"` is not a request, a URL in a
// `placeholder` is an example shown to the user, and an `<a href>` to a security
// advisory is a navigation the CSP does not govern: refusing them all would make this
// the rule people switch off.
const templates = [...walk(join(root, 'src', 'app'))].filter((path) => path.endsWith('.html'));
if (templates.length === 0) failures.push('no third-party resource: no template found, the rule would check nothing');
for (const path of templates) {
    const content = readFileSync(path, 'utf8').replace(/<!--[\s\S]*?-->/g, '');
    const external = [
        ...content.matchAll(/\b(?:src|srcset)\s*=\s*["'](https?:\/\/[^"']+)/g),
        ...content.matchAll(/url\(\s*['"]?(https?:\/\/[^)'"]+)/g),
        ...content.matchAll(/<link\b[^>]*\bhref\s*=\s*["'](https?:\/\/[^"']+)/g),
    ].map((match) => match[1]);
    if (external.length) {
        failures.push(`no third-party resource: ${path.slice(root.length + 1)} references ${[...new Set(external)].join(', ')}`);
    }
}

// The declared fonts must exist and be real woff2: an `@font-face` pointing at an
// absent file fails silently, like a blocked CDN.
check('declared fonts present', 'src/assets/styles.scss', (content) => {
    const declared = [...content.matchAll(/url\('([^']+\.woff2)'\)/g)].map((m) => m[1]);
    if (declared.length === 0) return 'no font declared';
    const missing = [];
    for (const url of declared) {
        const path = join(root, 'public', url.replace(/^\//, ''));
        if (!existsSync(path) || statSync(path).size === 0) {
            missing.push(url);
            continue;
        }
        // "wOF2": a woff2 file's signature. A truncated file, or an HTML error page
        // saved by mistake, would both pass a plain existence test.
        const magic = readFileSync(path).subarray(0, 4).toString('latin1');
        if (magic !== 'wOF2') missing.push(`${url} (signature « ${magic} », attendu « wOF2 »)`);
    }
    return missing.length ? `police(s) absentes ou invalides : ${missing.join(', ')}` : null;
});

// **Every `pi-*` class must exist in the installed primeicons.** An unknown one is not an
// error anywhere — the `<i>` renders as an empty box of the right size and the button next
// to it still works. Four of them (`pi-balance-scale`, `pi-file-code`, `pi-gitlab`,
// `pi-terminal`) exist in no primeicons release and were shipped blank on seven screens until
// somebody read the icon list. The known set is read from the stylesheet itself, which also
// covers the modifiers (`pi-fw`, `pi-spin`), so a primeicons upgrade that drops an icon
// fails here too.
const iconSheet = createRequire(import.meta.url).resolve('primeicons/primeicons.css');
const knownIcons = new Set([...readFileSync(iconSheet, 'utf8').matchAll(/\.(pi-[a-z0-9-]+)/g)].map((m) => m[1]));
const sources = [...walk(join(root, 'src', 'app'))].filter((path) => /\.(html|ts)$/.test(path) && !path.endsWith('.spec.ts'));
for (const path of sources) {
    const unknown = [...readFileSync(path, 'utf8').matchAll(/\bpi-[a-z0-9]+(?:-[a-z0-9]+)*\b/g)].map((m) => m[0]).filter((icon) => !knownIcons.has(icon));
    if (unknown.length) failures.push(`primeicons: ${path.slice(root.length + 1)} uses ${[...new Set(unknown)].join(', ')}, absent from ${iconSheet.slice(iconSheet.indexOf('node_modules'))}`);
}

// La licence de la police doit voyager avec elle (SIL OFL 1.1, article 2).
check('font licence present', 'public/fonts/LICENSE.txt', (content) => (content.includes('SIL OPEN FONT LICENSE') ? null : "le fichier ne contient pas le texte de la licence OFL"));

if (failures.length) {
    console.error('Asset check: failed\n');
    for (const failure of failures) console.error(`  - ${failure}`);
    process.exit(1);
}

console.log('Asset check: no third-party reference, fonts present and valid, every primeicons class exists.');
