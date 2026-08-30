#!/usr/bin/env node
/**
 * Vérifie que chaque clé de traduction demandée par un écran existe dans les deux bundles.
 *
 * Pourquoi ce script existe : le sélecteur de fournisseur d'IA proposait deux libellés
 * anglais en dur — `'Ollama — a model on a host you run'`, `'OpenAI-compatible API'` — sur
 * un écran où tous les autres libellés passaient par `i18n.t`. Trois audits successifs l'ont
 * signalé sans que rien ne puisse le voir. Les avoir routés par les bundles règle cet
 * écran-là ; ceci empêche la *prochaine* clé d'être référencée sans jamais être ajoutée, ce
 * qui affiche la clé elle-même à l'opérateur et ressemble à une faute de frappe plutôt qu'à
 * une traduction manquante.
 *
 * Ce que ce script ne vérifie délibérément pas : que le bundle français reflète l'anglais. Il
 * ne le fait pas, et c'est voulu — `settings.ts` retombe sur le libellé anglais du serveur
 * quand une clé se résout à elle-même, donc 52 clés existent en français sans contrepartie
 * anglaise. Exiger la parité échouerait sur un arbre correct, et c'est ainsi que commence une
 * liste d'exemptions.
 *
 * Seuls les appels littéraux sont vérifiables : une clé construite depuis une variable n'est
 * pas une clé que ce script peut lire.
 *
 * Exécuté par `npm test` avant la suite unitaire, comme `check-assets.mjs` : c'est une
 * vérification de fichiers, elle n'a pas besoin d'un navigateur.
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

const referenced = new Set();
for (const file of walk(join(root, 'src/app'))) {
    if (!/\.(ts|html)$/.test(file) || file.endsWith('.spec.ts')) continue;
    for (const [, key] of readFileSync(file, 'utf8').matchAll(/\bt\(\s*['"]([a-z0-9_.]+)['"]/g)) {
        referenced.add(key);
    }
}

// Garde-fou contre une règle qui ne vérifie rien : si le parcours cesse de trouver des
// sources, c'est le défaut, pas une exécution propre.
if (referenced.size < 40) {
    console.error(
        `Seules ${referenced.size} clés ont été trouvées dans src/app : le parcours ou l'expression ` +
        `est faux, et une règle qui n'inspecte rien passe indéfiniment.`);
    process.exit(1);
}

let failed = false;
for (const lang of ['en', 'fr']) {
    const known = bundle(lang);
    const missing = [...referenced].filter((key) => !known.has(key)).sort();
    if (missing.length > 0) {
        failed = true;
        console.error(`Clés absentes de public/i18n/${lang}.json :`);
        for (const key of missing) console.error(`  - ${key}`);
    }
}

if (failed) {
    console.error("Ajoutez-les dans les deux bundles : une clé non résolue s'affiche telle quelle.");
    process.exit(1);
}

console.log(`Vérification i18n : ${referenced.size} clés référencées, toutes présentes en français et en anglais.`);
