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
 * Ce que ce script vérifie, depuis le 30 août : que le *nombre* de clés référencées est celui
 * attendu — un plancher à 40 avait laissé passer une chute de 54 à 52 sans un mot, c'est-à-dire
 * le retour exact du défaut ci-dessus — et que le nombre de libellés écrits en dur ne monte pas.
 * Le second est un cliquet, pas une interdiction : l'interface n'est traduite qu'en partie, et
 * une règle qui échoue à sa première exécution est une règle qu'on désactive.
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

// **Le compte est épinglé, pas planché, et il l'est parce que le plancher n'a rien vu.**
// Ce fichier a d'abord porté `if (referenced.size < 40)`. Un audit a remis les deux libellés
// en dur que ce script avait été écrit pour empêcher : le compte est tombé de 54 à 52, 40 est
// resté franchi, la suite est passée verte et le défaut était de retour sans un mot. Un
// plancher qu'on ne peut pas atteindre ne se déclenche jamais ; c'est un garde-fou qui a
// l'air d'en être un.
//
// Un nombre exact se met à jour dans le même commit que la clé qu'on ajoute ou qu'on retire,
// donc il pose la question au moment où quelqu'un peut y répondre. Le changer est un geste
// d'une ligne — mais c'est un geste *délibéré*, et c'est toute la différence.
const EXPECTED_KEYS = 54;
if (referenced.size !== EXPECTED_KEYS) {
    const direction = referenced.size < EXPECTED_KEYS ? 'disparu' : 'apparu';
    console.error(
        `${referenced.size} clés référencées dans src/app, ${EXPECTED_KEYS} attendues : ` +
        `${Math.abs(referenced.size - EXPECTED_KEYS)} ont ${direction}.`);
    console.error(
        `Si c'est voulu, mettez EXPECTED_KEYS à jour dans le même commit. Si ça ne l'est pas, ` +
        `un libellé vient de repasser en dur — c'est exactement ce qui est arrivé le 30 août, ` +
        `et le plancher de 40 que portait ce fichier ne l'a pas vu.`);
    process.exit(1);
}

// **Le cliquet sur les libellés en dur.** Refuser tout littéral serait la bonne règle et la
// mauvaise décision aujourd'hui : `src/app` en porte 89, répartis sur 14 fichiers, parce que
// l'interface n'est traduite qu'en partie. Une règle qui échoue dès sa première exécution est
// une règle qu'on désactive.
//
// Un plafond qui ne peut que descendre bloque le *prochain* libellé en dur sans exiger que les
// 89 soient traduits aujourd'hui. Le retirer d'un cran quand on en traduit un est gratuit ; en
// ajouter un exige de lever le plafond, ce qui se lit dans le diff et se défend en revue.
// C'est la forme que `MAY_GROW` a dans `ReadCostSweepTest`, pour la même raison : une liste
// qui s'allonge à chaque rougeur finit par exempter le défaut suivant.
const HARDCODED_LABEL_CEILING = 89;
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
if (hardcoded > HARDCODED_LABEL_CEILING) {
    console.error(
        `${hardcoded} libellés en dur dans src/app, plafond ${HARDCODED_LABEL_CEILING} : ` +
        `${hardcoded - HARDCODED_LABEL_CEILING} de trop.`);
    console.error(
        `Un libellé écrit en clair est un libellé qu'un opérateur francophone lira en anglais. ` +
        `Routez-le par i18n.t et ajoutez la clé aux deux bundles. Le plafond ne monte que si ` +
        `vous décidez qu'il doit monter, et ce diff-là se défend en revue.`);
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
        console.error(`Clés absentes de public/i18n/${lang}.json :`);
        for (const key of missing) console.error(`  - ${key}`);
    }
}

if (failed) {
    console.error("Ajoutez-les dans les deux bundles : une clé non résolue s'affiche telle quelle.");
    process.exit(1);
}

console.log(
    `Vérification i18n : ${referenced.size} clés référencées, toutes présentes en français et ` +
    `en anglais ; ${hardcoded} libellés en dur (plafond ${HARDCODED_LABEL_CEILING}).`);
