#!/usr/bin/env node
/**
 * Vérifie qu'aucune ressource tierce n'est référencée par la coquille de l'application.
 *
 * Pourquoi ce script existe : la politique de sécurité de contenu de Vectispire
 * (`style-src 'self'`, `font-src 'self' data:`) refuse toute feuille de style ou
 * police servie par un tiers. Une telle référence ne casse rien de visible en
 * développement — le navigateur bloque la requête, la page retombe sur la police
 * système, et personne ne s'en aperçoit. C'est exactement ce qui est arrivé à la
 * version Reflex : sa typographie n'a jamais atteint la production, et il a fallu
 * la mesurer dans le navigateur pour s'en rendre compte.
 *
 * Le template Sakai dont ce frontend est issu chargeait Lato depuis un CDN. Ce
 * script est ce qui garantit que la correction ne sera pas défaite par une future
 * mise à jour du template.
 *
 * Exécuté par `npm test` avant la suite unitaire : c'est une vérification de
 * fichiers, elle n'a pas besoin d'un navigateur.
 */
import { readFileSync, existsSync, statSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const failures = [];

/** Tous les fichiers d'une arborescence, récursivement. */
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

// L'index et la feuille globale sont les deux seuls endroits d'où une ressource
// tierce peut être tirée sans passer par le bundler.
for (const file of ['src/index.html', 'src/assets/styles.scss']) {
    check('aucune ressource tierce', file, (content) => {
        // Les commentaires expliquent précisément pourquoi il n'y a pas de CDN ici ;
        // les compter comme des infractions rendrait la règle intenable.
        const withoutComments = content
            .replace(/<!--[\s\S]*?-->/g, '')
            .replace(/\/\*[\s\S]*?\*\//g, '')
            .replace(/^\s*\/\/.*$/gm, '');
        const external = withoutComments.match(/https?:\/\/[^\s"')]+/g);
        return external ? `référence(s) externe(s) : ${[...new Set(external)].join(', ')}` : null;
    });
}

// **Et les gabarits de composants, parce que c'est là que la fuite s'est produite.**
// Ce script ne lisait que la coquille ci-dessus ; deux pages héritées du template
// Sakai — `auth/access.html` et `auth/error.html` — tiraient chacune une illustration
// de `primefaces.org/cdn`, et rien ne le voyait. La CSP les refuse : la page s'affiche,
// le texte est là, l'image manque, et personne n'ouvre jamais ces deux écrans-là.
//
// Seules les positions de ressource sont examinées — `src`, `srcset`, `url()`, et
// `href` sur un `<link>`. Un `xmlns="http://www.w3.org/2000/svg"` n'est pas une
// requête, une URL dans un `placeholder` est un exemple montré à l'utilisateur, et un
// `<a href>` vers un avis de sécurité est une navigation que la CSP ne gouverne pas :
// les refuser tous ferait de cette règle celle qu'on désactive.
const templates = [...walk(join(root, 'src', 'app'))].filter((path) => path.endsWith('.html'));
if (templates.length === 0) failures.push('aucune ressource tierce : aucun gabarit trouvé, la règle ne vérifierait rien');
for (const path of templates) {
    const content = readFileSync(path, 'utf8').replace(/<!--[\s\S]*?-->/g, '');
    const external = [
        ...content.matchAll(/\b(?:src|srcset)\s*=\s*["'](https?:\/\/[^"']+)/g),
        ...content.matchAll(/url\(\s*['"]?(https?:\/\/[^)'"]+)/g),
        ...content.matchAll(/<link\b[^>]*\bhref\s*=\s*["'](https?:\/\/[^"']+)/g),
    ].map((match) => match[1]);
    if (external.length) {
        failures.push(`aucune ressource tierce : ${path.slice(root.length + 1)} référence ${[...new Set(external)].join(', ')}`);
    }
}

// Les polices déclarées doivent exister et être de vrais woff2 : un `@font-face`
// pointant vers un fichier absent échoue silencieusement, comme un CDN bloqué.
check('polices déclarées présentes', 'src/assets/styles.scss', (content) => {
    const declared = [...content.matchAll(/url\('([^']+\.woff2)'\)/g)].map((m) => m[1]);
    if (declared.length === 0) return 'aucune police déclarée';
    const missing = [];
    for (const url of declared) {
        const path = join(root, 'public', url.replace(/^\//, ''));
        if (!existsSync(path) || statSync(path).size === 0) {
            missing.push(url);
            continue;
        }
        // « wOF2 » : la signature d'un fichier woff2. Un fichier tronqué ou une page
        // d'erreur HTML enregistrée par erreur passeraient un simple test d'existence.
        const magic = readFileSync(path).subarray(0, 4).toString('latin1');
        if (magic !== 'wOF2') missing.push(`${url} (signature « ${magic} », attendu « wOF2 »)`);
    }
    return missing.length ? `police(s) absentes ou invalides : ${missing.join(', ')}` : null;
});

// La licence de la police doit voyager avec elle (SIL OFL 1.1, article 2).
check('licence de la police présente', 'public/fonts/LICENSE.txt', (content) => (content.includes('SIL OPEN FONT LICENSE') ? null : "le fichier ne contient pas le texte de la licence OFL"));

if (failures.length) {
    console.error('Vérification des ressources : échec\n');
    for (const failure of failures) console.error(`  - ${failure}`);
    process.exit(1);
}

console.log('Vérification des ressources : aucune référence tierce, polices présentes et valides.');
