#!/usr/bin/env node
/**
 * Refuse une méthode d'`api.service` que plus aucun écran n'appelle.
 *
 * **Pourquoi ce garde existe.** Quatre fonctionnalités complètes côté serveur ont vécu des
 * semaines sans le moindre écran : le plan de remédiation classé par levier, l'activation du
 * second facteur, l'affectation des cibles par compte, et la déconnexion elle-même. Dans chaque
 * cas la méthode cliente existait, personne ne l'appelait, et rien ne pouvait le voir — une
 * méthode morte ne casse pas la compilation, ne fait pas rougir une suite, et ne se signale à
 * personne. Il a fallu chercher pour les trouver.
 *
 * C'est le même défaut que les libellés en dur et les collisions de schémas : un produit qui
 * sait répondre à une question et ne le dit à personne. Et comme pour eux, la réponse est un
 * cliquet plutôt qu'une interdiction — la dette existe, elle se résorbe, et une règle qui échoue
 * dès sa première exécution est une règle qu'on désactive.
 *
 * **La liste est épinglée, pas comptée.** Un simple nombre laisserait passer l'échange : une
 * méthode branchée, une autre laissée morte, le compte ne bouge pas et la dette se déplace. Les
 * noms sont donc écrits ici, et tout écart — un nom en plus, un nom en moins — demande une
 * décision dans le commit qui la prend.
 *
 * **Ce que ce script ne voit pas, et le dire vaut mieux que de laisser croire.** Seuls les
 * appels littéraux `.nom(` sont reconnus. Une méthode atteinte par un nom construit à
 * l'exécution passerait pour morte ; il n'y en a aucune aujourd'hui, et le jour où il y en aura
 * une, l'exemption est une ligne ici plutôt qu'un garde désactivé.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const SERVICE = 'src/app/core/api.service.ts';

/**
 * Les méthodes qu'aucun écran n'appelle aujourd'hui, et ce qu'on attend d'elles.
 *
 * Onze au 15 septembre 2026, après en avoir branché quatre le jour même. Neuf depuis que les deux
 * qui visaient `t_issue_ticket` ont été retirées : cette table a son propre point d'entrée et
 * personne ne la lit — ni le webhook, ni la balayeuse, ni un écran. Le rattachement d'un ticket
 * se fait sur `ticketRef`, qui est le champ que tout le produit regarde.
 *
 * Chacune des neuf restantes est un calcul livré que personne ne peut atteindre : soit on lui
 * donne un écran, soit on la retire — et les deux se font dans un commit qui le dit.
 */
const DEAD = new Set([
    'complianceFramework',
    'getScanAttestation',
    'getScanCsaf',
    'getScanCycloneDx',
    'updateLicensePolicy',
    'getGlobalScorecard',
    'getAiAdvisorStatus',
    'explainCveWithAi',
    'getLatestSbomDiff'
]);

const walk = (dir) =>
    readdirSync(dir).flatMap((entry) => {
        const path = join(dir, entry);
        return statSync(path).isDirectory() ? walk(path) : [path];
    });

// Une méthode publique du service : quatre espaces d'indentation, un nom, une parenthèse.
const DECLARED = /^ {4}([a-zA-Z0-9_]+)\(/gm;

const service = readFileSync(join(root, SERVICE), 'utf8');
const declared = [...service.matchAll(DECLARED)].map(([, name]) => name).filter((name) => name !== 'constructor');

// Les specs sont exclues : un appel qui n'existe que dans un essai n'est pas un écran, et une
// méthode maintenue en vie par son propre test est exactement ce que ce garde cherche.
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
        `${appeared.length} méthode(s) d'api.service que plus aucun écran n'appelle : ${appeared.join(', ')}.`);
    console.error(
        `Un calcul livré que personne ne peut atteindre. Donnez-lui un écran, ou retirez-le — et si ` +
        `c'est délibéré, ajoutez son nom à DEAD dans le même commit.`);
    process.exit(1);
}

if (connected.length > 0) {
    console.error(
        `${connected.length} méthode(s) ne sont plus mortes : ${connected.join(', ')}.`);
    console.error(
        `Bonne nouvelle, et le cliquet doit descendre dans le même commit : retirez-les de DEAD.`);
    process.exit(1);
}

console.log(
    `Vérification des méthodes d'API : ${declared.length} déclarées, ${unused.length} sans écran ` +
    `(cliquet à ${DEAD.size}).`);
